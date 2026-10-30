"""Сервіс серверних об'єктів даних і політика Белла-ЛаПадула.

Об'єктами можуть бути рядки (``kind=text``) або імпортовані текстові файли
(``kind=file``).  Сам вміст зберігається в SQLite, тому клієнт не має
прямого доступу до файлової системи сервера.

Кожен запит до об'єкта проходить дві перевірки:

1. **Дискреційна (ACL).** Власник має всі права; іншим користувачам права
   призначає власник (``grant``/``revoke``).
2. **Мандатна (BLP без категорій).** read — no read up, append — no write
   down, write — рівні мають збігатися, delete — мандатно не обмежується.

Відмова на будь-якому рівні заноситься до журналу ``audit``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from common.protocol import get_str, validate_user_id
from common.security import (
    ALL_RIGHTS,
    FILE_KIND_TEXT,
    OBJECT_KINDS,
    RIGHT_READ,
    ROLE_ADMIN,
    authorize,
    effective_rights,
    level_name,
    mandatory_check,
    mandatory_create_check,
    parse_level,
    parse_rights,
    rights_text,
    sorted_rights,
    validate_object_name,
)
from server.db import Database, ObjectExistsError

# Обмеження вмісту: повідомлення протоколу до 64 КіБ, а JSON екранує
# лапки та зворотні слеші, тому лишаємо запас.
MAX_CONTENT_BYTES = 16 * 1024
MAX_AUDIT_ENTRIES = 500


@dataclass(frozen=True)
class Session:
    """Автентифікований сеанс у межах одного TCP-з'єднання."""

    user_id: str
    clearance: int
    role: str
    session_id: str


def _ok(action: str, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"type": "object_result", "ok": True, "action": action}
    payload.update(extra)
    return payload


def _fail(action: str, reason: str, *, code: str = "denied", **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": "object_result",
        "ok": False,
        "action": action,
        "code": code,
        "reason": reason,
    }
    payload.update(extra)
    return payload


def _content(value: Any, *, field: str = "content") -> str:
    if not isinstance(value, str):
        raise ValueError(f"поле {field!r} має бути рядком")
    if "\x00" in value:
        raise ValueError("вміст не може містити символ NUL")
    size = len(value.encode("utf-8"))
    if size > MAX_CONTENT_BYTES:
        raise ValueError(
            f"вміст завеликий: {size} байтів (максимум {MAX_CONTENT_BYTES})"
        )
    return value


class ObjectService:
    """Виконує операції над об'єктами від імені автентифікованого сеансу."""

    def __init__(self, db: Database) -> None:
        self.db = db
        # Серіалізує зміни об'єктів у межах одного процесу сервера.
        self._lock = threading.RLock()

    # --- допоміжні методи ---------------------------------------------------

    @staticmethod
    def _row_rights(session: Session, row: Any) -> Set[str]:
        acl_raw = ""
        try:
            keys = row.keys()
        except AttributeError:
            keys = []
        if "acl_rights" in keys and row["acl_rights"]:
            acl_raw = row["acl_rights"]
        return effective_rights(
            session.user_id,
            row["owner_id"],
            parse_rights(acl_raw, allow_empty=True),
        )

    def _rights(self, session: Session, row: Any) -> Set[str]:
        if "acl_rights" in row.keys():
            return self._row_rights(session, row)
        acl = self.db.get_acl_rights(int(row["object_id"]), session.user_id)
        return effective_rights(session.user_id, row["owner_id"], acl)

    def _audit(
        self,
        session: Session,
        action: str,
        object_name: Optional[str],
        allowed: bool,
        reason: str = "",
    ) -> None:
        self.db.log_audit(
            session.user_id, action, object_name, allowed, reason
        )

    def _metadata(
        self,
        session: Session,
        row: Any,
        rights: Set[str],
        *,
        include_acl: bool = False,
    ) -> Dict[str, Any]:
        level = int(row["level"])
        readable, read_reason = mandatory_check(RIGHT_READ, session.clearance, level)
        data: Dict[str, Any] = {
            "name": row["name"],
            "owner": row["owner_id"],
            "level": level_name(level),
            "level_rank": level,
            "kind": row["kind"],
            "size": int(row["size"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "rights": sorted_rights(rights),
            "rights_text": rights_text(rights),
            "readable": bool(RIGHT_READ in rights and readable),
            "read_blocked_by": "" if readable else read_reason,
        }
        if include_acl:
            data["acl"] = [
                {
                    "user": entry["user_id"],
                    "rights": sorted_rights(
                        parse_rights(entry["rights"], allow_empty=True)
                    ),
                    "granted_by": entry["granted_by"],
                    "granted_at": entry["granted_at"],
                }
                for entry in self.db.get_acl(int(row["object_id"]))
            ]
        return data

    def _load(self, name: str) -> Optional[Any]:
        return self.db.get_object(name)

    # --- дії ----------------------------------------------------------------

    def dispatch(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action")
        if not isinstance(action, str) or not action:
            return _fail("?", "не вказано дію", code="bad-request")
        action = action.strip().lower()
        handler = getattr(self, f"_handle_{action}", None)
        if handler is None:
            return _fail(action, f"невідома дія {action!r}", code="bad-action")
        try:
            return handler(session, message)
        except (ValueError, TypeError) as exc:
            self._audit(session, action, message.get("name"), False, str(exc))
            return _fail(action, str(exc), code="bad-request")

    def _handle_whoami(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        return _ok(
            "whoami",
            user=session.user_id,
            clearance=level_name(session.clearance),
            clearance_rank=session.clearance,
            role=session.role,
            rights=list(ALL_RIGHTS),
        )

    def _handle_list(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        rows = self.db.list_objects_for_user(session.user_id)
        items: List[Dict[str, Any]] = []
        for row in rows:
            rights = self._row_rights(session, row)
            items.append(self._metadata(session, row, rights))
        return _ok("list", count=len(items), objects=items)

    def _handle_info(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        row = self._load(name)
        if row is None:
            self._audit(session, "info", name, False, "object-not-found")
            return _fail("info", f"об'єкт {name!r} не знайдено", code="not-found")
        rights = self._rights(session, row)
        if not rights:
            self._audit(session, "info", name, False, "no-rights")
            return _fail(
                "info", "дискреційна відмова: немає жодного права на об'єкт"
            )
        include_acl = session.user_id == row["owner_id"] or session.role == ROLE_ADMIN
        return _ok(
            "info",
            object=self._metadata(session, row, rights, include_acl=include_acl),
        )

    def _handle_read(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        row = self._load(name)
        if row is None:
            self._audit(session, "read", name, False, "object-not-found")
            return _fail("read", f"об'єкт {name!r} не знайдено", code="not-found")

        rights = self._rights(session, row)
        allowed, reason = authorize(
            RIGHT_READ,
            user_id=session.user_id,
            owner_id=row["owner_id"],
            subject_level=session.clearance,
            object_level=int(row["level"]),
            acl_rights=rights,
        )
        if not allowed:
            self._audit(session, "read", name, False, reason)
            return _fail(
                "read",
                reason,
                level=level_name(int(row["level"])),
                rights_text=rights_text(rights),
            )

        self._audit(session, "read", name, True)
        data = self._metadata(session, row, rights)
        return _ok(
            "read",
            name=name,
            content=row["content"],
            object=data,
        )

    def _handle_create(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        level = parse_level(message.get("level"))
        kind = message.get("kind", FILE_KIND_TEXT)
        if kind not in OBJECT_KINDS:
            raise ValueError(
                f"тип об'єкта має бути одним із: {', '.join(OBJECT_KINDS)}"
            )
        text = _content(message.get("content", ""))

        allowed, reason = mandatory_create_check(session.clearance, level)
        if not allowed:
            self._audit(session, "create", name, False, reason)
            return _fail("create", reason, level=level_name(level))

        with self._lock:
            try:
                object_id = self.db.create_object(
                    name, session.user_id, level, kind, text
                )
            except ObjectExistsError:
                self._audit(session, "create", name, False, "object-exists")
                return _fail(
                    "create", f"об'єкт {name!r} уже існує", code="object-exists"
                )
        self._audit(session, "create", name, True)
        row = self.db.get_object(name)
        assert row is not None
        rights = effective_rights(session.user_id, row["owner_id"], set())
        return _ok(
            "create",
            object_id=object_id,
            object=self._metadata(session, row, rights),
        )

    def _handle_write(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        text = _content(message.get("content"))
        row = self._load(name)
        if row is None:
            self._audit(session, "write", name, False, "object-not-found")
            return _fail("write", f"об'єкт {name!r} не знайдено", code="not-found")

        rights = self._rights(session, row)
        allowed, reason = authorize(
            "write",
            user_id=session.user_id,
            owner_id=row["owner_id"],
            subject_level=session.clearance,
            object_level=int(row["level"]),
            acl_rights=rights,
        )
        if not allowed:
            self._audit(session, "write", name, False, reason)
            return _fail(
                "write",
                reason,
                level=level_name(int(row["level"])),
                rights_text=rights_text(rights),
            )

        with self._lock:
            self.db.set_object_content(int(row["object_id"]), text)
        self._audit(session, "write", name, True)
        updated = self.db.get_object(name)
        assert updated is not None
        return _ok(
            "write",
            name=name,
            size=len(text.encode("utf-8")),
            object=self._metadata(session, updated, rights),
        )

    def _handle_append(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        text = _content(message.get("content"))
        row = self._load(name)
        if row is None:
            self._audit(session, "append", name, False, "object-not-found")
            return _fail("append", f"об'єкт {name!r} не знайдено", code="not-found")

        rights = self._rights(session, row)
        allowed, reason = authorize(
            "append",
            user_id=session.user_id,
            owner_id=row["owner_id"],
            subject_level=session.clearance,
            object_level=int(row["level"]),
            acl_rights=rights,
        )
        if not allowed:
            self._audit(session, "append", name, False, reason)
            return _fail(
                "append",
                reason,
                level=level_name(int(row["level"])),
                rights_text=rights_text(rights),
            )

        new_size = int(row["size"]) + len(text.encode("utf-8"))
        if new_size > MAX_CONTENT_BYTES:
            reason = (
                f"після дописування об'єкт перевищить ліміт "
                f"{MAX_CONTENT_BYTES} байтів"
            )
            self._audit(session, "append", name, False, reason)
            return _fail("append", reason, code="too-large")

        with self._lock:
            self.db.append_object_content(int(row["object_id"]), text)
        self._audit(session, "append", name, True)
        updated = self.db.get_object(name)
        assert updated is not None
        return _ok(
            "append",
            name=name,
            appended=len(text.encode("utf-8")),
            size=int(updated["size"]),
            object=self._metadata(session, updated, rights),
        )

    def _handle_delete(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        row = self._load(name)
        if row is None:
            self._audit(session, "delete", name, False, "object-not-found")
            return _fail("delete", f"об'єкт {name!r} не знайдено", code="not-found")

        rights = self._rights(session, row)
        allowed, reason = authorize(
            "delete",
            user_id=session.user_id,
            owner_id=row["owner_id"],
            subject_level=session.clearance,
            object_level=int(row["level"]),
            acl_rights=rights,
        )
        if not allowed:
            self._audit(session, "delete", name, False, reason)
            return _fail("delete", reason, rights_text=rights_text(rights))

        with self._lock:
            deleted = self.db.delete_object(int(row["object_id"]))
        self._audit(session, "delete", name, deleted)
        if not deleted:
            return _fail("delete", "об'єкт уже видалено", code="not-found")
        return _ok("delete", name=name)

    def _handle_grant(self, session: Session, message: Dict[str, Any]) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        target = validate_user_id(get_str(message, "target", max_len=64))
        rights = parse_rights(message.get("rights"))
        row = self._load(name)
        if row is None:
            self._audit(session, "grant", name, False, "object-not-found")
            return _fail("grant", f"об'єкт {name!r} не знайдено", code="not-found")
        if session.user_id != row["owner_id"]:
            reason = "дискреційна відмова: призначати права може лише власник"
            self._audit(session, "grant", name, False, reason)
            return _fail("grant", reason)
        if target == row["owner_id"]:
            reason = "власник уже має повний набір прав"
            self._audit(session, "grant", name, False, reason)
            return _fail("grant", reason, code="bad-request")
        if self.db.get_user(target) is None:
            reason = f"користувача {target!r} не знайдено"
            self._audit(session, "grant", name, False, reason)
            return _fail("grant", reason, code="not-found")

        with self._lock:
            combined = self.db.grant_acl_rights(
                int(row["object_id"]), target, rights, session.user_id
            )
        self._audit(session, "grant", name, True)
        return _ok(
            "grant",
            name=name,
            target=target,
            granted=sorted_rights(rights),
            rights=sorted_rights(combined),
            acl=[
                {
                    "user": entry["user_id"],
                    "rights": sorted_rights(
                        parse_rights(entry["rights"], allow_empty=True)
                    ),
                }
                for entry in self.db.get_acl(int(row["object_id"]))
            ],
        )

    def _handle_revoke(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        name = validate_object_name(get_str(message, "name", max_len=64))
        target = validate_user_id(get_str(message, "target", max_len=64))
        raw_rights = message.get("rights")
        rights: Optional[Set[str]] = (
            parse_rights(raw_rights) if raw_rights is not None else None
        )
        row = self._load(name)
        if row is None:
            self._audit(session, "revoke", name, False, "object-not-found")
            return _fail("revoke", f"об'єкт {name!r} не знайдено", code="not-found")
        if session.user_id != row["owner_id"]:
            reason = "дискреційна відмова: відбирати права може лише власник"
            self._audit(session, "revoke", name, False, reason)
            return _fail("revoke", reason)

        with self._lock:
            remaining = self.db.revoke_acl_rights(
                int(row["object_id"]), target, rights
            )
        self._audit(session, "revoke", name, True)
        return _ok(
            "revoke",
            name=name,
            target=target,
            rights=sorted_rights(remaining),
        )

    def _handle_audit(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        if session.role != ROLE_ADMIN:
            reason = "журнал дій доступний лише адміністратору"
            self._audit(session, "audit", None, False, reason)
            return _fail("audit", reason)
        limit = message.get("limit", 100)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("поле 'limit' має бути цілим числом")
        limit = max(1, min(limit, MAX_AUDIT_ENTRIES))
        entries = [
            {
                "at": row["at"],
                "user": row["user_id"],
                "action": row["action"],
                "object": row["object_name"],
                "allowed": bool(row["allowed"]),
                "reason": row["reason"],
            }
            for row in self.db.list_audit(limit)
        ]
        return _ok("audit", count=len(entries), entries=entries)

    def _handle_inventory(
        self, session: Session, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        if session.role != ROLE_ADMIN:
            reason = "інвентаризація доступна лише адміністратору"
            self._audit(session, "inventory", None, False, reason)
            return _fail("inventory", reason)
        items = []
        for row in self.db.list_objects():
            rights = self._rights(session, row)
            items.append(self._metadata(session, row, rights))
        return _ok("inventory", count=len(items), objects=items)
