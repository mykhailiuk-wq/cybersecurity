"""Системна база даних сервера (SQLite).

У таблиці ``users`` зберігаються ідентифікатор користувача, узгоджена
процедура перетворення (назва хеш-алгоритму CryptoAPI), секрет токена,
серійний номер носія, допуск (рівень секретності) та роль.

Таблиця ``enroll_codes`` містить одноразові коди, які адміністратор видає
для реєстрації нових токенів.  Саме код визначає допуск і роль нового
користувача, тому клієнт не може сам собі підвищити рівень.

Таблиці ``objects``, ``acl`` і ``audit`` реалізують серверне сховище
об'єктів даних, дискреційні списки доступу та журнал дій.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from typing import Iterable, Iterator, List, Optional, Set

from common.audit import event_code, severity_for
from common.crypto import normalize_algorithm, random_bytes
from common.protocol import format_enroll_code, normalize_enroll_code, validate_user_id
from common.security import (
    GRANTABLE_RIGHTS,
    ROLE_ADMIN,
    ROLE_USER,
    parse_level,
    parse_rights,
    parse_role,
    sorted_rights,
    validate_object_name,
)
from common.util import parse_iso, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    algorithm    TEXT NOT NULL,
    secret       BLOB NOT NULL,
    media_serial TEXT,
    created_at   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    clearance    INTEGER NOT NULL DEFAULT 1,
    role         TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS enroll_codes (
    code       TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    used_by    TEXT,
    note       TEXT,
    clearance  INTEGER NOT NULL DEFAULT 1,
    is_admin   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS objects (
    object_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    owner_id   TEXT NOT NULL,
    level      INTEGER NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'text',
    content    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS acl (
    object_id  INTEGER NOT NULL,
    user_id    TEXT NOT NULL,
    rights     TEXT NOT NULL,
    granted_by TEXT,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (object_id, user_id),
    FOREIGN KEY (object_id) REFERENCES objects(object_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    user_id     TEXT,
    action      TEXT NOT NULL,
    object_name TEXT,
    allowed     INTEGER NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    event       TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'INFO',
    peer        TEXT,
    session_id  TEXT,
    details     TEXT NOT NULL DEFAULT ''
);

"""

# Індекси створюються після міграції: у старих базах стовпця audit.event
# ще немає, і CREATE INDEX на нього завершився б помилкою.
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_objects_level ON objects(level);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit(event);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id);
"""

# Можливі результати Database.enroll_user().
ENROLL_OK = "ok"
ENROLL_BAD_CODE = "bad_code"
ENROLL_CODE_USED = "code_used"
ENROLL_CODE_EXPIRED = "code_expired"
ENROLL_USER_EXISTS = "user_exists"


class ObjectExistsError(Exception):
    """Об'єкт з таким іменем уже є в сховищі."""


def _column_names(conn: sqlite3.Connection, table: str) -> Set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


class Database:
    """Невелика обгортка над SQLite; з'єднання відкривається на операцію."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    # --- службові методи ----------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @contextmanager
    def _query(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Додає нові стовпці у базу, створену попередньою версією програми."""
        user_columns = _column_names(conn, "users")
        if "clearance" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN clearance INTEGER NOT NULL DEFAULT 1"
            )
        if "role" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
            )

        code_columns = _column_names(conn, "enroll_codes")
        if "clearance" not in code_columns:
            conn.execute(
                "ALTER TABLE enroll_codes ADD COLUMN clearance INTEGER NOT NULL DEFAULT 1"
            )
        if "is_admin" not in code_columns:
            conn.execute(
                "ALTER TABLE enroll_codes ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"
            )

        audit_columns = _column_names(conn, "audit")
        added_event = "event" not in audit_columns
        if added_event:
            conn.execute("ALTER TABLE audit ADD COLUMN event TEXT NOT NULL DEFAULT ''")
        if "severity" not in audit_columns:
            conn.execute(
                "ALTER TABLE audit ADD COLUMN severity TEXT NOT NULL DEFAULT 'INFO'"
            )
        if "peer" not in audit_columns:
            conn.execute("ALTER TABLE audit ADD COLUMN peer TEXT")
        if "session_id" not in audit_columns:
            conn.execute("ALTER TABLE audit ADD COLUMN session_id TEXT")
        if "details" not in audit_columns:
            conn.execute("ALTER TABLE audit ADD COLUMN details TEXT NOT NULL DEFAULT ''")

        # Записи, створені попередньою версією (лаб. 9), не мали кодів подій.
        # Відновлюємо їх із наявних action/allowed, щоб фільтри працювали.
        if added_event:
            conn.execute(
                "UPDATE audit SET event = CASE action "
                "WHEN 'login' THEN CASE allowed WHEN 1 THEN 'AUTH-SUCCESS' "
                "ELSE 'AUTH-FAILURE' END "
                "WHEN 'enroll' THEN CASE allowed WHEN 1 THEN 'ENROLL-SUCCESS' "
                "ELSE 'ENROLL-FAILURE' END "
                "WHEN 'audit' THEN CASE allowed WHEN 1 THEN 'ADMIN-AUDIT-ALLOW' "
                "ELSE 'ADMIN-AUDIT-DENY' END "
                "WHEN 'inventory' THEN CASE allowed WHEN 1 THEN "
                "'ADMIN-INVENTORY-ALLOW' ELSE 'ADMIN-INVENTORY-DENY' END "
                "ELSE 'OBJECT-' || UPPER(action) || "
                "CASE allowed WHEN 1 THEN '-ALLOW' ELSE '-DENY' END END "
                "WHERE event = ''"
            )
            conn.execute(
                "UPDATE audit SET severity = CASE "
                "WHEN allowed = 0 THEN 'WARNING' ELSE 'INFO' END "
                "WHERE severity = 'INFO' AND allowed = 0"
            )

    def initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.executescript(INDEXES)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.commit()
        finally:
            conn.close()

    # --- користувачі --------------------------------------------------------

    def get_user(self, user_id: str) -> Optional[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT user_id, algorithm, secret, media_serial, created_at, "
                "enabled, clearance, role FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()

    def list_users(self) -> List[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT user_id, algorithm, media_serial, created_at, enabled, "
                "clearance, role FROM users ORDER BY user_id"
            ).fetchall()

    def set_enabled(self, user_id: str, enabled: bool) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET enabled = ? WHERE user_id = ?",
                (1 if enabled else 0, user_id),
            )
            return cursor.rowcount == 1

    def set_clearance(self, user_id: str, level: int) -> bool:
        rank = parse_level(level)
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET clearance = ? WHERE user_id = ?", (rank, user_id)
            )
            return cursor.rowcount == 1

    def set_role(self, user_id: str, role: str) -> bool:
        role = parse_role(role)
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET role = ? WHERE user_id = ?", (role, user_id)
            )
            return cursor.rowcount == 1

    def delete_user(self, user_id: str) -> bool:
        try:
            with self._transaction() as conn:
                conn.execute("DELETE FROM acl WHERE user_id = ?", (user_id,))
                cursor = conn.execute(
                    "DELETE FROM users WHERE user_id = ?", (user_id,)
                )
                return cursor.rowcount == 1
        except sqlite3.IntegrityError:
            # Користувач володіє об'єктами; спочатку їх треба видалити.
            return False

    # --- реєстрація ---------------------------------------------------------

    def issue_enroll_code(
        self,
        ttl_seconds: int = 900,
        note: Optional[str] = None,
        *,
        level: int = 1,
        admin: bool = False,
    ) -> str:
        """Створює одноразовий код реєстрації; повертає його у форматі XXXX-XXXX-..."""
        if ttl_seconds <= 0:
            raise ValueError("термін дії коду має бути додатним")
        rank = parse_level(level)
        code = random_bytes(8).hex().upper()
        now = utc_now()
        expires = now + timedelta(seconds=ttl_seconds)
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO enroll_codes"
                "(code, created_at, expires_at, note, clearance, is_admin) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    code,
                    now.isoformat(timespec="seconds"),
                    expires.isoformat(timespec="seconds"),
                    note,
                    rank,
                    1 if admin else 0,
                ),
            )
        return format_enroll_code(code)

    def enroll_user(
        self,
        code: str,
        user_id: str,
        algorithm: str,
        secret: bytes,
        media_serial: Optional[str] = None,
    ) -> str:
        """Атомарно витрачає код і створює користувача.

        Допуск і роль беруться з коду реєстрації, а не від клієнта.
        Повертає один із статусів ENROLL_*.
        """
        normalized_code = normalize_enroll_code(code)
        user_id = validate_user_id(user_id)
        algorithm = normalize_algorithm(algorithm)
        if not isinstance(secret, (bytes, bytearray)) or not 16 <= len(secret) <= 64:
            raise ValueError("секрет токена має містити від 16 до 64 байтів")
        if media_serial is not None and len(media_serial) > 32:
            raise ValueError("серійний номер носія задовгий")

        now = utc_now()
        now_text = now.isoformat(timespec="seconds")
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT used_at, expires_at, clearance, is_admin "
                    "FROM enroll_codes WHERE code = ?",
                    (normalized_code,),
                ).fetchone()
                if row is None:
                    return ENROLL_BAD_CODE
                if row["used_at"]:
                    return ENROLL_CODE_USED
                try:
                    expires_at = parse_iso(row["expires_at"])
                except ValueError:
                    return ENROLL_CODE_EXPIRED
                if expires_at <= now:
                    return ENROLL_CODE_EXPIRED
                if conn.execute(
                    "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
                ).fetchone():
                    return ENROLL_USER_EXISTS
                updated = conn.execute(
                    "UPDATE enroll_codes SET used_at = ?, used_by = ? "
                    "WHERE code = ? AND used_at IS NULL",
                    (now_text, user_id, normalized_code),
                )
                if updated.rowcount != 1:
                    return ENROLL_CODE_USED
                role = ROLE_ADMIN if row["is_admin"] else ROLE_USER
                conn.execute(
                    "INSERT INTO users"
                    "(user_id, algorithm, secret, media_serial, created_at, "
                    "clearance, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        algorithm,
                        bytes(secret),
                        media_serial,
                        now_text,
                        int(row["clearance"]),
                        role,
                    ),
                )
                return ENROLL_OK
        except sqlite3.IntegrityError:
            # Паралельна реєстрація того самого id — код відкотився разом із транзакцією.
            return ENROLL_USER_EXISTS

    # --- об'єкти даних ------------------------------------------------------

    def create_object(
        self,
        name: str,
        owner_id: str,
        level: int,
        kind: str = "text",
        content: str = "",
    ) -> int:
        name = validate_object_name(name)
        rank = parse_level(level)
        now = utc_now().isoformat(timespec="seconds")
        try:
            with self._transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO objects"
                    "(name, owner_id, level, kind, content, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, owner_id, rank, kind, content, now, now),
                )
                return int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ObjectExistsError(name) from exc

    def get_object(self, name: str) -> Optional[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT o.*, length(CAST(o.content AS BLOB)) AS size "
                "FROM objects o WHERE o.name = ?",
                (name,),
            ).fetchone()

    def list_objects(self) -> List[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT o.*, length(CAST(o.content AS BLOB)) AS size "
                "FROM objects o ORDER BY o.level DESC, o.name"
            ).fetchall()

    def list_objects_for_user(self, user_id: str) -> List[sqlite3.Row]:
        """Об'єкти, на які користувач має хоча б одне право (власник або ACL)."""
        with self._query() as conn:
            return conn.execute(
                "SELECT o.*, length(CAST(o.content AS BLOB)) AS size, "
                "a.rights AS acl_rights "
                "FROM objects o "
                "LEFT JOIN acl a ON a.object_id = o.object_id AND a.user_id = ? "
                "WHERE o.owner_id = ? OR a.user_id IS NOT NULL "
                "ORDER BY o.level DESC, o.name",
                (user_id, user_id),
            ).fetchall()

    def set_object_content(self, object_id: int, content: str) -> None:
        now = utc_now().isoformat(timespec="seconds")
        with self._transaction() as conn:
            conn.execute(
                "UPDATE objects SET content = ?, updated_at = ? WHERE object_id = ?",
                (content, now, object_id),
            )

    def append_object_content(self, object_id: int, content: str) -> None:
        now = utc_now().isoformat(timespec="seconds")
        with self._transaction() as conn:
            conn.execute(
                "UPDATE objects SET content = content || ?, updated_at = ? "
                "WHERE object_id = ?",
                (content, now, object_id),
            )

    def delete_object(self, object_id: int) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM objects WHERE object_id = ?", (object_id,)
            )
            return cursor.rowcount == 1

    # --- дискреційний доступ (ACL) -----------------------------------------

    def get_acl(self, object_id: int) -> List[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT user_id, rights, granted_by, granted_at "
                "FROM acl WHERE object_id = ? ORDER BY user_id",
                (object_id,),
            ).fetchall()

    def get_acl_rights(self, object_id: int, user_id: str) -> Set[str]:
        with self._query() as conn:
            row = conn.execute(
                "SELECT rights FROM acl WHERE object_id = ? AND user_id = ?",
                (object_id, user_id),
            ).fetchone()
        if row is None:
            return set()
        return parse_rights(row["rights"], allow_empty=True)

    def grant_acl_rights(
        self,
        object_id: int,
        user_id: str,
        rights: Iterable[str],
        granted_by: str,
    ) -> Set[str]:
        """Додає права до ACL (об'єднання з наявними) і повертає результат."""
        requested = {right for right in rights if right in GRANTABLE_RIGHTS}
        if not requested:
            raise ValueError("потрібно вказати хоча б одне право")
        now = utc_now().isoformat(timespec="seconds")
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT rights FROM acl WHERE object_id = ? AND user_id = ?",
                (object_id, user_id),
            ).fetchone()
            current = (
                parse_rights(row["rights"], allow_empty=True) if row else set()
            )
            combined = current | requested
            conn.execute(
                "INSERT INTO acl(object_id, user_id, rights, granted_by, granted_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(object_id, user_id) DO UPDATE SET "
                "rights = excluded.rights, granted_by = excluded.granted_by, "
                "granted_at = excluded.granted_at",
                (
                    object_id,
                    user_id,
                    ",".join(sorted_rights(combined)),
                    granted_by,
                    now,
                ),
            )
            return combined

    def revoke_acl_rights(
        self,
        object_id: int,
        user_id: str,
        rights: Optional[Iterable[str]] = None,
    ) -> Set[str]:
        """Відбирає права; без ``rights`` видаляє запис ACL повністю."""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT rights FROM acl WHERE object_id = ? AND user_id = ?",
                (object_id, user_id),
            ).fetchone()
            if row is None:
                return set()
            current = parse_rights(row["rights"], allow_empty=True)
            remaining = set() if rights is None else current - set(rights)
            if remaining:
                conn.execute(
                    "UPDATE acl SET rights = ? WHERE object_id = ? AND user_id = ?",
                    (",".join(sorted_rights(remaining)), object_id, user_id),
                )
            else:
                conn.execute(
                    "DELETE FROM acl WHERE object_id = ? AND user_id = ?",
                    (object_id, user_id),
                )
            return remaining

    # --- журнал дій ---------------------------------------------------------

    def log_audit(
        self,
        user_id: Optional[str],
        action: str,
        object_name: Optional[str],
        allowed: bool,
        reason: str = "",
        *,
        event: Optional[str] = None,
        severity: Optional[str] = None,
        peer: Optional[str] = None,
        session_id: Optional[str] = None,
        details: str = "",
    ) -> int:
        """Записує одну подію аудиту та повертає її ідентифікатор.

        ``event`` і ``severity`` обчислюються автоматично, якщо не задані.
        Поля ``peer``/``session_id`` дозволяють зіставити подію з конкретним
        мережевим з'єднанням, а ``details`` — зберегти додатковий контекст
        (наприклад, цільову особу для grant/revoke).
        """
        code = event or event_code(action, allowed)
        level = severity or severity_for(code, allowed)
        with self._transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO audit(at, user_id, action, object_name, allowed, "
                "reason, event, severity, peer, session_id, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    utc_now().isoformat(timespec="seconds"),
                    user_id,
                    action,
                    object_name,
                    1 if allowed else 0,
                    reason,
                    code,
                    level,
                    peer,
                    session_id,
                    details,
                ),
            )
            return int(cursor.lastrowid or 0)

    def last_audit_id(self) -> int:
        """Ідентифікатор останнього запису журналу (0 — журнал порожній)."""
        with self._query() as conn:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) AS last FROM audit").fetchone()
        return int(row["last"]) if row is not None else 0

    def list_audit(
        self,
        limit: int = 100,
        *,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        allowed: Optional[bool] = None,
        event: Optional[str] = None,
        object_name: Optional[str] = None,
        after_id: Optional[int] = None,
        ascending: bool = False,
    ) -> List[sqlite3.Row]:
        """Повертає журнал із необов'язковими фільтрами.

        ``after_id`` зручний для демонстрації: він дозволяє взяти лише ті
        події, які з'явилися після попереднього кроку сценарію.
        """
        limit = max(1, min(int(limit), 5000))
        clauses: List[str] = []
        params: List[object] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if action is not None:
            clauses.append("action = ?")
            params.append(action.strip().lower())
        if allowed is not None:
            clauses.append("allowed = ?")
            params.append(1 if allowed else 0)
        if event is not None:
            clauses.append("event = ?")
            params.append(event.strip().upper())
        if object_name is not None:
            clauses.append("object_name = ?")
            params.append(object_name)
        if after_id is not None:
            clauses.append("id > ?")
            params.append(int(after_id))

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        params.append(limit)
        with self._query() as conn:
            return conn.execute(
                "SELECT id, at, user_id, action, object_name, allowed, reason, "
                "event, severity, peer, session_id, details "
                f"FROM audit{where} ORDER BY id {order} LIMIT ?",
                params,
            ).fetchall()
