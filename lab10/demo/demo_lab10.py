"""Лабораторна 10: демонстрація журналу аудиту у вигляді таблиці.

Скрипт піднімає справжній TCP-сервер на ``127.0.0.1``, реєструє чотирьох
користувачів, створює 10 серверних об'єктів і виконує як успішні, так і
невдалі спроби автентифікації та доступу до об'єктів.  Після кожного кроку
з журналу ``audit`` вибираються нові записи, тому підсумковий протокол
містить таблицю з двох стовпчиків:

    дія користувача  ->  відображення цієї дії в журналі аудиту

Результат записується у ``logs/lab10_audit_protocol.md``.

Запуск із кореня проєкту::

    python demo/demo_lab10.py
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import shutil
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if sys.path[:1] != [str(PROJECT_ROOT)]:
    try:
        sys.path.remove(str(PROJECT_ROOT))
    except ValueError:
        pass
    sys.path.insert(0, str(PROJECT_ROOT))

from client.client import (
    AuthSession,
    AuthenticationFailed,
    open_session,
    register,
)
from common.audit import event_title, format_audit_table, format_event
from common.security import level_name
from common.util import configure_stdio
from server.db import Database
from server.server import AuthServer

HOST = "127.0.0.1"
DEMO_DIR = PROJECT_ROOT / "data" / "lab10-demo"
TOKEN_ROOT = DEMO_DIR / "tokens"
LOG_PATH = PROJECT_ROOT / "logs" / "lab10_audit_protocol.md"

USERS: Tuple[Tuple[str, int, bool, str], ...] = (
    ("alice", 4, True, "Аліса — адміністратор, TOP_SECRET"),
    ("bob", 3, False, "Богдан — SECRET"),
    ("carol", 2, False, "Кароліна — CONFIDENTIAL"),
    ("dave", 1, False, "Данило — UNCLASSIFIED"),
)

OBJECTS: Tuple[Tuple[str, str, int, str, str], ...] = (
    ("alice", "ts-plan", 4, "text", "TOP_SECRET: план захисту периметра.\n"),
    ("alice", "ts-keys", 4, "file", "TOP_SECRET: перелік ключів (демо).\n"),
    ("alice", "ts-notes", 4, "text", "TOP_SECRET: нотатки адміністратора.\n"),
    ("bob", "s-report", 3, "text", "SECRET: звіт про інцидент.\n"),
    ("bob", "s-design", 3, "text", "SECRET: схема сегмента мережі.\n"),
    ("bob", "s-tasks", 3, "text", "SECRET: перелік завдань групи.\n"),
    ("carol", "c-budget", 2, "text", "CONFIDENTIAL: бюджет підрозділу.\n"),
    ("carol", "c-contacts", 2, "text", "CONFIDENTIAL: контакти партнерів.\n"),
    ("dave", "u-readme", 1, "file", "UNCLASSIFIED: публічна інструкція.\n"),
    ("dave", "u-faq", 1, "text", "UNCLASSIFIED: часті запитання.\n"),
)


class Transcript:
    """Збирає Markdown-протокол і дублює короткі повідомлення у консоль."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lines: List[str] = []

    def line(self, text: str = "") -> None:
        self._lines.append(text)

    def console(self, text: str = "") -> None:
        print(text)
        self.line(text)

    def write(self) -> None:
        self.path.write_text("\n".join(self._lines) + "\n", encoding="utf-8")


class AuditProtocol:
    """Фіксує дію та нові записи журналу, які вона породила."""

    def __init__(self, db: Database, transcript: Transcript) -> None:
        self.db = db
        self.transcript = transcript
        self.rows: List[Tuple[int, str, List[Any]]] = []
        self._number = 0

    def step(self, description: str, action: Callable[[], Any]) -> Any:
        self._number += 1
        before = self.db.last_audit_id()
        result = action()
        events = self.db.list_audit(
            limit=200, after_id=before, ascending=True
        )
        if not events:
            raise RuntimeError(
                f"крок «{description}» не залишив жодного запису в журналі аудиту"
            )
        self.rows.append((self._number, description, events))
        return result

    @staticmethod
    def _audit_cell(events: Sequence[Any]) -> str:
        chunks: List[str] = []
        for event in events:
            text = format_event(event)
            code = str(event["event"])
            title = event_title(code)
            if title != code:
                text = text.replace(code, f"{code} — {title}", 1)
            # Вертикальна риска всередині комірки Markdown ламає таблицю.
            chunks.append(text.replace("|", "\\|"))
        return "<br>".join(chunks)

    def render(self) -> None:
        t = self.transcript
        t.line()
        t.line("## Таблиця «дія користувача — запис у журналі аудиту»")
        t.line()
        t.line("| Дія користувача | Відображення в журналі аудиту |")
        t.line("|---|---|")
        for number, description, events in self.rows:
            t.line(
                f"| {number}. {description} | {self._audit_cell(events)} |"
            )

        t.line()
        t.line("## Повний журнал аудиту")
        t.line()
        t.line("```text")
        for line in format_audit_table(
            self.db.list_audit(limit=500, ascending=True)
        ):
            t.line(line)
        t.line("```")


def _create(
    session: AuthSession,
    name: str,
    level: int,
    kind: str,
    content: str,
) -> Dict[str, Any]:
    reply = session.request(
        "create", name=name, level=level, kind=kind, content=content
    )
    if not reply.get("ok"):
        raise RuntimeError(f"не вдалося створити {name}: {reply}")
    return reply


def _expect(
    session: AuthSession,
    action: str,
    *,
    ok: bool,
    **fields: Any,
) -> Dict[str, Any]:
    reply = session.request(action, **fields)
    if bool(reply.get("ok")) != ok:
        raise RuntimeError(
            f"{session.user_id}: {action} {fields.get('name', '')} — "
            f"очікували {'дозвіл' if ok else 'відмову'}, отримали {reply}"
        )
    return reply


def _failed_login(token_dir: Path, note: str) -> str:
    try:
        open_session(HOST, CURRENT_PORT[0], str(token_dir), allow_fixed=True)
    except AuthenticationFailed as exc:
        return f"{note}: {exc}"
    raise RuntimeError(f"{note}: сервер несподівано дозволив вхід")


CURRENT_PORT: List[int] = [0]


def _forge_token(
    source: Path,
    destination: Path,
    *,
    secret: Optional[bytes] = None,
    user_id: Optional[str] = None,
) -> Path:
    """Копіює файл токена й підміняє секрет або ідентифікатор для демо-атак."""
    destination.mkdir(parents=True, exist_ok=True)
    payload = json.loads(
        (source / "usb_auth_token.json").read_text(encoding="utf-8")
    )
    if secret is not None:
        payload["secret"] = base64.b64encode(secret).decode("ascii")
    if user_id is not None:
        payload["user_id"] = user_id
    (destination / "usb_auth_token.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def _register_users(
    db: Database,
    protocol: AuditProtocol,
    token_dirs: Dict[str, Path],
) -> Dict[str, AuthSession]:
    sessions: Dict[str, AuthSession] = {}
    for user_id, level, admin, note in USERS:
        code = db.issue_enroll_code(
            ttl_seconds=900, note=note, level=level, admin=admin
        )
        token_dir = TOKEN_ROOT / user_id
        token_dir.mkdir(parents=True, exist_ok=True)
        token_dirs[user_id] = token_dir
        protocol.step(
            f"{user_id}: реєстрація токена за одноразовим кодом "
            f"(допуск {level_name(level)}, роль {'admin' if admin else 'user'})",
            lambda u=user_id, d=token_dir, c=code: register(
                HOST,
                CURRENT_PORT[0],
                str(d),
                u,
                "SHA256",
                c,
                allow_fixed=True,
            ),
        )
    return sessions


def _open_sessions(
    protocol: AuditProtocol, token_dirs: Dict[str, Path]
) -> Dict[str, AuthSession]:
    sessions: Dict[str, AuthSession] = {}
    for user_id, level, _admin, _note in USERS:
        sessions[user_id] = protocol.step(
            f"{user_id}: успішне рукостискання з сервером "
            f"(допуск {level_name(level)})",
            lambda u=user_id: open_session(
                HOST,
                CURRENT_PORT[0],
                str(token_dirs[u]),
                allow_fixed=True,
            ),
        )
    return sessions


def _failed_authentications(
    db: Database,
    protocol: AuditProtocol,
    token_dirs: Dict[str, Path],
) -> None:
    # 1. Хибний секрет у скопійованому токені.
    forged = _forge_token(
        token_dirs["alice"],
        TOKEN_ROOT / "intruder-bad-secret",
        secret=b"x" * 32,
    )
    protocol.step(
        "intruder: вхід із підробленим секретом токена (очікувана відмова)",
        lambda: _failed_login(forged, "хибний секрет"),
    )

    # 2. Неіснуючий ідентифікатор користувача.
    ghost = _forge_token(
        token_dirs["bob"],
        TOKEN_ROOT / "intruder-unknown-user",
        user_id="mallory",
    )
    protocol.step(
        "mallory: вхід із невідомим ідентифікатором (очікувана відмова)",
        lambda: _failed_login(ghost, "невідомий користувач"),
    )

    # 3. Вимкнений обліковий запис.
    db.set_enabled("dave", False)
    protocol.step(
        "dave: вхід після вимкнення облікового запису (очікувана відмова)",
        lambda: _failed_login(token_dirs["dave"], "обліковий запис вимкнено"),
    )
    db.set_enabled("dave", True)


def _create_objects(
    protocol: AuditProtocol, sessions: Dict[str, AuthSession]
) -> None:
    for owner, name, level, kind, content in OBJECTS:
        protocol.step(
            f"{owner}: створення об'єкта {name} рівня {level_name(level)} "
            f"(тип {kind})",
            lambda o=owner, n=name, l=level, k=kind, c=content: _create(
                sessions[o], n, l, k, c
            ),
        )


def _run_object_scenario(
    protocol: AuditProtocol, sessions: Dict[str, AuthSession]
) -> None:
    alice = sessions["alice"]
    bob = sessions["bob"]
    carol = sessions["carol"]
    dave = sessions["dave"]

    protocol.step(
        "bob: читання власного об'єкта s-report",
        lambda: _expect(bob, "read", ok=True, name="s-report"),
    )
    protocol.step(
        "alice: спроба прочитати s-report без права в ACL (очікувана відмова)",
        lambda: _expect(alice, "read", ok=False, name="s-report"),
    )
    protocol.step(
        "bob: надання alice права read на s-report",
        lambda: _expect(
            bob, "grant", ok=True, name="s-report", target="alice", rights="read"
        ),
    )
    protocol.step(
        "alice: читання s-report після надання права read",
        lambda: _expect(alice, "read", ok=True, name="s-report"),
    )
    protocol.step(
        "alice: спроба дописати в s-report без права append (очікувана відмова)",
        lambda: _expect(
            alice, "append", ok=False, name="s-report", content="TOP_SECRET: x\n"
        ),
    )
    protocol.step(
        "bob: надання alice права append на s-report",
        lambda: _expect(
            bob, "grant", ok=True, name="s-report", target="alice", rights="append"
        ),
    )
    protocol.step(
        "alice: дописування вниз у s-report, TOP_SECRET -> SECRET "
        "(очікувана відмова no-write-down)",
        lambda: _expect(
            alice,
            "append",
            ok=False,
            name="s-report",
            content="TOP_SECRET: спроба запису вниз.\n",
        ),
    )
    protocol.step(
        "alice: надання dave права read на ts-plan",
        lambda: _expect(
            alice, "grant", ok=True, name="ts-plan", target="dave", rights="read"
        ),
    )
    protocol.step(
        "dave: спроба прочитати ts-plan вищого рівня "
        "(очікувана відмова no-read-up)",
        lambda: _expect(dave, "read", ok=False, name="ts-plan"),
    )
    protocol.step(
        "bob: надання carol права read на s-report",
        lambda: _expect(
            bob, "grant", ok=True, name="s-report", target="carol", rights="read"
        ),
    )
    protocol.step(
        "carol: спроба прочитати s-report вищого рівня "
        "(очікувана відмова no-read-up)",
        lambda: _expect(carol, "read", ok=False, name="s-report"),
    )
    protocol.step(
        "bob: надання carol права append на s-report",
        lambda: _expect(
            bob, "grant", ok=True, name="s-report", target="carol", rights="append"
        ),
    )
    protocol.step(
        "carol: дописування вгору в s-report, CONFIDENTIAL -> SECRET",
        lambda: _expect(
            carol,
            "append",
            ok=True,
            name="s-report",
            content="CONFIDENTIAL: коментар Кароліни.\n",
        ),
    )
    protocol.step(
        "carol: спроба видалити s-report без права delete (очікувана відмова)",
        lambda: _expect(carol, "delete", ok=False, name="s-report"),
    )
    protocol.step(
        "bob: видалення власного об'єкта s-tasks",
        lambda: _expect(bob, "delete", ok=True, name="s-tasks"),
    )
    protocol.step(
        "carol: читання вже видаленого s-tasks (очікувана відмова object-not-found)",
        lambda: _expect(carol, "read", ok=False, name="s-tasks"),
    )
    protocol.step(
        "carol: створення об'єкта нижче допуску, CONFIDENTIAL -> UNCLASSIFIED "
        "(очікувана відмова no-write-down)",
        lambda: _expect(
            carol,
            "create",
            ok=False,
            name="c-low",
            level=1,
            kind="text",
            content="спроба запису вниз",
        ),
    )
    protocol.step(
        "bob: заміна вмісту власного s-report (рівні збігаються)",
        lambda: _expect(
            bob,
            "write",
            ok=True,
            name="s-report",
            content="SECRET: звіт про інцидент (версія 2).\n",
        ),
    )
    protocol.step(
        "dave: дописування у власний u-readme",
        lambda: _expect(
            dave, "append", ok=True, name="u-readme", content="UNCLASSIFIED: доповнення.\n"
        ),
    )
    protocol.step(
        "bob: відбирання права read у carol на s-report",
        lambda: _expect(
            bob, "revoke", ok=True, name="s-report", target="carol", rights="read"
        ),
    )
    protocol.step(
        "carol: повторне читання s-report після відбирання права "
        "(очікувана відмова)",
        lambda: _expect(carol, "read", ok=False, name="s-report"),
    )
    protocol.step(
        "alice: перевірка власного допуску та ролі (whoami)",
        lambda: _expect(alice, "whoami", ok=True),
    )
    protocol.step(
        "alice: перегляд списку доступних об'єктів (list)",
        lambda: _expect(alice, "list", ok=True),
    )
    protocol.step(
        "bob: перегляд метаданих s-report (info)",
        lambda: _expect(bob, "info", ok=True, name="s-report"),
    )
    protocol.step(
        "bob: запит метаданих неіснуючого об'єкта (очікувана відмова)",
        lambda: _expect(bob, "info", ok=False, name="no-such-object"),
    )
    protocol.step(
        "alice: інвентаризація всіх об'єктів як адміністратор",
        lambda: _expect(alice, "inventory", ok=True),
    )
    protocol.step(
        "bob: спроба інвентаризації без ролі адміністратора "
        "(очікувана відмова)",
        lambda: _expect(bob, "inventory", ok=False),
    )
    protocol.step(
        "alice: перегляд журналу аудиту як адміністратор",
        lambda: _expect(alice, "audit", ok=True, limit=200),
    )
    protocol.step(
        "bob: спроба переглянути журнал аудиту без ролі адміністратора "
        "(очікувана відмова)",
        lambda: _expect(bob, "audit", ok=False),
    )


def main() -> int:
    configure_stdio()
    logging.getLogger("usb-auth.server").setLevel(logging.WARNING)

    shutil.rmtree(DEMO_DIR, ignore_errors=True)
    TOKEN_ROOT.mkdir(parents=True, exist_ok=True)
    if LOG_PATH.exists():
        LOG_PATH.unlink()

    transcript = Transcript(LOG_PATH)
    server: Optional[AuthServer] = None
    sessions: Dict[str, AuthSession] = {}
    token_dirs: Dict[str, Path] = {}
    try:
        db = Database(str(DEMO_DIR / "auth.db"))
        db.initialize()
        server = AuthServer(db, host=HOST, port=0, timeout=15.0)
        server.start()
        CURRENT_PORT[0] = server.port
        thread = threading.Thread(
            target=server.serve_forever, name="lab10-demo-server", daemon=True
        )
        thread.start()

        protocol = AuditProtocol(db, transcript)

        transcript.line("# Лабораторна 10. Протокол реєстрації подій")
        transcript.line()
        transcript.line(
            "Дата запуску: "
            + datetime.datetime.now().isoformat(timespec="seconds")
        )
        transcript.line()
        transcript.line(f"* Проєкт: `{PROJECT_ROOT}`")
        transcript.line(f"* Сервер: `{HOST}:{server.port}` (loopback)")
        transcript.line(f"* База даних: `{db.path}`")
        transcript.line(
            "* Користувачі: alice (TOP_SECRET/admin), bob (SECRET), "
            "carol (CONFIDENTIAL), dave (UNCLASSIFIED)"
        )
        transcript.line(
            "* Події: успішні та невдалі входи, успішні та невдалі "
            "операції з об'єктами"
        )

        _register_users(db, protocol, token_dirs)
        sessions = _open_sessions(protocol, token_dirs)
        _failed_authentications(db, protocol, token_dirs)
        _create_objects(protocol, sessions)
        _run_object_scenario(protocol, sessions)

        protocol.render()

        transcript.line()
        transcript.line("## Підсумок")
        transcript.line()
        total = len(protocol.rows)
        denied = sum(
            1
            for _number, _description, events in protocol.rows
            for event in events
            if not bool(event["allowed"])
        )
        allowed = sum(
            1
            for _number, _description, events in protocol.rows
            for event in events
            if bool(event["allowed"])
        )
        transcript.line(f"* Кроків сценарію: **{total}**")
        transcript.line(f"* Записів аудиту: **{allowed + denied}** "
                        f"(дозволено — {allowed}, відмовлено — {denied})")
        transcript.line(f"* Протокол: `{LOG_PATH}`")

        transcript.write()
        print()
        print(f"[OK] Протокол записано: {LOG_PATH}")
        print(f"[OK] Кроків: {total}; подій аудиту: {allowed + denied} "
              f"(allow={allowed}, deny={denied})")
        return 0
    finally:
        for session in sessions.values():
            session.close()
        if server is not None:
            server.stop()
        transcript.write()


if __name__ == "__main__":
    raise SystemExit(main())
