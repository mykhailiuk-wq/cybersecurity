"""Демонстрація роботи: 4 користувачі, 10+ об'єктів, модель Белла-ЛаПадула.

Скрипт піднімає справжній TCP-сервер на loopback 127.0.0.1, реєструє токени
чотирьох користувачів з різними допусками, створює серверні об'єкти й
виконує як дозволені, так і заборонені операції.  Кожен запит і відповідь
записуються у протокол ``logs/lab9_protocol.log``.

Запуск із кореня проєкту::

    python demo/demo_blp.py
"""

from __future__ import annotations

import datetime
import json
import logging
import shutil
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if sys.path[:1] != [str(PROJECT_ROOT)]:
    try:
        sys.path.remove(str(PROJECT_ROOT))
    except ValueError:
        pass
    sys.path.insert(0, str(PROJECT_ROOT))

from client.client import AuthSession, open_session, register
from common.security import level_name
from common.util import configure_stdio
from server.db import Database
from server.server import AuthServer

HOST = "127.0.0.1"
DEMO_DIR = PROJECT_ROOT / "data" / "lab9-demo"
TOKEN_ROOT = DEMO_DIR / "tokens"
LOG_PATH = PROJECT_ROOT / "logs" / "lab9_protocol.log"

USERS = (
    ("alice", 4, True, "Аліса — адміністратор, TOP_SECRET"),
    ("bob", 3, False, "Богдан — SECRET"),
    ("carol", 2, False, "Кароліна — CONFIDENTIAL"),
    ("dave", 1, False, "Данило — UNCLASSIFIED"),
)


class Transcript:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("w", encoding="utf-8")
        self._step = 0

    def line(self, text: str = "") -> None:
        print(text)
        self._file.write(text + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def section(self, title: str) -> None:
        self.line()
        self.line("=" * 78)
        self.line(title)
        self.line("=" * 78)

    def call(
        self,
        session: AuthSession,
        action: str,
        *,
        expect_ok: bool,
        **fields: Any,
    ) -> Dict[str, Any]:
        self._step += 1
        response = session.request(action, **fields)
        actual = bool(response.get("ok"))
        request_preview = {"action": action}
        request_preview.update(fields)
        self.line()
        self.line(
            f"#{self._step:02d} [{session.user_id} / {level_name(session.clearance)}] "
            f"{action.upper()} {fields.get('name', '')}".rstrip()
        )
        self.line("  -> " + json.dumps(_shorten(request_preview), ensure_ascii=False))
        self.line("  <- " + json.dumps(_shorten(response), ensure_ascii=False))
        if actual:
            self.line("  РЕЗУЛЬТАТ: ДОЗВОЛЕНО")
        else:
            self.line(
                f"  РЕЗУЛЬТАТ: ВІДМОВА [{response.get('code', 'denied')}] "
                f"{response.get('reason', '')}"
            )
        if actual != expect_ok:
            raise RuntimeError(
                f"крок #{self._step}: очікували "
                f"{'дозвіл' if expect_ok else 'відмову'}, отримали {response}"
            )
        return response


def _shorten(value: Any, *, limit: int = 140) -> Any:
    """Скорочує довгі рядки (вміст об'єктів) у протоколі."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…"
    if isinstance(value, list):
        return [_shorten(item, limit=limit) for item in value]
    if isinstance(value, dict):
        return {key: _shorten(item, limit=limit) for key, item in value.items()}
    return value


def _register_users(
    db: Database, transcript: Transcript, port: int
) -> Dict[str, AuthSession]:
    sessions: Dict[str, AuthSession] = {}
    transcript.section("1. РЕЄСТРАЦІЯ КОРИСТУВАЧІВ І ТОКЕНІВ")
    for user_id, level, admin, note in USERS:
        code = db.issue_enroll_code(
            ttl_seconds=900, note=note, level=level, admin=admin
        )
        token_dir = TOKEN_ROOT / user_id
        token_dir.mkdir(parents=True, exist_ok=True)
        path = register(
            HOST,
            port,
            str(token_dir),
            user_id,
            "SHA256",
            code,
            allow_fixed=True,
        )
        transcript.line(
            f"[{user_id}] код видано, токен записано: {path.relative_to(PROJECT_ROOT)}"
        )
        transcript.line(
            f"         допуск: {level_name(level)}; роль: "
            f"{'admin' if admin else 'user'}"
        )
        sessions[user_id] = open_session(
            HOST, port, str(token_dir), allow_fixed=True
        )
        transcript.line(
            f"         рукостискання: OK, сеанс {sessions[user_id].session_id}"
        )
    return sessions


def _create_objects(sessions: Dict[str, AuthSession], transcript: Transcript) -> None:
    transcript.section("2. СТВОРЕННЯ СЕРВЕРНИХ ОБ'ЄКТІВ (11 об'єктів)")
    seed = DEMO_DIR / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    readme_file = seed / "u-readme.txt"
    readme_file.write_text(
        "Публічна інструкція лабораторної роботи.\n"
        "Об'єкт створено з текстового файлу.\n",
        encoding="utf-8",
    )

    objects: List[tuple[str, str, int, str, str]] = [
        (
            "alice",
            "ts-plan",
            4,
            "text",
            "TOP_SECRET: план захисту периметра.\n",
        ),
        (
            "alice",
            "ts-keys",
            4,
            "file",
            "TOP_SECRET: перелік ключів (демонстраційні дані).\n",
        ),
        (
            "alice",
            "ts-notes",
            4,
            "text",
            "TOP_SECRET: нотатки адміністратора.\n",
        ),
        ("bob", "s-report", 3, "text", "SECRET: звіт про інцидент.\n"),
        ("bob", "s-design", 3, "text", "SECRET: схема сегмента мережі.\n"),
        ("bob", "s-tasks", 3, "text", "SECRET: перелік завдань групи.\n"),
        ("carol", "c-budget", 2, "text", "CONFIDENTIAL: бюджет підрозділу.\n"),
        ("carol", "c-contacts", 2, "text", "CONFIDENTIAL: контакти партнерів.\n"),
        (
            "dave",
            "u-readme",
            1,
            "file",
            readme_file.read_text(encoding="utf-8"),
        ),
        ("dave", "u-faq", 1, "text", "UNCLASSIFIED: часті запитання.\n"),
    ]
    for owner, name, level, kind, content in objects:
        transcript.call(
            sessions[owner],
            "create",
            expect_ok=True,
            name=name,
            level=level,
            kind=kind,
            content=content,
        )


def _run_scenario(sessions: Dict[str, AuthSession], transcript: Transcript) -> None:
    alice = sessions["alice"]
    bob = sessions["bob"]
    carol = sessions["carol"]
    dave = sessions["dave"]

    transcript.section("3. ЧИТАННЯ ВЛАСНИХ ОБ'ЄКТІВ (мандатні правила)")
    transcript.call(alice, "list", expect_ok=True)
    transcript.call(alice, "read", expect_ok=True, name="ts-plan")
    transcript.call(
        alice,
        "write",
        expect_ok=True,
        name="ts-plan",
        content="TOP_SECRET: план захисту периметра (версія 2).\n",
    )
    transcript.call(bob, "read", expect_ok=True, name="s-report")
    transcript.call(carol, "read", expect_ok=True, name="c-budget")
    transcript.call(dave, "read", expect_ok=True, name="u-readme")

    transcript.section("4. ДИСКРЕЦІЙНА ВІДМОВА: НЕМАЄ ПРАВА В ACL")
    transcript.call(alice, "read", expect_ok=False, name="s-report")
    transcript.call(dave, "read", expect_ok=False, name="c-budget")
    transcript.call(carol, "delete", expect_ok=False, name="ts-plan")

    transcript.section("5. ПРИЗНАЧЕННЯ ПРАВ І МАНДАТНІ ОБМЕЖЕННЯ")
    transcript.call(
        bob, "grant", expect_ok=True, name="s-report", target="carol", rights="read"
    )
    # ACL read є, але допуск carol (CONFIDENTIAL) нижчий за SECRET.
    transcript.call(carol, "read", expect_ok=False, name="s-report")
    transcript.call(
        bob, "grant", expect_ok=True, name="s-report", target="carol", rights="append"
    )
    # Дописування вгору (CONFIDENTIAL -> SECRET) моделлю дозволене.
    transcript.call(
        carol,
        "append",
        expect_ok=True,
        name="s-report",
        content="CONFIDENTIAL: додано коментар Кароліни.\n",
    )
    transcript.call(
        bob, "grant", expect_ok=True, name="s-report", target="alice", rights="append"
    )
    # Дописування вниз (TOP_SECRET -> SECRET) заборонене.
    transcript.call(
        alice,
        "append",
        expect_ok=False,
        name="s-report",
        content="TOP_SECRET: дописування вниз.\n",
    )
    transcript.call(
        bob, "grant", expect_ok=True, name="s-report", target="alice", rights="read"
    )
    transcript.call(alice, "read", expect_ok=True, name="s-report")

    transcript.section("6. ЧИТАННЯ ВНИЗ І ПРИЗНАЧЕННЯ ПРАВ НИЖЧОМУ РІВНЮ")
    transcript.call(
        dave, "grant", expect_ok=True, name="u-readme", target="alice", rights="read"
    )
    transcript.call(alice, "read", expect_ok=True, name="u-readme")

    transcript.section("7. СТВОРЕННЯ ВГОРУ ТА ЗАБОРОНА СТВОРЕННЯ ВНИЗ")
    transcript.call(
        carol,
        "create",
        expect_ok=False,
        name="c-low",
        level=1,
        kind="text",
        content="спроба запису вниз",
    )
    transcript.call(
        carol,
        "create",
        expect_ok=True,
        name="c-archive",
        level=3,
        kind="text",
        content="CONFIDENTIAL: архів, класифікований як SECRET.\n",
    )
    transcript.call(carol, "read", expect_ok=False, name="c-archive")
    transcript.call(
        carol, "grant", expect_ok=True, name="c-archive", target="bob", rights="read"
    )
    transcript.call(bob, "read", expect_ok=True, name="c-archive")

    transcript.section("8. РІВНІ ПРИ ЗАМІНІ ВМІСТУ (write)")
    transcript.call(
        bob, "grant", expect_ok=True, name="s-report", target="alice", rights="write"
    )
    transcript.call(
        alice,
        "write",
        expect_ok=False,
        name="s-report",
        content="спроба замінити SECRET з допуском TOP_SECRET",
    )
    transcript.call(dave, "write", expect_ok=True, name="u-faq", content="UNCLASSIFIED: оновлений FAQ.\n")

    transcript.section("9. ПРАВО DELETE І ВІДБИРАННЯ ПРАВ")
    transcript.call(
        bob, "grant", expect_ok=True, name="s-tasks", target="carol", rights="delete"
    )
    transcript.call(carol, "delete", expect_ok=True, name="s-tasks")
    transcript.call(
        bob, "revoke", expect_ok=True, name="s-report", target="carol", rights="read"
    )
    transcript.call(carol, "read", expect_ok=False, name="s-report")

    transcript.section("10. ІНВЕНТАРИЗАЦІЯ ТА ЖУРНАЛ (АДМІНІСТРАТОР)")
    inventory = transcript.call(alice, "inventory", expect_ok=True)
    names = ", ".join(item["name"] for item in inventory["objects"])
    transcript.line(f"  Об'єкти на сервері ({inventory['count']}): {names}")
    transcript.call(alice, "audit", expect_ok=True, limit=200)


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
    try:
        transcript.section("ЛАБОРАТОРНА 9. МОДЕЛЬ БЕЛЛА-ЛАПАДУЛА БЕЗ КАТЕГОРІЙ")
        transcript.line(
            "Час запуску: "
            + datetime.datetime.now().isoformat(timespec="seconds")
        )
        transcript.line(f"Проєкт: {PROJECT_ROOT}")
        transcript.line(f"Протокол: {LOG_PATH}")

        db = Database(str(DEMO_DIR / "auth.db"))
        db.initialize()
        server = AuthServer(db, host=HOST, port=0, timeout=15.0)
        server.start()
        thread = threading.Thread(
            target=server.serve_forever, name="lab9-demo-server", daemon=True
        )
        thread.start()
        transcript.line(f"Сервер: {HOST}:{server.port} (loopback)")
        transcript.line(f"База даних: {db.path}")

        sessions = _register_users(db, transcript, server.port)
        _create_objects(sessions, transcript)
        _run_scenario(sessions, transcript)

        transcript.section("ПІДСУМОК")
        transcript.line("Усі кроки виконано; очікувані дозволи й відмови збіглися.")
        transcript.line("Модель: Белла-ЛаПадула без категорій.")
        transcript.line(
            "Права: owner (власник), read, append, write, delete — 5 прав."
        )
        transcript.line("Рівні: 1 UNCLASSIFIED < 2 CONFIDENTIAL < 3 SECRET < 4 TOP_SECRET.")
        transcript.line(f"Повний протокол: {LOG_PATH}")
        return 0
    finally:
        for session in sessions.values():
            session.close()
        if server is not None:
            server.stop()
        transcript.close()


if __name__ == "__main__":
    raise SystemExit(main())
