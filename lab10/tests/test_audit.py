"""Тести механізму реєстрації подій (лабораторна 10)."""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Dict, Optional

from client.client import (
    AuthSession,
    AuthenticationFailed,
    ClientError,
    open_session,
    register,
)
from server.db import Database
from server.server import AuthServer

logging.getLogger("usb-auth.server").setLevel(logging.CRITICAL)

HOST = "127.0.0.1"


class AuditEventsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="lab10-audit-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.db = Database(str(self.root / "auth.db"))
        self.db.initialize()

        self.server = AuthServer(
            self.db, host=HOST, port=0, timeout=5.0, lockout=2.0
        )
        self.server.start()
        self.port = self.server.port
        self.thread = threading.Thread(
            target=self.server.serve_forever, name="lab10-audit-server", daemon=True
        )
        self.thread.start()

        self.tokens: Dict[str, Path] = {}
        for user, level, admin in (
            ("alice", 4, True),
            ("bob", 3, False),
            ("carol", 2, False),
            ("dave", 1, False),
        ):
            self._register_user(user, level, admin)

    def tearDown(self) -> None:
        self.server.stop()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive(), "сервер не зупинився")

    # --- допоміжні методи ---------------------------------------------------

    def _register_user(self, user_id: str, level: int, admin: bool) -> None:
        code = self.db.issue_enroll_code(600, level=level, admin=admin)
        directory = self.root / f"token-{user_id}"
        directory.mkdir()
        register(
            HOST,
            self.port,
            str(directory),
            user_id,
            "SHA256",
            code,
            allow_fixed=True,
        )
        self.tokens[user_id] = directory

    def _session(self, user_id: str) -> AuthSession:
        return open_session(
            HOST, self.port, str(self.tokens[user_id]), allow_fixed=True
        )

    def _create(
        self, session: AuthSession, name: str, level: int, content: str = ""
    ) -> dict:
        reply = session.request(
            "create", name=name, level=level, content=content, kind="text"
        )
        self.assertTrue(reply.get("ok"), reply)
        return reply

    def _forge(
        self,
        user_id: str,
        *,
        secret: Optional[bytes] = None,
        new_user: Optional[str] = None,
    ) -> Path:
        directory = self.root / f"forged-{user_id}-{new_user or 'same'}"
        directory.mkdir()
        payload = json.loads(
            (self.tokens[user_id] / "usb_auth_token.json").read_text(encoding="utf-8")
        )
        if secret is not None:
            payload["secret"] = base64.b64encode(secret).decode("ascii")
        if new_user is not None:
            payload["user_id"] = new_user
        (directory / "usb_auth_token.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return directory

    def _events(self, **filters: object) -> list[sqlite3.Row]:
        return self.db.list_audit(200, ascending=True, **filters)

    # --- автентифікація -----------------------------------------------------

    def test_successful_login_is_logged_with_peer_and_session(self) -> None:
        session = self._session("alice")
        session_id = session.session_id
        session.close()

        events = self._events(event="AUTH-SUCCESS", user_id="alice")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertTrue(event["allowed"])
        self.assertEqual(event["action"], "login")
        self.assertEqual(event["severity"], "INFO")
        self.assertEqual(event["session_id"], session_id)
        self.assertIn("127.0.0.1:", event["peer"])
        self.assertIn("level=TOP_SECRET", event["details"])

    def test_failed_authentication_variants_are_logged(self) -> None:
        # Хибний секрет.
        with self.assertRaises(AuthenticationFailed):
            open_session(
                HOST,
                self.port,
                str(self._forge("alice", secret=b"x" * 32)),
                allow_fixed=True,
            )
        # Невідомий користувач.
        with self.assertRaises(AuthenticationFailed):
            open_session(
                HOST,
                self.port,
                str(self._forge("bob", new_user="mallory")),
                allow_fixed=True,
            )
        # Вимкнений обліковий запис.
        self.assertTrue(self.db.set_enabled("dave", False))
        with self.assertRaises(AuthenticationFailed):
            open_session(
                HOST, self.port, str(self.tokens["dave"]), allow_fixed=True
            )

        failures = self._events(event="AUTH-FAILURE")
        reasons = {event["reason"] for event in failures}
        self.assertIn("bad-response", reasons)
        self.assertIn("unknown-user,bad-response", reasons)
        self.assertIn("disabled", reasons)
        for event in failures:
            self.assertFalse(event["allowed"])
            self.assertEqual(event["severity"], "WARNING")
            self.assertTrue(event["peer"])
            self.assertTrue(event["session_id"])

    def test_failed_enrollment_is_logged(self) -> None:
        directory = self.root / "bad-enroll"
        directory.mkdir()
        with self.assertRaises(ClientError):
            register(
                HOST,
                self.port,
                str(directory),
                "eve",
                "SHA256",
                "DEAD-BEEF-DEAD-BEEF",
                allow_fixed=True,
            )

        events = self._events(event="ENROLL-FAILURE", user_id="eve")
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["allowed"])
        self.assertEqual(events[0]["reason"], "bad_code")
        self.assertIn(events[0]["severity"], ("WARNING", "ALERT"))

    # --- доступ до об'єктів -------------------------------------------------

    def test_allowed_and_denied_object_accesses_are_logged(self) -> None:
        bob = self._session("bob")
        alice = self._session("alice")
        carol = self._session("carol")
        try:
            self._create(bob, "s-doc", 3, "secret")
            self.assertTrue(bob.request("read", name="s-doc")["ok"])

            denied = alice.request("read", name="s-doc")
            self.assertFalse(denied["ok"])
            self.assertIn("дискреційна", denied["reason"])

            self.assertTrue(
                bob.request(
                    "grant", name="s-doc", target="alice", rights="read"
                )["ok"]
            )
            self.assertTrue(alice.request("read", name="s-doc")["ok"])

            self.assertTrue(
                bob.request(
                    "grant", name="s-doc", target="alice", rights="append"
                )["ok"]
            )
            write_down = alice.request("append", name="s-doc", content="top")
            self.assertFalse(write_down["ok"])
            self.assertIn("no-write-down", write_down["reason"])

            self.assertTrue(
                bob.request(
                    "grant", name="s-doc", target="carol", rights="read"
                )["ok"]
            )
            read_up = carol.request("read", name="s-doc")
            self.assertFalse(read_up["ok"])
            self.assertIn("no-read-up", read_up["reason"])

            self.assertTrue(bob.request("delete", name="s-doc")["ok"])
            not_found = carol.request("read", name="s-doc")
            self.assertFalse(not_found["ok"])
            self.assertEqual(not_found["code"], "not-found")
        finally:
            bob.close()
            alice.close()
            carol.close()

        read_allow = self._events(event="OBJECT-READ-ALLOW", object_name="s-doc")
        self.assertGreaterEqual(len(read_allow), 2)
        self.assertTrue(all(event["user_id"] == "bob" or event["user_id"] == "alice"
                            for event in read_allow))
        self.assertTrue(all(event["session_id"] for event in read_allow))
        self.assertTrue(all(event["peer"] for event in read_allow))

        read_deny = self._events(event="OBJECT-READ-DENY", object_name="s-doc")
        self.assertGreaterEqual(len(read_deny), 3)
        reasons = " ".join(event["reason"] for event in read_deny)
        self.assertIn("дискреційна", reasons)
        self.assertIn("no-read-up", reasons)
        self.assertIn("object-not-found", reasons)

        append_deny = self._events(event="OBJECT-APPEND-DENY", object_name="s-doc")
        self.assertEqual(len(append_deny), 1)
        self.assertIn("no-write-down", append_deny[0]["reason"])

        grant_allow = self._events(event="OBJECT-GRANT-ALLOW", object_name="s-doc")
        self.assertEqual(len(grant_allow), 3)
        self.assertTrue(all("target=" in event["details"] for event in grant_allow))

        delete_allow = self._events(event="OBJECT-DELETE-ALLOW", object_name="s-doc")
        self.assertEqual(len(delete_allow), 1)
        self.assertEqual(delete_allow[0]["user_id"], "bob")

    def test_audit_filters_last_id_and_order(self) -> None:
        bob = self._session("bob")
        try:
            first = self._create(bob, "s-one", 3, "one")
            self.assertTrue(first["ok"])
            before = self.db.last_audit_id()
            self._create(bob, "s-two", 3, "two")
            after = self.db.last_audit_id()
            self.assertGreater(after, before)

            only_new = self.db.list_audit(
                limit=50, after_id=before, ascending=True
            )
            self.assertEqual(len(only_new), 1)
            self.assertEqual(only_new[0]["object_name"], "s-two")

            by_user = self.db.list_audit(50, user_id="bob", action="create")
            self.assertEqual({event["object_name"] for event in by_user},
                             {"s-one", "s-two"})

            only_allow = self.db.list_audit(50, allowed=True, event="OBJECT-CREATE-ALLOW")
            self.assertEqual(len(only_allow), 2)

            only_deny = self.db.list_audit(50, allowed=False)
            self.assertTrue(only_deny is not None)
        finally:
            bob.close()

    def test_old_audit_table_is_migrated(self) -> None:
        path = self.root / "old.db"
        conn = sqlite3.connect(path)
        try:
            conn.executescript(
                """
                CREATE TABLE audit (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    at          TEXT NOT NULL,
                    user_id     TEXT,
                    action      TEXT NOT NULL,
                    object_name TEXT,
                    allowed     INTEGER NOT NULL,
                    reason      TEXT NOT NULL DEFAULT ''
                );
                """
            )
            conn.execute(
                "INSERT INTO audit(at, user_id, action, object_name, allowed, reason) "
                "VALUES ('2026-01-01T00:00:00+00:00', 'alice', 'login', NULL, 1, '')"
            )
            conn.execute(
                "INSERT INTO audit(at, user_id, action, object_name, allowed, reason) "
                "VALUES ('2026-01-01T00:00:01+00:00', 'bob', 'read', 'doc', 0, 'denied')"
            )
            conn.commit()
        finally:
            conn.close()

        old = Database(str(path))
        old.initialize()

        rows = old.list_audit(10, ascending=True)
        self.assertEqual([row["event"] for row in rows],
                         ["AUTH-SUCCESS", "OBJECT-READ-DENY"])
        self.assertEqual(rows[0]["severity"], "INFO")
        self.assertEqual(rows[1]["severity"], "WARNING")
        self.assertIn("peer", rows[0].keys())
        self.assertIn("session_id", rows[0].keys())
        self.assertIn("details", rows[0].keys())


if __name__ == "__main__":
    unittest.main()
