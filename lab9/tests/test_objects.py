"""Інтеграційні тести серверних об'єктів і політики BLP через loopback."""

from __future__ import annotations

import contextlib
import io
import logging
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Dict

from client.client import (
    AuthSession,
    ClientError,
    main as client_main,
    open_session,
    register,
)
from server.db import Database
from server.server import AuthServer

logging.getLogger("usb-auth.server").setLevel(logging.CRITICAL)

HOST = "127.0.0.1"


class ObjectAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="lab9-objects-")
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
            target=self.server.serve_forever, name="lab9-test-server", daemon=True
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
            HOST,
            self.port,
            str(self.tokens[user_id]),
            allow_fixed=True,
        )

    def _create(
        self,
        session: AuthSession,
        name: str,
        level: int,
        content: str = "",
        kind: str = "text",
    ) -> dict:
        reply = session.request(
            "create", name=name, level=level, content=content, kind=kind
        )
        self.assertTrue(reply.get("ok"), reply)
        return reply

    def _reply(
        self, session: AuthSession, action: str, **fields: object
    ) -> dict:
        return session.request(action, **fields)

    # --- тести ---------------------------------------------------------------

    def test_owner_has_all_rights_and_acl_is_enforced(self) -> None:
        carol = self._session("carol")
        bob = self._session("bob")
        dave = self._session("dave")
        try:
            self._create(carol, "c-doc", 2, "version-1")

            self.assertTrue(self._reply(carol, "read", name="c-doc")["ok"])
            self.assertTrue(
                self._reply(carol, "write", name="c-doc", content="version-2")[
                    "ok"
                ]
            )
            self.assertTrue(
                self._reply(carol, "append", name="c-doc", content="\nmore")["ok"]
            )

            # Без запису ACL навіть користувач вищого рівня не має доступу.
            denied = self._reply(bob, "read", name="c-doc")
            self.assertFalse(denied["ok"])
            self.assertIn("дискреційна", denied["reason"])

            self.assertTrue(
                self._reply(
                    carol, "grant", name="c-doc", target="bob", rights="read"
                )["ok"]
            )
            self.assertTrue(self._reply(bob, "read", name="c-doc")["ok"])

            # bob має допуск вище за об'єкт: дописування вниз заборонене.
            self.assertTrue(
                self._reply(
                    carol, "grant", name="c-doc", target="bob", rights="append"
                )["ok"]
            )
            append_denied = self._reply(bob, "append", name="c-doc", content="x")
            self.assertFalse(append_denied["ok"])
            self.assertIn("no-write-down", append_denied["reason"])

            # dave має нижчий допуск: дописування вгору дозволене.
            self.assertTrue(
                self._reply(
                    carol, "grant", name="c-doc", target="dave", rights="append"
                )["ok"]
            )
            self.assertTrue(
                self._reply(dave, "append", name="c-doc", content="dave-line")[
                    "ok"
                ]
            )

            # Без права read dave не читає, навіть якщо має append.
            self.assertFalse(self._reply(dave, "read", name="c-doc")["ok"])

            self.assertTrue(
                self._reply(
                    carol, "revoke", name="c-doc", target="bob", rights="read"
                )["ok"]
            )
            self.assertFalse(self._reply(bob, "read", name="c-doc")["ok"])

            self.assertTrue(self._reply(carol, "delete", name="c-doc")["ok"])
            self.assertFalse(self._reply(carol, "read", name="c-doc")["ok"])
        finally:
            for session in (carol, bob, dave):
                session.close()

    def test_no_read_up_and_no_write_down(self) -> None:
        bob = self._session("bob")
        carol = self._session("carol")
        alice = self._session("alice")
        try:
            self._create(bob, "s-doc", 3, "secret")

            self.assertTrue(
                self._reply(
                    bob, "grant", name="s-doc", target="carol", rights="read"
                )["ok"]
            )
            read_up = self._reply(carol, "read", name="s-doc")
            self.assertFalse(read_up["ok"])
            self.assertIn("no-read-up", read_up["reason"])

            self.assertTrue(
                self._reply(
                    bob, "grant", name="s-doc", target="carol", rights="append"
                )["ok"]
            )
            self.assertTrue(
                self._reply(carol, "append", name="s-doc", content="\nlow")["ok"]
            )

            self.assertTrue(
                self._reply(
                    bob, "grant", name="s-doc", target="alice", rights="append"
                )["ok"]
            )
            write_down = self._reply(alice, "append", name="s-doc", content="\ntop")
            self.assertFalse(write_down["ok"])
            self.assertIn("no-write-down", write_down["reason"])

            self.assertTrue(
                self._reply(
                    bob, "grant", name="s-doc", target="alice", rights="read"
                )["ok"]
            )
            self.assertTrue(self._reply(alice, "read", name="s-doc")["ok"])
        finally:
            for session in (bob, carol, alice):
                session.close()

    def test_write_requires_equal_level(self) -> None:
        carol = self._session("carol")
        alice = self._session("alice")
        try:
            self._create(carol, "c-write", 2, "original")
            self.assertTrue(
                self._reply(
                    carol, "grant", name="c-write", target="alice", rights="write"
                )["ok"]
            )
            denied = self._reply(alice, "write", name="c-write", content="changed")
            self.assertFalse(denied["ok"])
            self.assertIn("no-write-down", denied["reason"])
            self.assertEqual(
                self._reply(carol, "read", name="c-write")["content"], "original"
            )
        finally:
            carol.close()
            alice.close()

    def test_create_cannot_write_down_but_can_write_up(self) -> None:
        carol = self._session("carol")
        bob = self._session("bob")
        try:
            down = self._reply(
                carol, "create", name="c-low", level=1, content="should fail"
            )
            self.assertFalse(down["ok"])
            self.assertIn("no-write-down", down["reason"])

            self._create(carol, "c-up", 3, "written up")
            denied = self._reply(carol, "read", name="c-up")
            self.assertFalse(denied["ok"])
            self.assertIn("no-read-up", denied["reason"])

            self.assertTrue(
                self._reply(
                    carol, "grant", name="c-up", target="bob", rights="read"
                )["ok"]
            )
            self.assertTrue(self._reply(bob, "read", name="c-up")["ok"])
        finally:
            carol.close()
            bob.close()

    def test_admin_inventory_audit_and_whoami(self) -> None:
        alice = self._session("alice")
        bob = self._session("bob")
        try:
            self._create(alice, "ts-doc", 4, "top secret")
            who = self._reply(alice, "whoami")
            self.assertTrue(who["ok"])
            self.assertEqual(who["role"], "admin")
            self.assertEqual(who["clearance"], "TOP_SECRET")

            inventory = self._reply(alice, "inventory")
            self.assertTrue(inventory["ok"])
            self.assertGreaterEqual(inventory["count"], 1)
            self.assertIn("ts-doc", [item["name"] for item in inventory["objects"]])

            denied = self._reply(bob, "inventory")
            self.assertFalse(denied["ok"])

            audit = self._reply(alice, "audit", limit=100)
            self.assertTrue(audit["ok"])
            actions = {(entry["action"], entry["object"]) for entry in audit["entries"]}
            self.assertIn(("create", "ts-doc"), actions)
            self.assertIn(("login", None), actions)

            self.assertFalse(self._reply(bob, "audit")["ok"])
        finally:
            alice.close()
            bob.close()

    def test_tokens_do_not_contain_server_secrets_in_output(self) -> None:
        bob = self._session("bob")
        try:
            self._create(bob, "s-file", 3, "line-1\nline-2\n", kind="file")
            info = self._reply(bob, "info", name="s-file")
            self.assertTrue(info["ok"])
            self.assertEqual(info["object"]["kind"], "file")
            self.assertEqual(info["object"]["size"], 14)
            self.assertNotIn("content", info["object"])
        finally:
            bob.close()

    def test_cli_object_flow(self) -> None:
        def run(*args: str) -> tuple[int, str]:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                status = client_main(list(args))
            return status, output.getvalue()

        bob_token = str(self.tokens["bob"])
        alice_token = str(self.tokens["alice"])

        status, output = run(
            "create",
            "--token",
            bob_token,
            "--allow-fixed",
            "--name",
            "cli-doc",
            "--level",
            "SECRET",
            "--text",
            "hello from CLI",
        )
        self.assertEqual(status, 0, output)
        self.assertIn("Створено cli-doc", output)

        status, output = run(
            "grant",
            "--token",
            bob_token,
            "--allow-fixed",
            "--name",
            "cli-doc",
            "--id",
            "alice",
            "--rights",
            "read,append",
        )
        self.assertEqual(status, 0, output)

        status, output = run(
            "read", "--token", alice_token, "--allow-fixed", "--name", "cli-doc"
        )
        self.assertEqual(status, 0, output)
        self.assertIn("hello from CLI", output)

        status, output = run(
            "ls", "--token", alice_token, "--allow-fixed"
        )
        self.assertEqual(status, 0, output)
        self.assertIn("cli-doc", output)

        status, output = run(
            "inventory", "--token", alice_token, "--allow-fixed"
        )
        self.assertEqual(status, 0, output)
        self.assertIn("Усього об'єктів", output)

        status, output = run("audit", "--token", alice_token, "--allow-fixed")
        self.assertEqual(status, 0, output)
        self.assertIn("cli-doc", output)

        status, output = run("inventory", "--token", bob_token, "--allow-fixed")
        self.assertEqual(status, 1, output)
        self.assertIn("[DENY]", output)

    def test_unknown_object_and_bad_action(self) -> None:
        bob = self._session("bob")
        try:
            missing = self._reply(bob, "read", name="no-such-object")
            self.assertFalse(missing["ok"])
            self.assertEqual(missing["code"], "not-found")

            bad = self._reply(bob, "explode", name="x")
            self.assertFalse(bad["ok"])
            self.assertEqual(bad["code"], "bad-action")
        finally:
            bob.close()

    def test_acl_revoke_all(self) -> None:
        bob = self._session("bob")
        carol = self._session("carol")
        try:
            self._create(bob, "s-acl", 3, "data")
            self.assertTrue(
                self._reply(
                    bob, "grant", name="s-acl", target="carol", rights="read,append"
                )["ok"]
            )
            self.assertEqual(len(self._reply(bob, "info", name="s-acl")["object"]["acl"]), 1)
            self.assertTrue(
                self._reply(bob, "revoke", name="s-acl", target="carol")["ok"]
            )
            self.assertEqual(self._reply(bob, "info", name="s-acl")["object"]["acl"], [])
            self.assertFalse(self._reply(carol, "read", name="s-acl")["ok"])
        finally:
            bob.close()
            carol.close()


if __name__ == "__main__":
    unittest.main()
