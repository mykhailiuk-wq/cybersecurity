"""Інтеграційні тести: сервер + клієнт через loopback (127.0.0.1)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import logging
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Optional, Tuple

from client.client import ClientError, authenticate, main as client_main, register
from client.token_file import load_token
from common.crypto import compute_response
from common.protocol import JsonChannel
from server.db import Database
from server.server import AuthServer

# Під час тестів журнал сервера не потрібен у виводі.
logging.getLogger("usb-auth.server").setLevel(logging.CRITICAL)


class IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="usb-auth-test-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.db = Database(str(self.root / "auth.db"))
        self.db.initialize()

        self.server = AuthServer(
            self.db,
            host="127.0.0.1",
            port=0,
            timeout=5.0,
            failure_limit=5,
            lockout=2.0,
        )
        self.server.start()
        self.thread = threading.Thread(
            target=self.server.serve_forever, name="test-auth-server", daemon=True
        )
        self.thread.start()

        self.host = "127.0.0.1"
        self.port = self.server.port
        self.token_dir = self.root / "token"
        self.token_dir.mkdir()

    def tearDown(self) -> None:
        self.server.stop()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive(), "сервер не зупинився")

    # --- допоміжні методи ---------------------------------------------------

    def _register(
        self,
        user_id: str = "alice",
        algorithm: str = "SHA256",
        code: Optional[str] = None,
        token_dir: Optional[Path] = None,
    ) -> Path:
        if code is None:
            code = self.db.issue_enroll_code(600)
        return register(
            self.host,
            self.port,
            str(token_dir or self.token_dir),
            user_id,
            algorithm,
            code,
            allow_fixed=True,
        )

    def _begin_handshake(self, user_id: str, serial: Optional[str]) -> Tuple[
        socket.socket, JsonChannel, dict
    ]:
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(5)
        channel = JsonChannel(sock)
        channel.send(
            {
                "type": "hello",
                "proto": 1,
                "id": user_id,
                "media_serial": serial,
                "client": "test",
            }
        )
        return sock, channel, channel.recv()

    def _manual_auth(
        self,
        user_id: str,
        secret: bytes,
        algorithm: str,
        serial: Optional[str],
    ) -> dict:
        sock, channel, challenge = self._begin_handshake(user_id, serial)
        try:
            if challenge.get("type") != "challenge":
                # Наприклад, сервер заблокував обліковий запис.
                return challenge
            nonce = base64.b64decode(challenge["nonce"])
            mac = compute_response(algorithm, secret, nonce, user_id)
            channel.send(
                {
                    "type": "response",
                    "session": challenge["session"],
                    "mac": base64.b64encode(mac).decode("ascii"),
                }
            )
            return channel.recv()
        finally:
            channel.close()
            sock.close()

    # --- тести ---------------------------------------------------------------

    def test_registration_and_successful_login(self) -> None:
        path = self._register()
        self.assertTrue(path.exists())

        token = load_token(str(self.token_dir))
        self.assertEqual(token.user_id, "alice")
        self.assertEqual(token.algorithm, "SHA256")
        self.assertEqual(token.server, f"{self.host}:{self.port}")

        ok, message, algorithm = authenticate(
            self.host, self.port, str(self.token_dir), allow_fixed=True
        )
        self.assertTrue(ok, message)
        self.assertEqual(algorithm, "SHA256")

    def test_each_hash_algorithm_works(self) -> None:
        for index, algorithm in enumerate(("MD5", "SHA1", "SHA256", "SHA384", "SHA512")):
            with self.subTest(algorithm=algorithm):
                token_dir = self.root / f"token-{index}"
                token_dir.mkdir()
                self._register(
                    user_id=f"user{index}", algorithm=algorithm, token_dir=token_dir
                )
                ok, message, _ = authenticate(
                    self.host, self.port, str(token_dir), allow_fixed=True
                )
                self.assertTrue(ok, message)

    def test_wrong_secret_is_rejected(self) -> None:
        self._register()
        path = self.token_dir / "usb_auth_token.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["secret"] = base64.b64encode(b"z" * 32).decode("ascii")
        path.write_text(json.dumps(payload), encoding="utf-8")

        ok, message, _ = authenticate(
            self.host, self.port, str(self.token_dir), allow_fixed=True
        )
        self.assertFalse(ok)
        self.assertEqual(message, "authentication failed")

    def test_unknown_user_gets_same_generic_answer(self) -> None:
        self._register()
        path = self.token_dir / "usb_auth_token.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["user_id"] = "ghost"
        path.write_text(json.dumps(payload), encoding="utf-8")

        ok, message, _ = authenticate(
            self.host, self.port, str(self.token_dir), allow_fixed=True
        )
        self.assertFalse(ok)
        self.assertEqual(message, "authentication failed")

    def test_enroll_code_is_single_use(self) -> None:
        code = self.db.issue_enroll_code(600)
        self._register(user_id="eve", code=code)

        other_dir = self.root / "token2"
        other_dir.mkdir()
        with self.assertRaises(ClientError):
            self._register(user_id="frank", code=code, token_dir=other_dir)

    def test_unknown_enroll_code_is_rejected(self) -> None:
        with self.assertRaises(ClientError):
            self._register(code="DEAD-BEEF-DEAD-BEEF")

    def test_disabled_account_is_rejected(self) -> None:
        self._register(user_id="dave")
        self.assertTrue(self.db.set_enabled("dave", False))
        ok, _, _ = authenticate(
            self.host, self.port, str(self.token_dir), allow_fixed=True
        )
        self.assertFalse(ok)

    def test_response_cannot_be_replayed(self) -> None:
        token_path = self._register()
        token = load_token(str(token_path.parent))

        sock, channel, challenge = self._begin_handshake(token.user_id, None)
        try:
            nonce = base64.b64decode(challenge["nonce"])
            mac = compute_response(token.algorithm, token.secret, nonce, token.user_id)
            stolen = {
                "type": "response",
                "session": challenge["session"],
                "mac": base64.b64encode(mac).decode("ascii"),
            }
            channel.send(stolen)
            first = channel.recv()
            self.assertTrue(first.get("ok"))
        finally:
            channel.close()
            sock.close()

        sock2, channel2, challenge2 = self._begin_handshake(token.user_id, None)
        try:
            self.assertNotEqual(challenge2["nonce"], challenge["nonce"])
            channel2.send(stolen)
            second = channel2.recv()
            self.assertFalse(second.get("ok", False))
            self.assertEqual(second.get("type"), "error")
        finally:
            channel2.close()
            sock2.close()

    def test_token_serial_is_bound_to_account(self) -> None:
        code = self.db.issue_enroll_code(600)
        secret = b"s" * 32
        self.assertEqual(
            self.db.enroll_user(code, "bob", "SHA1", secret, "AAAA1111"), "ok"
        )

        wrong = self._manual_auth("bob", secret, "SHA1", "BBBB2222")
        self.assertFalse(wrong.get("ok"))

        correct = self._manual_auth("bob", secret, "SHA1", "aaaa1111")
        self.assertTrue(correct.get("ok"))

    def test_lockout_after_repeated_failures(self) -> None:
        code = self.db.issue_enroll_code(600)
        secret = b"k" * 32
        self.assertEqual(
            self.db.enroll_user(code, "carol", "SHA256", secret, None), "ok"
        )

        for _ in range(5):
            failed = self._manual_auth("carol", b"x" * 32, "SHA256", None)
            self.assertFalse(failed.get("ok"))

        blocked = self._manual_auth("carol", secret, "SHA256", None)
        self.assertFalse(blocked.get("ok"))
        self.assertIn("too many failed attempts", blocked.get("message", ""))

        time.sleep(2.1)
        after = self._manual_auth("carol", secret, "SHA256", None)
        self.assertTrue(after.get("ok"))

    def test_cli_register_and_login(self) -> None:
        code = self.db.issue_enroll_code(600)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = client_main(
                [
                    "register",
                    "--server",
                    f"{self.host}:{self.port}",
                    "--token",
                    str(self.token_dir),
                    "--id",
                    "cliuser",
                    "--code",
                    code,
                    "--allow-fixed",
                ]
            )
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("Токен зареєстровано", output.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = client_main(
                ["login", "--token", str(self.token_dir), "--allow-fixed"]
            )
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("Аутентифікацію пройдено", output.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = client_main(["info", "--token", str(self.token_dir)])
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("SHA256", output.getvalue())
        self.assertNotIn("secret", output.getvalue().lower().replace("секрет", ""))


if __name__ == "__main__":
    unittest.main()
