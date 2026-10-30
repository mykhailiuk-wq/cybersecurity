"""Сервер аутентифікації методом «рукостискання» (варіант 10).

Сервер зберігає в системній базі даних ідентифікатор користувача та
узгоджену процедуру перетворення (хеш-алгоритм CryptoAPI).  Під час
аутентифікації сервер генерує випадкове число, передає його клієнту,
самостійно обчислює очікувану відповідь і порівнює її з отриманою.

Запуск (з кореня проєкту)::

    python -m server.server run --host 127.0.0.1 --port 5555

Керування::

    python -m server.server enroll-code --ttl 900
    python -m server.server users
    python -m server.server disable --id student10
    python -m server.server enable  --id student10
    python -m server.server remove  --id student10
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import logging
import os
import socket
import socketserver
import sys
import threading
import time
from typing import Dict, List, Optional

# Дозволяє запускати файл напряму: python server/server.py ...
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import DEFAULT_ALGORITHM, compute_response, normalize_algorithm, random_bytes
from common.protocol import (
    PROTO_VERSION,
    ConnectionClosed,
    JsonChannel,
    ProtocolError,
    error_message,
    get_str,
    require_proto,
    result_message,
    validate_user_id,
)
from common.util import configure_stdio
from server.db import (
    ENROLL_BAD_CODE,
    ENROLL_CODE_EXPIRED,
    ENROLL_CODE_USED,
    ENROLL_OK,
    ENROLL_USER_EXISTS,
    Database,
)

LOG = logging.getLogger("usb-auth.server")

DEFAULT_DB = os.path.join("data", "auth.db")

ENROLL_ERRORS: Dict[str, str] = {
    ENROLL_BAD_CODE: "код реєстрації невідомий",
    ENROLL_CODE_USED: "код реєстрації вже використано",
    ENROLL_CODE_EXPIRED: "термін дії коду реєстрації минув",
    ENROLL_USER_EXISTS: "користувач з таким ідентифікатором уже зареєстрований",
}


class FailureTracker:
    """Облік невдалих спроб і тимчасове блокування облікового запису."""

    def __init__(
        self,
        limit: int = 5,
        window: float = 600.0,
        lockout: float = 300.0,
    ) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1.0, float(window))
        self.lockout = max(1.0, float(lockout))
        self._lock = threading.Lock()
        self._failures: Dict[str, List[float]] = {}
        self._locked_until: Dict[str, float] = {}

    def _prune(self, user_id: str, now: float) -> List[float]:
        events = self._failures.get(user_id)
        if not events:
            return []
        fresh = [moment for moment in events if now - moment < self.window]
        if fresh:
            self._failures[user_id] = fresh
        else:
            self._failures.pop(user_id, None)
        return fresh

    def locked_for(self, user_id: str) -> float:
        """Скільки секунд залишилось до розблокування (0 — не заблоковано)."""
        now = time.monotonic()
        with self._lock:
            until = self._locked_until.get(user_id)
            if until is None:
                return 0.0
            if until <= now:
                self._locked_until.pop(user_id, None)
                self._failures.pop(user_id, None)
                return 0.0
            return until - now

    def record_failure(self, user_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._prune(user_id, now)
            events.append(now)
            self._failures[user_id] = events
            if len(events) >= self.limit:
                self._locked_until[user_id] = now + self.lockout
                self._failures.pop(user_id, None)

    def reset(self, user_id: str) -> None:
        with self._lock:
            self._failures.pop(user_id, None)
            self._locked_until.pop(user_id, None)


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16


class _AuthHandler(socketserver.BaseRequestHandler):
    """Один TCP-сеанс: або аутентифікація (hello), або реєстрація (enroll)."""

    def handle(self) -> None:
        app: "AuthServer" = self.server.app  # type: ignore[attr-defined]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        try:
            self.request.settimeout(app.timeout)
        except OSError:
            return

        channel = JsonChannel(self.request)
        try:
            message = channel.recv()
            kind = message.get("type")
            if kind == "hello":
                self._authenticate(app, channel, message, peer)
            elif kind == "enroll":
                self._enroll(app, channel, message, peer)
            else:
                channel.send(
                    error_message("bad_request", "очікується запит 'hello' або 'enroll'")
                )
        except ConnectionClosed as exc:
            LOG.info("connection closed by %s: %s", peer, exc)
        except socket.timeout:
            LOG.warning("timeout waiting for data from %s", peer)
        except ProtocolError as exc:
            LOG.warning("protocol error from %s: %s", peer, exc)
            self._safe_send(channel, error_message("protocol_error", str(exc)))
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            LOG.info("connection reset by %s", peer)
        except OSError as exc:
            LOG.warning("socket error with %s: %s", peer, exc)
        except Exception:  # noqa: BLE001 - сервер не повинен падати через один сеанс
            LOG.exception("unexpected error while serving %s", peer)
            self._safe_send(channel, error_message("internal_error", "internal server error"))
        finally:
            channel.close()

    @staticmethod
    def _safe_send(channel: JsonChannel, message: Dict[str, object]) -> None:
        try:
            channel.send(message)
        except (OSError, ProtocolError):
            pass

    # --- аутентифікація -----------------------------------------------------

    def _authenticate(
        self,
        app: "AuthServer",
        channel: JsonChannel,
        message: Dict[str, object],
        peer: str,
    ) -> None:
        require_proto(message)
        try:
            user_id = validate_user_id(get_str(message, "id", max_len=64))
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc

        media_serial = message.get("media_serial")
        if media_serial is not None and (
            not isinstance(media_serial, str) or len(media_serial) > 32
        ):
            raise ProtocolError("поле 'media_serial' має бути рядком до 32 символів")

        blocked_for = app.failures.locked_for(user_id)
        if blocked_for > 0:
            LOG.warning(
                "AUTH BLOCKED user=%s peer=%s retry_after=%.0fs",
                user_id,
                peer,
                blocked_for,
            )
            channel.send(
                result_message(
                    False,
                    "too many failed attempts, try again later",
                    retry_after=int(blocked_for) + 1,
                )
            )
            return

        record = app.db.get_user(user_id)
        if record is not None:
            algorithm = str(record["algorithm"])
            secret = bytes(record["secret"])
            enabled = bool(record["enabled"])
            stored_serial: Optional[str] = record["media_serial"]
        else:
            # Для невідомого користувача виконуємо ті самі дії з випадковим
            # секретом, щоб час відповіді не викривав наявність облікового запису.
            algorithm = DEFAULT_ALGORITHM
            secret = random_bytes(32)
            enabled = False
            stored_serial = None

        nonce = random_bytes(app.challenge_size)
        session = random_bytes(8).hex()
        channel.send(
            {
                "type": "challenge",
                "proto": PROTO_VERSION,
                "session": session,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "expires_in": int(app.timeout),
            }
        )

        response = channel.recv()
        if response.get("type") != "response":
            raise ProtocolError("очікується повідомлення 'response'")
        if response.get("session") != session:
            raise ProtocolError("ідентифікатор сеансу не збігається")

        mac_b64 = get_str(response, "mac", max_len=256)
        try:
            received_mac = base64.b64decode(mac_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProtocolError("поле 'mac' не є коректним base64") from exc

        try:
            expected_mac = compute_response(algorithm, secret, nonce, user_id)
        except ValueError:
            LOG.error("invalid hash algorithm %r stored for user=%s", algorithm, user_id)
            expected_mac = None
        mac_ok = expected_mac is not None and hmac.compare_digest(
            received_mac, expected_mac
        )

        serial_ok = True
        if stored_serial and media_serial is not None:
            serial_ok = stored_serial.upper() == media_serial.upper()

        ok = record is not None and enabled and mac_ok and serial_ok
        if ok:
            app.failures.reset(user_id)
            LOG.info("AUTH OK user=%s peer=%s algorithm=%s", user_id, peer, algorithm)
            channel.send(
                result_message(
                    True,
                    "authentication successful",
                    user=user_id,
                    algorithm=algorithm,
                    session=session,
                )
            )
            return

        app.failures.record_failure(user_id)
        reasons = []
        if record is None:
            reasons.append("unknown-user")
        elif not enabled:
            reasons.append("disabled")
        if not mac_ok:
            reasons.append("bad-response")
        if not serial_ok:
            reasons.append("token-serial-mismatch")
        LOG.warning(
            "AUTH FAIL user=%s peer=%s reason=%s",
            user_id,
            peer,
            ",".join(reasons) or "unknown",
        )
        channel.send(result_message(False, "authentication failed", session=session))

    # --- реєстрація ---------------------------------------------------------

    def _enroll(
        self,
        app: "AuthServer",
        channel: JsonChannel,
        message: Dict[str, object],
        peer: str,
    ) -> None:
        require_proto(message)
        try:
            code = get_str(message, "code", max_len=64)
            user_id = validate_user_id(get_str(message, "id", max_len=64))
            algorithm = normalize_algorithm(get_str(message, "algorithm", max_len=32))
            secret = base64.b64decode(
                get_str(message, "secret", max_len=256), validate=True
            )
        except (ValueError, binascii.Error) as exc:
            raise ProtocolError(str(exc)) from exc

        if not 16 <= len(secret) <= 64:
            raise ProtocolError("секрет токена має містити від 16 до 64 байтів")

        media_serial = message.get("media_serial")
        if media_serial is not None and (
            not isinstance(media_serial, str) or len(media_serial) > 32
        ):
            raise ProtocolError("поле 'media_serial' має бути рядком до 32 символів")

        try:
            status = app.db.enroll_user(code, user_id, algorithm, secret, media_serial)
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc

        if status != ENROLL_OK:
            LOG.warning(
                "ENROLL FAIL id=%s code=...%s status=%s peer=%s",
                user_id,
                code[-4:] if isinstance(code, str) else "????",
                status,
                peer,
            )
            channel.send(
                error_message(status, ENROLL_ERRORS.get(status, "реєстрацію відхилено"))
            )
            return

        LOG.info("ENROLL OK user=%s peer=%s algorithm=%s", user_id, peer, algorithm)
        channel.send(
            {
                "type": "enrolled",
                "proto": PROTO_VERSION,
                "user": user_id,
                "algorithm": algorithm,
                "message": "enrollment successful",
            }
        )


class AuthServer:
    """TCP-сервер аутентифікації."""

    def __init__(
        self,
        db: Database,
        host: str = "127.0.0.1",
        port: int = 5555,
        *,
        challenge_size: int = 32,
        timeout: float = 15.0,
        failure_limit: int = 5,
        failure_window: float = 600.0,
        lockout: float = 300.0,
    ) -> None:
        self.db = db
        self.host = host
        self.port = int(port)
        self.challenge_size = max(16, int(challenge_size))
        self.timeout = max(1.0, float(timeout))
        self.failures = FailureTracker(failure_limit, failure_window, lockout)
        self._httpd: Optional[_ThreadedTCPServer] = None

    def start(self) -> _ThreadedTCPServer:
        """Створює слухаючий сокет; після цього self.port містить реальний порт."""
        if self._httpd is not None:
            return self._httpd
        httpd = _ThreadedTCPServer((self.host, self.port), _AuthHandler)
        httpd.app = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self.port = int(httpd.server_address[1])
        return httpd

    def serve_forever(self) -> None:
        httpd = self.start()
        LOG.info("authentication server listening on %s:%s", self.host, self.port)
        httpd.serve_forever(poll_interval=0.25)

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()


# --- командний рядок ------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m server.server",
        description="Сервер USB-аутентифікації (варіант 10, «рукостискання»)",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"шлях до бази даних SQLite (за замовчуванням: {DEFAULT_DB})",
    )
    parser.add_argument("--debug", action="store_true", help="докладне журналювання")

    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="запустити сервер")
    run.add_argument("--host", default="127.0.0.1", help="адреса прослуховування")
    run.add_argument("--port", type=int, default=5555, help="TCP-порт")
    run.add_argument(
        "--challenge-bytes",
        type=int,
        default=32,
        help="розмір випадкового числа (байтів)",
    )
    run.add_argument("--timeout", type=float, default=15.0, help="тайм-аут сеансу, с")
    run.add_argument(
        "--failure-limit",
        type=int,
        default=5,
        help="кількість невдалих спроб до блокування",
    )
    run.add_argument(
        "--lockout", type=float, default=300.0, help="тривалість блокування, с"
    )

    enroll = sub.add_parser("enroll-code", help="видати одноразовий код реєстрації")
    enroll.add_argument("--ttl", type=int, default=900, help="термін дії, с")
    enroll.add_argument("--note", help="примітка (наприклад, ПІБ студента)")

    sub.add_parser("users", help="показати зареєстрованих користувачів")

    for name, text in (
        ("enable", "увімкнути обліковий запис"),
        ("disable", "вимкнути обліковий запис"),
        ("remove", "видалити обліковий запис"),
    ):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("--id", required=True, dest="user_id")

    return parser


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_users(rows: List[object]) -> None:
    if not rows:
        print("Користувачів не зареєстровано.")
        return
    print(f"{'ID':<20} {'ALGORITHM':<10} {'SERIAL':<10} {'ENABLED':<8} CREATED")
    print("-" * 72)
    for row in rows:
        print(
            f"{row['user_id']:<20} {row['algorithm']:<10} "
            f"{(row['media_serial'] or '-'):<10} "
            f"{'yes' if row['enabled'] else 'no':<8} {row['created_at']}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    configure_stdio()
    args = _build_parser().parse_args(argv)
    _setup_logging(args.debug)

    db = Database(args.db)
    db.initialize()

    if args.command == "run":
        server = AuthServer(
            db,
            host=args.host,
            port=args.port,
            challenge_size=args.challenge_bytes,
            timeout=args.timeout,
            failure_limit=args.failure_limit,
            lockout=args.lockout,
        )
        server.start()
        print(f"[*] Сервер аутентифікації: {args.host}:{server.port}")
        print(f"[*] База даних: {db.path}")
        print("[*] Для зупинки натисніть Ctrl+C")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Зупинка сервера...")
        finally:
            server.stop()
        return 0

    if args.command == "enroll-code":
        code = db.issue_enroll_code(ttl_seconds=args.ttl, note=args.note)
        print(f"Одноразовий код реєстрації: {code}")
        print(f"Дійсний протягом {args.ttl} с. Передайте його користувачу.")
        return 0

    if args.command == "users":
        _print_users(db.list_users())
        return 0

    if args.command in ("enable", "disable"):
        enabled = args.command == "enable"
        if db.set_enabled(args.user_id, enabled):
            print(f"[OK] Обліковий запис {args.user_id}: {'увімкнено' if enabled else 'вимкнено'}")
            return 0
        print(f"[!] Користувача {args.user_id} не знайдено", file=sys.stderr)
        return 1

    if args.command == "remove":
        if db.delete_user(args.user_id):
            print(f"[OK] Обліковий запис {args.user_id} видалено")
            return 0
        print(f"[!] Користувача {args.user_id} не знайдено", file=sys.stderr)
        return 1

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
