"""Сервер аутентифікації та доступу до об'єктів (лабораторна 9).

Сервер зберігає в системній базі даних ідентифікатор користувача,
узгоджену процедуру перетворення (хеш-алгоритм CryptoAPI), допуск і роль.
Під час аутентифікації сервер генерує випадкове число, передає його
клієнту, самостійно обчислює очікувану відповідь і порівнює її з
отриманою.  Після успішного рукостискання в тому самому TCP-з'єднанні
обслуговуються запити до серверних об'єктів даних згідно з моделлю
Белла-ЛаПадула без категорій та дискреційними ACL.

Запуск (з кореня проєкту)::

    python -m server.server run --host 127.0.0.1 --port 5555

Керування::

    python -m server.server enroll-code --ttl 900 --level SECRET
    python -m server.server users
    python -m server.server objects
    python -m server.server acl --object s-report
    python -m server.server audit --limit 50
    python -m server.server set-level --id student10 --level CONFIDENTIAL
    python -m server.server set-role  --id student10 --role admin
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

# Корінь проєкту додається до sys.path завжди: це дозволяє запускати і
# ``python server/server.py``, і ``python -m server.server``, і
# ``python -m lab9.server.server`` з батьківського каталогу.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[:1] != [PROJECT_ROOT]:
    try:
        sys.path.remove(PROJECT_ROOT)
    except ValueError:
        pass
    sys.path.insert(0, PROJECT_ROOT)

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
from common.security import (
    ROLE_ADMIN,
    level_choices,
    level_name,
    parse_level,
    parse_role,
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
from server.objects import ObjectService, Session

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
                session = self._authenticate(app, channel, message, peer)
                if session is not None:
                    self._serve_session(app, channel, session, peer)
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
    ) -> Optional[Session]:
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
            app.db.log_audit(
                user_id, "login", None, False, "account-temporarily-locked"
            )
            channel.send(
                result_message(
                    False,
                    "too many failed attempts, try again later",
                    retry_after=int(blocked_for) + 1,
                )
            )
            return None

        record = app.db.get_user(user_id)
        if record is not None:
            algorithm = str(record["algorithm"])
            secret = bytes(record["secret"])
            enabled = bool(record["enabled"])
            stored_serial: Optional[str] = record["media_serial"]
            clearance = int(record["clearance"])
            role = str(record["role"])
        else:
            # Для невідомого користувача виконуємо ті самі дії з випадковим
            # секретом, щоб час відповіді не викривав наявність облікового запису.
            algorithm = DEFAULT_ALGORITHM
            secret = random_bytes(32)
            enabled = False
            stored_serial = None
            clearance = 1
            role = "user"

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
            app.db.log_audit(user_id, "login", None, True)
            LOG.info(
                "AUTH OK user=%s peer=%s algorithm=%s level=%s role=%s",
                user_id,
                peer,
                algorithm,
                level_name(clearance),
                role,
            )
            channel.send(
                result_message(
                    True,
                    "authentication successful",
                    user=user_id,
                    algorithm=algorithm,
                    session=session,
                    clearance=clearance,
                    level=level_name(clearance),
                    role=role,
                )
            )
            return Session(
                user_id=user_id,
                clearance=clearance,
                role=role,
                session_id=session,
            )

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
        reason_text = ",".join(reasons) or "unknown"
        app.db.log_audit(user_id, "login", None, False, reason_text)
        LOG.warning(
            "AUTH FAIL user=%s peer=%s reason=%s",
            user_id,
            peer,
            reason_text,
        )
        channel.send(result_message(False, "authentication failed", session=session))
        return None

    # --- сеанс роботи з об'єктами ------------------------------------------

    def _serve_session(
        self,
        app: "AuthServer",
        channel: JsonChannel,
        session: Session,
        peer: str,
    ) -> None:
        """Після успішного рукостискання обслуговує запити до об'єктів."""
        while True:
            message = channel.recv()
            kind = message.get("type")
            if kind == "bye":
                channel.send({"type": "bye", "proto": PROTO_VERSION})
                return
            if kind != "object":
                raise ProtocolError("очікується запит 'object' або 'bye'")
            require_proto(message)
            if message.get("session") != session.session_id:
                raise ProtocolError("ідентифікатор сеансу не збігається")
            response = app.objects.dispatch(session, message)
            channel.send(response)
            LOG.debug(
                "OBJECT user=%s peer=%s action=%s ok=%s",
                session.user_id,
                peer,
                message.get("action"),
                response.get("ok"),
            )

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

        record = app.db.get_user(user_id)
        clearance = int(record["clearance"]) if record is not None else 1
        role = str(record["role"]) if record is not None else "user"
        app.db.log_audit(user_id, "enroll", None, True)
        LOG.info(
            "ENROLL OK user=%s peer=%s algorithm=%s level=%s role=%s",
            user_id,
            peer,
            algorithm,
            level_name(clearance),
            role,
        )
        channel.send(
            {
                "type": "enrolled",
                "proto": PROTO_VERSION,
                "user": user_id,
                "algorithm": algorithm,
                "clearance": clearance,
                "level": level_name(clearance),
                "role": role,
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
        self.objects = ObjectService(db)
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
    enroll.add_argument(
        "--level",
        type=parse_level,
        default=1,
        help=f"допуск нового користувача ({level_choices()})",
    )
    enroll.add_argument(
        "--admin", action="store_true", help="зробити нового користувача адміністратором"
    )

    sub.add_parser("users", help="показати зареєстрованих користувачів")
    sub.add_parser("objects", help="показати всі об'єкти даних")

    acl = sub.add_parser("acl", help="показати ACL об'єкта")
    acl.add_argument("--object", required=True, dest="object_name")

    audit = sub.add_parser("audit", help="показати журнал дій")
    audit.add_argument("--limit", type=int, default=50)

    obj_remove = sub.add_parser("object-remove", help="видалити об'єкт (адміністратор)")
    obj_remove.add_argument("--name", required=True, dest="object_name")

    for name, text in (
        ("enable", "увімкнути обліковий запис"),
        ("disable", "вимкнути обліковий запис"),
        ("remove", "видалити обліковий запис"),
    ):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("--id", required=True, dest="user_id")

    set_level = sub.add_parser("set-level", help="змінити допуск користувача")
    set_level.add_argument("--id", required=True, dest="user_id")
    set_level.add_argument(
        "--level", required=True, type=parse_level, help=level_choices()
    )

    set_role = sub.add_parser("set-role", help="змінити роль користувача")
    set_role.add_argument("--id", required=True, dest="user_id")
    set_role.add_argument(
        "--role", required=True, type=parse_role, choices=("user", ROLE_ADMIN)
    )

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
    print(
        f"{'ID':<16} {'LEVEL':<14} {'ROLE':<7} {'ALGORITHM':<10} "
        f"{'SERIAL':<10} {'ON':<3} CREATED"
    )
    print("-" * 92)
    for row in rows:
        print(
            f"{row['user_id']:<16} {level_name(int(row['clearance'])):<14} "
            f"{row['role']:<7} {row['algorithm']:<10} "
            f"{(row['media_serial'] or '-'):<10} "
            f"{'yes' if row['enabled'] else 'no':<3} {row['created_at']}"
        )


def _print_objects(rows: List[object]) -> None:
    if not rows:
        print("Об'єктів не створено.")
        return
    print(
        f"{'NAME':<18} {'LEVEL':<14} {'KIND':<5} {'OWNER':<14} "
        f"{'SIZE':>6} UPDATED"
    )
    print("-" * 80)
    for row in rows:
        print(
            f"{row['name']:<18} {level_name(int(row['level'])):<14} "
            f"{row['kind']:<5} {row['owner_id']:<14} "
            f"{int(row['size']):>6} {row['updated_at']}"
        )


def _print_acl(rows: List[object]) -> None:
    if not rows:
        print("ACL порожній (права має лише власник).")
        return
    print(f"{'USER':<18} {'RIGHTS':<28} GRANTED_BY")
    print("-" * 62)
    for row in rows:
        print(
            f"{row['user_id']:<18} {row['rights']:<28} "
            f"{row['granted_by'] or '-'}"
        )


def _print_audit(rows: List[object]) -> None:
    if not rows:
        print("Журнал порожній.")
        return
    print(f"{'TIME':<21} {'USER':<12} {'ACTION':<10} {'OBJECT':<16} {'RESULT':<6} REASON")
    print("-" * 100)
    for row in rows:
        print(
            f"{row['at']:<21} {(row['user_id'] or '-'):<12} {row['action']:<10} "
            f"{(row['object_name'] or '-'):<16} "
            f"{'allow' if row['allowed'] else 'deny':<6} {row['reason']}"
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
        code = db.issue_enroll_code(
            ttl_seconds=args.ttl,
            note=args.note,
            level=args.level,
            admin=args.admin,
        )
        print(f"Одноразовий код реєстрації: {code}")
        print(
            f"Допуск: {level_name(args.level)}; роль: "
            f"{ROLE_ADMIN if args.admin else 'user'}"
        )
        print(f"Дійсний протягом {args.ttl} с. Передайте його користувачу.")
        return 0

    if args.command == "users":
        _print_users(db.list_users())
        return 0

    if args.command == "objects":
        _print_objects(db.list_objects())
        return 0

    if args.command == "acl":
        record = db.get_object(args.object_name)
        if record is None:
            print(f"[!] Об'єкт {args.object_name} не знайдено", file=sys.stderr)
            return 1
        print(
            f"Об'єкт {record['name']}: рівень {level_name(int(record['level']))}, "
            f"власник {record['owner_id']}, тип {record['kind']}"
        )
        _print_acl(db.get_acl(int(record["object_id"])))
        return 0

    if args.command == "audit":
        _print_audit(db.list_audit(args.limit))
        return 0

    if args.command == "object-remove":
        record = db.get_object(args.object_name)
        if record is None:
            print(f"[!] Об'єкт {args.object_name} не знайдено", file=sys.stderr)
            return 1
        db.delete_object(int(record["object_id"]))
        print(f"[OK] Об'єкт {args.object_name} видалено")
        return 0

    if args.command in ("enable", "disable"):
        enabled = args.command == "enable"
        if db.set_enabled(args.user_id, enabled):
            print(f"[OK] Обліковий запис {args.user_id}: {'увімкнено' if enabled else 'вимкнено'}")
            return 0
        print(f"[!] Користувача {args.user_id} не знайдено", file=sys.stderr)
        return 1

    if args.command == "set-level":
        if db.set_clearance(args.user_id, args.level):
            print(
                f"[OK] Допуск {args.user_id}: {level_name(args.level)}"
            )
            return 0
        print(f"[!] Користувача {args.user_id} не знайдено", file=sys.stderr)
        return 1

    if args.command == "set-role":
        if db.set_role(args.user_id, args.role):
            print(f"[OK] Роль {args.user_id}: {args.role}")
            return 0
        print(f"[!] Користувача {args.user_id} не знайдено", file=sys.stderr)
        return 1

    if args.command == "remove":
        if db.delete_user(args.user_id):
            print(f"[OK] Обліковий запис {args.user_id} видалено")
            return 0
        print(
            f"[!] Користувача {args.user_id} не знайдено або він володіє об'єктами",
            file=sys.stderr,
        )
        return 1

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
