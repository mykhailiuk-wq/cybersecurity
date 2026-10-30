"""Клієнт аутентифікації методом «рукостискання» (варіант 10).

Клієнт читає реєстраційні дані з файлу на флеш-диску, підключається до
сервера по TCP, отримує випадкове число, перетворює його узгодженим
хеш-алгоритмом CryptoAPI та повертає результат серверу.

Приклади::

    python -m client.client register --server 127.0.0.1:5555 ^
        --token E:\\ --id student10 --code ABCD-1234-EF56-7890

    python -m client.client login --token E:\\

    python -m client.client info --token E:\\
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import socket
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# Дозволяє запускати файл напряму: python client/client.py ...
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import (
    DEFAULT_ALGORITHM,
    algorithm_spec,
    compute_response,
    new_secret,
    normalize_algorithm,
)
from common.media import describe_media
from common.protocol import (
    PROTO_VERSION,
    JsonChannel,
    ProtocolError,
    get_str,
    normalize_enroll_code,
    parse_endpoint,
    validate_user_id,
)
from common.util import configure_stdio, iso_now
from client.token_file import (
    TOKEN_FORMAT,
    TokenError,
    check_token_media,
    load_token,
    token_file_path,
    write_token,
)

CLIENT_NAME = "usb-auth-client/1.0"


class ClientError(Exception):
    """Помилка клієнта (мережа, протокол, дані токена)."""


# --- мережеві операції ----------------------------------------------------------


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise ClientError(f"не вдалося підключитися до {host}:{port}: {exc}") from exc
    sock.settimeout(timeout)
    return sock


def _exchange(
    host: str,
    port: int,
    request: dict,
    timeout: float,
) -> dict:
    """Надсилає один запит і читає одну відповідь."""
    sock = _connect(host, port, timeout)
    channel = JsonChannel(sock)
    try:
        channel.send(request)
        return channel.recv()
    except ProtocolError as exc:
        raise ClientError(f"помилка протоколу: {exc}") from exc
    except socket.timeout as exc:
        raise ClientError("сервер не відповів вчасно") from exc
    finally:
        channel.close()
        sock.close()


# --- реєстрація -----------------------------------------------------------------


def register(
    host: str,
    port: int,
    token_target: str,
    user_id: str,
    algorithm: str,
    code: str,
    *,
    allow_fixed: bool = False,
    force: bool = False,
    timeout: float = 10.0,
) -> Path:
    """Реєструє новий токен на сервері та записує файл на носій.

    Процедура перетворення (хеш-алгоритм) узгоджується тут: клієнт обирає
    алгоритм, сервер зберігає його разом з ідентифікатором у своїй базі.
    """
    try:
        user_id = validate_user_id(user_id)
        algorithm = normalize_algorithm(algorithm)
        code = normalize_enroll_code(code)
    except ValueError as exc:
        raise ClientError(str(exc)) from exc

    path = token_file_path(token_target, for_write=True)
    if path.exists() and not force:
        raise ClientError(
            f"токен уже існує: {path}. Використайте --force, щоб перезаписати"
        )

    # Перевіряємо носій до реєстрації: токен має бути на знімному диску.
    media = check_token_media(path.parent, None, allow_fixed=allow_fixed)
    secret = new_secret(32)

    reply = _exchange(
        host,
        port,
        {
            "type": "enroll",
            "proto": PROTO_VERSION,
            "code": code,
            "id": user_id,
            "algorithm": algorithm,
            "secret": base64.b64encode(secret).decode("ascii"),
            "media_serial": media.serial,
            "client": CLIENT_NAME,
        },
        timeout,
    )

    if reply.get("type") == "error":
        raise ClientError(str(reply.get("message", "сервер відхилив реєстрацію")))
    if reply.get("type") != "enrolled":
        raise ClientError("неочікувана відповідь сервера під час реєстрації")

    payload = {
        "format": TOKEN_FORMAT,
        "user_id": user_id,
        "algorithm": algorithm,
        "secret": base64.b64encode(secret).decode("ascii"),
        "media_serial": media.serial,
        "media_label": media.label,
        "server": f"{host}:{port}",
        "created_at": iso_now(),
        "comment": (
            "USB authentication token. Keep this file on the registered flash drive."
        ),
    }
    write_token(path, payload)
    return path


# --- аутентифікація --------------------------------------------------------------


def authenticate(
    host: str,
    port: int,
    token_target: str,
    *,
    allow_fixed: bool = False,
    timeout: float = 10.0,
) -> Tuple[bool, str, str]:
    """Виконує рукостискання; повертає (успіх, повідомлення, алгоритм)."""
    token = load_token(token_target)
    media = check_token_media(
        token.path.parent, token.media_serial, allow_fixed=allow_fixed
    )

    sock = _connect(host, port, timeout)
    channel = JsonChannel(sock)
    try:
        channel.send(
            {
                "type": "hello",
                "proto": PROTO_VERSION,
                "id": token.user_id,
                "media_serial": media.serial or token.media_serial,
                "client": CLIENT_NAME,
            }
        )

        challenge = channel.recv()
        if challenge.get("type") == "error":
            raise ClientError(str(challenge.get("message", "сервер повернув помилку")))
        if challenge.get("type") != "challenge":
            raise ClientError("сервер не надіслав випадкове число (challenge)")

        session = get_str(challenge, "session", max_len=64)
        nonce = base64.b64decode(get_str(challenge, "nonce", max_len=256), validate=True)
        mac = compute_response(token.algorithm, token.secret, nonce, token.user_id)

        channel.send(
            {
                "type": "response",
                "session": session,
                "mac": base64.b64encode(mac).decode("ascii"),
            }
        )

        result = channel.recv()
        if result.get("type") == "error":
            raise ClientError(str(result.get("message", "сервер повернув помилку")))
        if result.get("type") != "result":
            raise ClientError("неочікувана відповідь сервера")
        return (
            bool(result.get("ok")),
            str(result.get("message", "")),
            token.algorithm,
        )
    except ProtocolError as exc:
        raise ClientError(f"помилка протоколу: {exc}") from exc
    except socket.timeout as exc:
        raise ClientError("сервер не відповів вчасно") from exc
    except (binascii.Error, ValueError) as exc:
        raise ClientError(f"некоректні дані від сервера: {exc}") from exc
    finally:
        channel.close()
        sock.close()


# --- командний рядок ------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m client.client",
        description="Клієнт USB-аутентифікації (варіант 10, «рукостискання»)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", help="зареєструвати токен на сервері")
    reg.add_argument("--server", required=True, help="адреса сервера, напр. 127.0.0.1:5555")
    reg.add_argument(
        "--token", required=True, help="каталог флеш-диска (напр. E:\\) або шлях до файлу"
    )
    reg.add_argument("--id", required=True, dest="user_id", help="ідентифікатор користувача")
    reg.add_argument("--code", required=True, help="одноразовий код реєстрації")
    reg.add_argument(
        "--algorithm",
        default=DEFAULT_ALGORITHM,
        help=f"хеш-алгоритм CryptoAPI (за замовчуванням {DEFAULT_ALGORITHM})",
    )
    reg.add_argument(
        "--allow-fixed",
        action="store_true",
        help="дозволити незнімний носій (лише для налагодження)",
    )
    reg.add_argument("--force", action="store_true", help="перезаписати наявний токен")
    reg.add_argument("--timeout", type=float, default=10.0, help="тайм-аут, с")

    login = sub.add_parser("login", help="пройти аутентифікацію")
    login.add_argument(
        "--server",
        help="адреса сервера; за замовчуванням береться з файлу токена",
    )
    login.add_argument("--token", required=True, help="каталог або файл токена")
    login.add_argument(
        "--allow-fixed",
        action="store_true",
        help="дозволити незнімний носій (лише для налагодження)",
    )
    login.add_argument("--timeout", type=float, default=10.0, help="тайм-аут, с")

    info = sub.add_parser("info", help="показати вміст токена без секрету")
    info.add_argument("--token", required=True, help="каталог або файл токена")
    return parser


def _cmd_register(args: argparse.Namespace) -> int:
    host, port = parse_endpoint(args.server)
    path = register(
        host,
        port,
        args.token,
        args.user_id,
        args.algorithm,
        args.code,
        allow_fixed=args.allow_fixed,
        force=args.force,
        timeout=args.timeout,
    )
    print(f"[OK] Токен зареєстровано та записано: {path}")
    print(f"     Користувач: {args.user_id}")
    print(f"     Алгоритм:  {normalize_algorithm(args.algorithm)}")
    print(f"     Сервер:    {host}:{port}")
    return 0


def _cmd_login(args: argparse.Namespace) -> int:
    token = load_token(args.token)
    server_value = args.server or token.server
    if not server_value:
        raise ClientError(
            "адресу сервера не вказано ні параметром --server, ні у файлі токена"
        )
    host, port = parse_endpoint(server_value)
    ok, message, algorithm = authenticate(
        host,
        port,
        args.token,
        allow_fixed=args.allow_fixed,
        timeout=args.timeout,
    )
    if ok:
        print(f"[OK] Аутентифікацію пройдено: {token.user_id}")
        print(f"     Алгоритм: {algorithm}; сервер: {host}:{port}")
        return 0
    print(f"[FAIL] Сервер відхилив аутентифікацію: {message}", file=sys.stderr)
    return 1


def _cmd_info(args: argparse.Namespace) -> int:
    token = load_token(args.token)
    spec = algorithm_spec(token.algorithm)
    media = describe_media(str(token.path.parent))
    print(f"Файл токена:       {token.path}")
    print(f"Користувач:        {token.user_id}")
    print(
        f"Алгоритм:          {token.algorithm} "
        f"(CALG=0x{spec.calg_id:08X}, {spec.digest_size} байтів)"
    )
    print(f"Сервер:            {token.server or '(не вказано)'}")
    print(f"Створено:          {token.created_at}")
    print(
        f"Поточний носій:    {media.root} ({media.drive_type_name}), "
        f"серійний номер {media.serial or 'невідомий'}"
    )
    print(f"Серійний у токені: {token.media_serial or '(не записано)'}")
    print("Секрет токена:     приховано")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    configure_stdio()
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "register":
            return _cmd_register(args)
        if args.command == "login":
            return _cmd_login(args)
        if args.command == "info":
            return _cmd_info(args)
        raise AssertionError(f"unhandled command: {args.command}")
    except (ClientError, TokenError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
