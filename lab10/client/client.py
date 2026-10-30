"""Клієнт аутентифікації та роботи з об'єктами (лабораторна 9).

Спочатку клієнт проходить рукостискання з сервером (варіант 10), потім у
межах того самого TCP-з'єднання надсилає запити до серверних об'єктів даних.
Сервер самостійно перевіряє дискреційні права (ACL) і мандатні правила
моделі Белла-ЛаПадула без категорій.

Приклади::

    python -m client.client register --server 127.0.0.1:5555 ^
        --token E:\\ --id alice --code ABCD-1234-EF56-7890

    python -m client.client login --token E:\\
    python -m client.client ls --token E:\\
    python -m client.client read --token E:\\ --name public-readme
    python -m client.client create --token E:\\ --name report --level SECRET ^
        --file report.txt
    python -m client.client grant --token E:\\ --name report --id bob --rights read
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Корінь проєкту додається до sys.path завжди: це дозволяє запускати і
# ``python client/client.py``, і ``python -m client.client``, і
# ``python -m lab9.client.client`` з батьківського каталогу.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[:1] != [PROJECT_ROOT]:
    try:
        sys.path.remove(PROJECT_ROOT)
    except ValueError:
        pass
    sys.path.insert(0, PROJECT_ROOT)

from common.audit import format_audit_table
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
from common.security import (
    level_name,
    parse_level,
    parse_role,
    rights_text,
    sorted_rights,
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

CLIENT_NAME = "usb-auth-client/1.1"
MAX_CONTENT_BYTES = 16 * 1024


class ClientError(Exception):
    """Помилка клієнта (мережа, протокол, дані токена)."""


class AuthenticationFailed(ClientError):
    """Сервер відхилив рукостискання (невірний токен, блокування тощо)."""

    def __init__(self, message: str, retry_after: Optional[int] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


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
    """Надсилає один запит і читає одну відповідь (для реєстрації)."""
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

    Допуск і роль визначає одноразовий код, який видав адміністратор.
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
        "clearance": int(reply.get("clearance", 1)),
        "role": str(reply.get("role", "user")),
        "comment": (
            "USB authentication token. Keep this file on the registered flash drive."
        ),
    }
    write_token(path, payload)
    return path


# --- автентифікований сеанс ------------------------------------------------------


@dataclass(frozen=True)
class AuthSession:
    """Рукостискання завершено; можна надсилати запити до об'єктів."""

    host: str
    port: int
    token: Any
    sock: socket.socket
    channel: JsonChannel
    session_id: str
    user_id: str
    clearance: int
    role: str
    message: str

    def request(self, action: str, **fields: Any) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": "object",
            "proto": PROTO_VERSION,
            "session": self.session_id,
            "action": action,
        }
        payload.update(fields)
        try:
            self.channel.send(payload)
            response = self.channel.recv()
        except ProtocolError as exc:
            raise ClientError(f"помилка протоколу: {exc}") from exc
        except socket.timeout as exc:
            raise ClientError("сервер не відповів вчасно") from exc
        if response.get("type") == "error":
            raise ClientError(str(response.get("message", "сервер повернув помилку")))
        if response.get("type") != "object_result":
            raise ClientError("неочікувана відповідь сервера")
        return response

    def close(self) -> None:
        try:
            self.channel.send({"type": "bye", "proto": PROTO_VERSION})
            self.channel.recv()
        except (OSError, ProtocolError):
            pass
        try:
            self.channel.close()
        finally:
            try:
                self.sock.close()
            except OSError:
                pass


def open_session(
    host: str,
    port: int,
    token_target: str,
    *,
    allow_fixed: bool = False,
    timeout: float = 10.0,
) -> AuthSession:
    """Читає токен, виконує рукостискання й повертає відкритий сеанс."""
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

        session_id = get_str(challenge, "session", max_len=64)
        nonce = base64.b64decode(get_str(challenge, "nonce", max_len=256), validate=True)
        mac = compute_response(token.algorithm, token.secret, nonce, token.user_id)

        channel.send(
            {
                "type": "response",
                "session": session_id,
                "mac": base64.b64encode(mac).decode("ascii"),
            }
        )

        result = channel.recv()
        if result.get("type") == "error":
            raise ClientError(str(result.get("message", "сервер повернув помилку")))
        if result.get("type") != "result":
            raise ClientError("неочікувана відповідь сервера")
        if not result.get("ok"):
            retry_after = result.get("retry_after")
            raise AuthenticationFailed(
                str(result.get("message", "authentication failed")),
                int(retry_after) if isinstance(retry_after, int) else None,
            )

        clearance = parse_level(result.get("clearance", 1))
        role = parse_role(result.get("role", "user"))
        return AuthSession(
            host=host,
            port=port,
            token=token,
            sock=sock,
            channel=channel,
            session_id=session_id,
            user_id=token.user_id,
            clearance=clearance,
            role=role,
            message=str(result.get("message", "authentication successful")),
        )
    except AuthenticationFailed:
        channel.close()
        sock.close()
        raise
    except ProtocolError as exc:
        channel.close()
        sock.close()
        raise ClientError(f"помилка протоколу: {exc}") from exc
    except socket.timeout as exc:
        channel.close()
        sock.close()
        raise ClientError("сервер не відповів вчасно") from exc
    except (binascii.Error, ValueError) as exc:
        channel.close()
        sock.close()
        raise ClientError(f"некоректні дані від сервера: {exc}") from exc


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
    try:
        session = open_session(
            host, port, token_target, allow_fixed=allow_fixed, timeout=timeout
        )
    except AuthenticationFailed as exc:
        return False, str(exc), token.algorithm
    try:
        return True, session.message, token.algorithm
    finally:
        session.close()


# --- допоміжні функції CLI ------------------------------------------------------


def _add_session_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--token", required=True, help="каталог або файл токена")
    parser.add_argument(
        "--server",
        help="адреса сервера; за замовчуванням береться з файлу токена",
    )
    parser.add_argument(
        "--allow-fixed",
        action="store_true",
        help="дозволити незнімний носій (лише для налагодження)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="тайм-аут, с")


def _session_for(args: argparse.Namespace) -> AuthSession:
    token = load_token(args.token)
    server_value = args.server or token.server
    if not server_value:
        raise ClientError(
            "адресу сервера не вказано ні параметром --server, ні у файлі токена"
        )
    host, port = parse_endpoint(server_value)
    return open_session(
        host,
        port,
        args.token,
        allow_fixed=args.allow_fixed,
        timeout=args.timeout,
    )


def _read_payload(args: argparse.Namespace, *, required: bool) -> str:
    if args.text is not None and args.input_file is not None:
        raise ClientError("вкажіть або --text, або --file, а не обидва параметри")
    if args.input_file is not None:
        try:
            text = Path(args.input_file).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ClientError(f"не вдалося прочитати файл {args.input_file}: {exc}") from exc
    elif args.text is not None:
        text = args.text
    elif required:
        raise ClientError("потрібно вказати --text або --file")
    else:
        text = ""
    size = len(text.encode("utf-8"))
    if size > MAX_CONTENT_BYTES:
        raise ClientError(
            f"вміст завеликий: {size} байтів (максимум {MAX_CONTENT_BYTES})"
        )
    return text


def _deny(action: str, reply: Dict[str, Any]) -> int:
    reason = reply.get("reason") or reply.get("message") or "відмовлено"
    print(f"[DENY] {action}: {reason}", file=sys.stderr)
    return 1


def _print_object_table(objects: List[Dict[str, Any]]) -> None:
    if not objects:
        print("Доступних об'єктів немає.")
        return
    print(
        f"{'NAME':<18} {'LEVEL':<14} {'KIND':<5} {'OWNER':<12} "
        f"{'SIZE':>6} {'READ':<4} RIGHTS"
    )
    print("-" * 92)
    for item in objects:
        print(
            f"{item['name']:<18} {item['level']:<14} {item['kind']:<5} "
            f"{item['owner']:<12} {int(item['size']):>6} "
            f"{'yes' if item.get('readable') else 'no':<4} "
            f"{item.get('rights_text', '-')}"
        )


def _print_acl(entries: List[Dict[str, Any]]) -> None:
    if not entries:
        print("ACL порожній (права має лише власник).")
        return
    for entry in entries:
        print(
            f"  {entry['user']:<14} {rights_text(sorted_rights(entry['rights']))}"
        )


# --- команди --------------------------------------------------------------------


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
    token = load_token(str(path))
    print(f"[OK] Токен зареєстровано та записано: {path}")
    print(f"     Користувач: {args.user_id}")
    print(
        f"     Допуск:    {level_name(token.clearance or 1)}; "
        f"роль: {token.role or 'user'}"
    )
    print(f"     Алгоритм:  {normalize_algorithm(args.algorithm)}")
    print(f"     Сервер:    {host}:{port}")
    return 0


def _cmd_login(args: argparse.Namespace) -> int:
    try:
        session = _session_for(args)
    except AuthenticationFailed as exc:
        suffix = (
            f" (повторіть через {exc.retry_after} с)" if exc.retry_after else ""
        )
        print(f"[FAIL] Сервер відхилив аутентифікацію: {exc}{suffix}", file=sys.stderr)
        return 1
    try:
        print(f"[OK] Аутентифікацію пройдено: {session.user_id}")
        print(
            f"     Допуск: {level_name(session.clearance)}; роль: {session.role}"
        )
        print(
            f"     Алгоритм: {session.token.algorithm}; "
            f"сервер: {session.host}:{session.port}"
        )
    finally:
        session.close()
    return 0


def _cmd_whoami(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("whoami")
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny("whoami", reply)
    print(f"Користувач: {reply['user']}")
    print(f"Допуск:    {reply['clearance']} ({reply['clearance_rank']})")
    print(f"Роль:      {reply['role']}")
    print(f"Права:     {', '.join(reply['rights'])}")
    return 0


def _cmd_ls(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("list")
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny("list", reply)
    _print_object_table(reply.get("objects", []))
    return 0


def _cmd_read(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("read", name=args.name)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"read {args.name}", reply)
    meta = reply["object"]
    print(
        f"=== {meta['name']} [{meta['level']}], власник {meta['owner']}, "
        f"{meta['size']} байтів ==="
    )
    print(reply["content"], end="" if reply["content"].endswith("\n") else "\n")
    return 0


def _cmd_create(args: argparse.Namespace) -> int:
    text = _read_payload(args, required=False)
    kind = "file" if args.input_file is not None else "text"
    session = _session_for(args)
    try:
        reply = session.request(
            "create",
            name=args.name,
            level=args.level,
            kind=kind,
            content=text,
        )
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"create {args.name}", reply)
    meta = reply["object"]
    print(
        f"[OK] Створено {meta['name']} [{meta['level']}], "
        f"власник {meta['owner']}, {meta['size']} байтів"
    )
    return 0


def _cmd_write(args: argparse.Namespace) -> int:
    text = _read_payload(args, required=True)
    session = _session_for(args)
    try:
        reply = session.request("write", name=args.name, content=text)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"write {args.name}", reply)
    print(f"[OK] Записано {reply['name']}: {reply['size']} байтів")
    return 0


def _cmd_append(args: argparse.Namespace) -> int:
    text = _read_payload(args, required=True)
    session = _session_for(args)
    try:
        reply = session.request("append", name=args.name, content=text)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"append {args.name}", reply)
    print(
        f"[OK] Дописано {reply['appended']} байтів до {reply['name']}; "
        f"тепер {reply['size']} байтів"
    )
    return 0


def _cmd_delete(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("delete", name=args.name)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"delete {args.name}", reply)
    print(f"[OK] Об'єкт {args.name} видалено")
    return 0


def _cmd_grant(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request(
            "grant", name=args.name, target=args.target, rights=args.rights
        )
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"grant {args.name}", reply)
    print(
        f"[OK] {reply['target']} отримав права "
        f"{rights_text(reply['rights'])} на {reply['name']}"
    )
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    fields: Dict[str, Any] = {"name": args.name, "target": args.target}
    if args.rights:
        fields["rights"] = args.rights
    session = _session_for(args)
    try:
        reply = session.request("revoke", **fields)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"revoke {args.name}", reply)
    print(
        f"[OK] Права {reply['target']} на {reply['name']}: "
        f"{rights_text(reply['rights']) if reply['rights'] else 'відсутні'}"
    )
    return 0


def _cmd_objinfo(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("info", name=args.name)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"info {args.name}", reply)
    meta = reply["object"]
    print(f"Об'єкт:      {meta['name']}")
    print(f"Рівень:      {meta['level']} ({meta['level_rank']})")
    print(f"Власник:     {meta['owner']}")
    print(f"Тип:         {meta['kind']}")
    print(f"Розмір:      {meta['size']} байтів")
    print(f"Створено:    {meta['created_at']}")
    print(f"Оновлено:    {meta['updated_at']}")
    print(f"Мої права:   {rights_text(meta['rights'])}")
    print(f"Читання:     {'дозволено' if meta['readable'] else 'заборонено'}")
    if meta.get("read_blocked_by"):
        print(f"Причина:     {meta['read_blocked_by']}")
    if "acl" in meta:
        print("ACL:")
        _print_acl(meta["acl"])
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("read", name=args.name)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny(f"read {args.name}", reply)
    path = Path(args.out)
    try:
        path.write_text(reply["content"], encoding="utf-8")
    except OSError as exc:
        raise ClientError(f"не вдалося записати {path}: {exc}") from exc
    print(f"[OK] {args.name} експортовано у {path}")
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    session = _session_for(args)
    try:
        reply = session.request("inventory")
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny("inventory", reply)
    _print_object_table(reply.get("objects", []))
    print(f"Усього об'єктів: {reply['count']}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    fields: Dict[str, Any] = {"limit": args.limit}
    if args.event:
        fields["event"] = args.event
    if args.audit_user:
        fields["user"] = args.audit_user
    if args.audit_object:
        fields["object"] = args.audit_object
    if args.result:
        fields["result"] = args.result
    session = _session_for(args)
    try:
        reply = session.request("audit", **fields)
    finally:
        session.close()
    if not reply.get("ok"):
        return _deny("audit", reply)
    if not reply["entries"]:
        print("Журнал порожній.")
        return 0
    for line in format_audit_table(reply["entries"]):
        print(line)
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    token = load_token(args.token)
    spec = algorithm_spec(token.algorithm)
    media = describe_media(str(token.path.parent))
    print(f"Файл токена:       {token.path}")
    print(f"Користувач:        {token.user_id}")
    print(
        f"Допуск:            {level_name(token.clearance or 1)}; "
        f"роль: {token.role or 'user'}"
    )
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


# --- командний рядок ------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m client.client",
        description="Клієнт USB-аутентифікації та доступу до об'єктів (лаб. 9)",
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
    _add_session_args(login)

    info = sub.add_parser("info", help="показати вміст токена без секрету")
    info.add_argument("--token", required=True, help="каталог або файл токена")

    whoami = sub.add_parser("whoami", help="показати допуск і роль на сервері")
    _add_session_args(whoami)

    ls = sub.add_parser("ls", help="показати доступні об'єкти")
    _add_session_args(ls)

    read = sub.add_parser("read", help="прочитати об'єкт")
    _add_session_args(read)
    read.add_argument("--name", required=True)

    create = sub.add_parser("create", help="створити об'єкт")
    _add_session_args(create)
    create.add_argument("--name", required=True)
    create.add_argument("--level", required=True, help="рівень секретності")
    create.add_argument("--text", help="вміст рядком")
    create.add_argument("--file", dest="input_file", help="імпортувати текстовий файл")

    write = sub.add_parser("write", help="замінити вміст об'єкта")
    _add_session_args(write)
    write.add_argument("--name", required=True)
    write.add_argument("--text")
    write.add_argument("--file", dest="input_file")

    append = sub.add_parser("append", help="дописати в об'єкт")
    _add_session_args(append)
    append.add_argument("--name", required=True)
    append.add_argument("--text")
    append.add_argument("--file", dest="input_file")

    delete = sub.add_parser("delete", help="видалити об'єкт")
    _add_session_args(delete)
    delete.add_argument("--name", required=True)

    grant = sub.add_parser("grant", help="призначити права іншому користувачу")
    _add_session_args(grant)
    grant.add_argument("--name", required=True)
    grant.add_argument("--id", required=True, dest="target")
    grant.add_argument("--rights", required=True, help="read,append,write,delete")

    revoke = sub.add_parser("revoke", help="відібрати права")
    _add_session_args(revoke)
    revoke.add_argument("--name", required=True)
    revoke.add_argument("--id", required=True, dest="target")
    revoke.add_argument("--rights", help="які саме права відібрати (типово всі)")

    objinfo = sub.add_parser("objinfo", help="метадані та ACL об'єкта")
    _add_session_args(objinfo)
    objinfo.add_argument("--name", required=True)

    export = sub.add_parser("export", help="зберегти об'єкт у локальний файл")
    _add_session_args(export)
    export.add_argument("--name", required=True)
    export.add_argument("--out", required=True)

    inventory = sub.add_parser("inventory", help="усі об'єкти (лише адміністратор)")
    _add_session_args(inventory)

    audit = sub.add_parser("audit", help="журнал подій (лише адміністратор)")
    _add_session_args(audit)
    audit.add_argument("--limit", type=int, default=50)
    audit.add_argument("--event", help="фільтр за кодом події, напр. AUTH-FAILURE")
    audit.add_argument("--user", dest="audit_user", help="фільтр за користувачем")
    audit.add_argument("--object", dest="audit_object", help="фільтр за об'єктом")
    audit.add_argument(
        "--result", choices=("allow", "deny"), help="фільтр за результатом"
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    configure_stdio()
    args = _build_parser().parse_args(argv)
    try:
        handlers = {
            "register": _cmd_register,
            "login": _cmd_login,
            "info": _cmd_info,
            "whoami": _cmd_whoami,
            "ls": _cmd_ls,
            "read": _cmd_read,
            "create": _cmd_create,
            "write": _cmd_write,
            "append": _cmd_append,
            "delete": _cmd_delete,
            "grant": _cmd_grant,
            "revoke": _cmd_revoke,
            "objinfo": _cmd_objinfo,
            "export": _cmd_export,
            "inventory": _cmd_inventory,
            "audit": _cmd_audit,
        }
        handler = handlers.get(args.command)
        if handler is None:
            raise AssertionError(f"unhandled command: {args.command}")
        return handler(args)
    except (ClientError, TokenError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
