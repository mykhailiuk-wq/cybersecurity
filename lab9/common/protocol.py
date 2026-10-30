"""Протокол обміну повідомленнями: JSON-об'єкти, по одному в рядку."""

from __future__ import annotations

import json
import re
import socket
from typing import Any, Dict, Optional, Tuple

PROTO_VERSION = 1
DEFAULT_PORT = 5555
MAX_MESSAGE_BYTES = 64 * 1024

USER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
ENROLL_CODE_RE = re.compile(r"^[0-9A-F]{8,64}$")


class ProtocolError(Exception):
    """Некоректне або неочікуване повідомлення протоколу."""


class ConnectionClosed(ProtocolError):
    """Співрозмовник закрив з'єднання до завершення обміну."""


def validate_user_id(value: str) -> str:
    if not isinstance(value, str) or not USER_ID_RE.match(value):
        raise ValueError(
            "ідентифікатор користувача: 3-64 символи, лише латинські літери, "
            "цифри, '.', '_' або '-'"
        )
    return value


def normalize_enroll_code(value: str) -> str:
    """Прибирає розділювачі та переводить код у верхній регістр."""
    if not isinstance(value, str):
        raise ValueError("код реєстрації має бути рядком")
    code = re.sub(r"[^0-9A-Za-z]", "", value).upper()
    if not ENROLL_CODE_RE.match(code):
        raise ValueError("код реєстрації має містити 8-64 шістнадцяткових символів")
    return code


def format_enroll_code(code: str) -> str:
    """Групує код по чотири символи для зручного введення."""
    return "-".join(code[i : i + 4] for i in range(0, len(code), 4))


def parse_endpoint(
    value: str, default_port: int = DEFAULT_PORT
) -> Tuple[str, int]:
    """Розбирає "host:port", "host", "[::1]:port"."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("адреса сервера порожня")
    text = value.strip()

    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("некоректна IPv6-адреса")
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
        elif rest:
            raise ValueError(f"неочікуваний текст після IPv6-адреси: {rest!r}")
        else:
            port_text = ""
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    elif ":" in text:
        # IPv6 без порту: "::1"
        host, port_text = text, ""
    else:
        host, port_text = text, ""

    if not host:
        raise ValueError("адреса сервера не містить хоста")
    if port_text == "":
        port = default_port
    else:
        try:
            port = int(port_text)
        except ValueError:
            raise ValueError(f"некоректний порт: {port_text!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError("порт має бути в діапазоні 1..65535")
    return host, port


def error_message(code: str, message: str) -> Dict[str, Any]:
    return {"type": "error", "code": code, "message": message}


def result_message(ok: bool, message: str, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": "result",
        "ok": bool(ok),
        "message": message,
    }
    payload.update(extra)
    return payload


def require_proto(message: Dict[str, Any]) -> None:
    value = message.get("proto")
    if value != PROTO_VERSION:
        raise ProtocolError(
            f"непідтримувана версія протоколу {value!r} (очікується {PROTO_VERSION})"
        )


def get_str(
    message: Dict[str, Any],
    key: str,
    *,
    min_len: int = 0,
    max_len: int = 4096,
) -> str:
    value = message.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"поле {key!r} має бути рядком")
    if not min_len <= len(value) <= max_len:
        raise ProtocolError(f"поле {key!r} має неприпустиму довжину")
    return value


def get_int(
    message: Dict[str, Any],
    key: str,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    value = message.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"поле {key!r} має бути цілим числом")
    if min_value is not None and value < min_value:
        raise ProtocolError(f"поле {key!r} замале")
    if max_value is not None and value > max_value:
        raise ProtocolError(f"поле {key!r} завелике")
    return value


class JsonChannel:
    """Надсилання та приймання JSON-повідомлень через TCP-сокет."""

    def __init__(self, sock: socket.socket, max_bytes: int = MAX_MESSAGE_BYTES):
        self._sock = sock
        self._reader = sock.makefile("rb")
        self._max = max_bytes

    def close(self) -> None:
        try:
            self._reader.close()
        except OSError:
            pass

    def recv(self) -> Dict[str, Any]:
        line = self._reader.readline(self._max + 1)
        if not line:
            raise ConnectionClosed("з'єднання закрито співрозмовником")
        if len(line) > self._max:
            raise ProtocolError(f"повідомлення перевищує {self._max} байтів")
        if not line.endswith(b"\n"):
            raise ConnectionClosed("з'єднання закрито посеред повідомлення")
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("повідомлення не є коректним UTF-8") from exc
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"повідомлення не є коректним JSON: {exc.msg}") from exc
        if not isinstance(message, dict):
            raise ProtocolError("повідомлення має бути JSON-об'єктом")
        return message

    def send(self, message: Dict[str, Any]) -> None:
        try:
            data = json.dumps(
                message,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProtocolError(f"не вдалося серіалізувати повідомлення: {exc}") from exc
        if len(data) + 1 > self._max:
            raise ProtocolError("вихідне повідомлення завелике")
        self._sock.sendall(data + b"\n")
