"""Файл токена на флеш-диску та перевірка носія.

Уся реєстраційна інформація, потрібна для аутентифікації, зберігається
в одному JSON-файлі ``usb_auth_token.json`` у корені флеш-диска:
ідентифікатор користувача, узгоджений хеш-алгоритм, секрет токена,
серійний номер носія та адреса сервера.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from common.crypto import normalize_algorithm
from common.media import MediaInfo, describe_media
from common.protocol import validate_user_id
from common.security import parse_level, parse_role

TOKEN_FILENAME = "usb_auth_token.json"
TOKEN_FORMAT = "usb-auth-token/1"
MIN_SECRET_BYTES = 16
MAX_SECRET_BYTES = 64


class TokenError(Exception):
    """Проблема з файлом токена або носієм."""


@dataclass(frozen=True)
class Token:
    path: Path
    user_id: str
    algorithm: str
    secret: bytes
    server: str
    media_serial: Optional[str]
    media_label: Optional[str]
    created_at: str
    clearance: int
    role: str
    raw: Dict[str, Any]


def token_file_path(target: str, *, for_write: bool = False) -> Path:
    """Визначає шлях до файлу токена.

    ``target`` може бути каталогом (корінь флеш-диска) або безпосередньо
    шляхом до JSON-файлу.
    """
    path = Path(target).expanduser()
    if path.exists():
        return path / TOKEN_FILENAME if path.is_dir() else path

    if for_write and path.suffix.lower() == ".json" and path.parent.exists():
        return path

    if for_write:
        raise TokenError(f"каталог токена не існує: {path}")
    raise TokenError(f"файл або каталог токена не існує: {path}")


def load_token(target: str) -> Token:
    path = token_file_path(target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TokenError(f"не вдалося прочитати файл токена {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TokenError(f"файл токена {path} пошкоджено: {exc}") from exc

    if not isinstance(raw, dict):
        raise TokenError(f"файл токена {path} має некоректну структуру")
    if raw.get("format") != TOKEN_FORMAT:
        raise TokenError(
            f"невідомий формат токена {raw.get('format')!r} (очікується {TOKEN_FORMAT})"
        )

    try:
        user_id = validate_user_id(raw["user_id"])
        algorithm = normalize_algorithm(raw["algorithm"])
        secret = base64.b64decode(raw["secret"], validate=True)
        if not MIN_SECRET_BYTES <= len(secret) <= MAX_SECRET_BYTES:
            raise ValueError("секрет має містити 16-64 байти")
        server = raw.get("server", "")
        if not isinstance(server, str):
            raise ValueError("поле 'server' має бути рядком")
        media_serial = raw.get("media_serial")
        if media_serial is not None and not isinstance(media_serial, str):
            raise ValueError("поле 'media_serial' має бути рядком")
        media_label = raw.get("media_label")
        if media_label is not None and not isinstance(media_label, str):
            raise ValueError("поле 'media_label' має бути рядком")
        created_at = raw.get("created_at", "")
        if not isinstance(created_at, str):
            raise ValueError("поле 'created_at' має бути рядком")
        clearance = parse_level(raw.get("clearance", 1))
        role = parse_role(raw.get("role", "user"))
    except (KeyError, ValueError, binascii.Error) as exc:
        raise TokenError(f"файл токена {path} має некоректні дані: {exc}") from exc

    return Token(
        path=path,
        user_id=user_id,
        algorithm=algorithm,
        secret=secret,
        server=server,
        media_serial=media_serial,
        media_label=media_label,
        created_at=created_at,
        clearance=clearance,
        role=role,
        raw=raw,
    )


def write_token(path: Path, payload: Dict[str, Any]) -> None:
    """Атомарно записує файл токена (спочатку .tmp, потім os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise TokenError(f"не вдалося записати файл токена {path}: {exc}") from exc


def check_token_media(
    location: Path,
    expected_serial: Optional[str],
    *,
    allow_fixed: bool = False,
) -> MediaInfo:
    """Перевіряє, що токен лежить на тому самому знімному носії.

    ``allow_fixed`` потрібен лише для налагодження на звичайному диску
    (наприклад, у каталозі на диску C:).
    """
    media = describe_media(str(location))

    if os.name == "nt":
        if media.serial is None and not allow_fixed:
            raise TokenError(
                f"не вдалося визначити серійний номер носія {media.root}; "
                "перевірте, чи підключено флеш-диск"
            )
        if media.removable is False and not allow_fixed:
            raise TokenError(
                f"{media.root} не є знімним носієм (тип: {media.drive_type_name}). "
                "Запустіть програму з флеш-диска або вкажіть --allow-fixed для тесту"
            )

    if (
        expected_serial
        and media.serial
        and media.serial.upper() != expected_serial.upper()
    ):
        raise TokenError(
            f"серійний номер носія {media.serial} не збігається із записаним "
            f"у токені {expected_serial}; файл токена скопійовано на інший носій?"
        )

    return media
