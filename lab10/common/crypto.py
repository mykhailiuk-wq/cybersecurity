"""Криптографічні примітиви, спільні для клієнта та сервера.

Процедура перетворення випадкового числа (варіант 10) — HMAC, побудований
на одному з хеш-алгоритмів Windows CryptoAPI.  Ідентифікатори ALG_ID
відповідають заголовку ``WinCrypt.h``:

    CALG_MD5     = 0x00008003
    CALG_SHA1    = 0x00008004
    CALG_SHA_256 = 0x0000800C
    CALG_SHA_384 = 0x0000800D
    CALG_SHA_512 = 0x0000800E

Випадкові числа генеруються CryptoAPI-функцією ``CryptGenRandom``
(провайдер PROV_RSA_FULL).  Якщо CryptoAPI недоступний (наприклад, під час
тестів на Linux/macOS), використовується CSPRNG операційної системи
(``os.urandom``, який на Windows і так побудований на BCryptGenRandom).
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import re
import threading
from dataclasses import dataclass
from typing import Dict

# Константи CryptoAPI (WinCrypt.h).
PROV_RSA_FULL = 1
CRYPT_VERIFYCONTEXT = 0x00000000F0000000
CRYPT_SILENT = 0x00000040


@dataclass(frozen=True)
class HashSpec:
    """Опис хеш-алгоритму CryptoAPI."""

    name: str
    calg_id: int
    hashlib_name: str
    digest_size: int
    secure: bool


HASHES: Dict[str, HashSpec] = {
    "MD5": HashSpec("MD5", 0x00008003, "md5", 16, False),
    "SHA1": HashSpec("SHA1", 0x00008004, "sha1", 20, False),
    "SHA256": HashSpec("SHA256", 0x0000800C, "sha256", 32, True),
    "SHA384": HashSpec("SHA384", 0x0000800D, "sha384", 48, True),
    "SHA512": HashSpec("SHA512", 0x0000800E, "sha512", 64, True),
}

DEFAULT_ALGORITHM = "SHA256"
HANDSHAKE_CONTEXT = b"usb-auth-handshake-v1"

# Канонічний вигляд назв: без пробілів, дефісів, крапок і підкреслень,
# у верхньому регістрі.  Так "SHA-256", "sha_256", "CALG_SHA_256" і
# "SHA256" перетворюються на один і той самий ключ.
_ALIASES: Dict[str, str] = {}
for _name, _spec in HASHES.items():
    _ALIASES[_name] = _name
    _ALIASES[f"CALG{_name}"] = _name
    _ALIASES[_spec.hashlib_name.upper()] = _name
_ALIASES["CALGSHA1"] = "SHA1"
_ALIASES["CALGSHA256"] = "SHA256"
_ALIASES["CALGSHA384"] = "SHA384"
_ALIASES["CALGSHA512"] = "SHA512"


def normalize_algorithm(value: str) -> str:
    """Зводить назву алгоритму до канонічного вигляду ("SHA256")."""
    if not isinstance(value, str):
        raise ValueError("назва алгоритму має бути рядком")
    key = re.sub(r"[\s._\-]", "", value).upper()
    try:
        return _ALIASES[key]
    except KeyError:
        supported = ", ".join(HASHES)
        raise ValueError(
            f"непідтримуваний хеш-алгоритм {value!r}; доступні: {supported}"
        ) from None


def algorithm_spec(value: str) -> HashSpec:
    return HASHES[normalize_algorithm(value)]


def digest(algorithm: str, data: bytes) -> bytes:
    """Обчислює хеш вибраним алгоритмом CryptoAPI."""
    spec = algorithm_spec(algorithm)
    try:
        # usedforsecurity=False дозволяє MD5/SHA1 у FIPS-режимі (лише для демонстрації).
        return hashlib.new(spec.hashlib_name, data, usedforsecurity=False).digest()
    except TypeError:  # Python < 3.9
        return hashlib.new(spec.hashlib_name, data).digest()


def compute_response(
    algorithm: str, secret: bytes, challenge: bytes, user_id: str
) -> bytes:
    """Процедура перетворення випадкового числа (узгоджується при реєстрації).

    Результат = HMAC(ключ = секрет токена,
                     повідомлення = контекст ‖ id користувача ‖ challenge).

    Контекст відділяє цю конструкцію від інших застосувань того ж ключа,
    а ідентифікатор прив'язує відповідь до конкретного облікового запису.
    """
    spec = algorithm_spec(algorithm)
    message = (
        HANDSHAKE_CONTEXT
        + b"\x00"
        + user_id.encode("utf-8")
        + b"\x00"
        + challenge
    )
    return hmac.new(secret, message, spec.hashlib_name).digest()


# --- Генератор випадкових чисел -------------------------------------------------

_advapi32 = None
_advapi32_lock = threading.Lock()


def _load_advapi32():
    """Ліниве завантаження advapi32.dll з правильними сигнатурами."""
    global _advapi32
    if _advapi32 is not None:
        return _advapi32
    with _advapi32_lock:
        if _advapi32 is None:
            lib = ctypes.WinDLL("advapi32", use_last_error=True)
            lib.CryptAcquireContextW.argtypes = [
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            lib.CryptAcquireContextW.restype = ctypes.c_bool
            lib.CryptGenRandom.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            lib.CryptGenRandom.restype = ctypes.c_bool
            lib.CryptReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            lib.CryptReleaseContext.restype = ctypes.c_bool
            _advapi32 = lib
    return _advapi32


def cryptoapi_random(size: int) -> bytes:
    """``CryptGenRandom`` з CryptoAPI (тільки Windows)."""
    if os.name != "nt":
        raise OSError("CryptoAPI доступний лише у Windows")
    if size < 0:
        raise ValueError("розмір має бути невід'ємним")
    if size == 0:
        return b""
    lib = _load_advapi32()
    provider = ctypes.c_void_p()
    if not lib.CryptAcquireContextW(
        ctypes.byref(provider),
        None,
        None,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_string_buffer(size)
        if not lib.CryptGenRandom(provider, size, buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw
    finally:
        lib.CryptReleaseContext(provider, 0)


def random_bytes(size: int) -> bytes:
    """Криптостійкі випадкові байти (CryptoAPI, з резервним CSPRNG ОС)."""
    if size < 0:
        raise ValueError("розмір має бути невід'ємним")
    if size == 0:
        return b""
    if os.name == "nt":
        try:
            return cryptoapi_random(size)
        except OSError:
            pass
    return os.urandom(size)


def new_secret(size: int = 32) -> bytes:
    """Новий секрет токена (256 біт за замовчуванням)."""
    return random_bytes(size)
