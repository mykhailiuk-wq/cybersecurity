"""Системна база даних сервера (SQLite).

У таблиці ``users`` зберігаються ідентифікатор користувача, узгоджена
процедура перетворення (назва хеш-алгоритму CryptoAPI), секрет токена та
серійний номер носія.  Таблиця ``enroll_codes`` містить одноразові коди,
які адміністратор видає для реєстрації нових токенів.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from typing import Iterator, List, Optional

from common.crypto import normalize_algorithm, random_bytes
from common.protocol import format_enroll_code, normalize_enroll_code, validate_user_id
from common.util import parse_iso, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    algorithm    TEXT NOT NULL,
    secret       BLOB NOT NULL,
    media_serial TEXT,
    created_at   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS enroll_codes (
    code       TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    used_by    TEXT,
    note       TEXT
);
"""

# Можливі результати Database.enroll_user().
ENROLL_OK = "ok"
ENROLL_BAD_CODE = "bad_code"
ENROLL_CODE_USED = "code_used"
ENROLL_CODE_EXPIRED = "code_expired"
ENROLL_USER_EXISTS = "user_exists"


class Database:
    """Невелика обгортка над SQLite; з'єднання відкривається на операцію."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    # --- службові методи ----------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @contextmanager
    def _query(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.commit()
        finally:
            conn.close()

    # --- користувачі --------------------------------------------------------

    def get_user(self, user_id: str) -> Optional[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT user_id, algorithm, secret, media_serial, created_at, enabled "
                "FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()

    def list_users(self) -> List[sqlite3.Row]:
        with self._query() as conn:
            return conn.execute(
                "SELECT user_id, algorithm, media_serial, created_at, enabled "
                "FROM users ORDER BY user_id"
            ).fetchall()

    def set_enabled(self, user_id: str, enabled: bool) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET enabled = ? WHERE user_id = ?",
                (1 if enabled else 0, user_id),
            )
            return cursor.rowcount == 1

    def delete_user(self, user_id: str) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            return cursor.rowcount == 1

    # --- реєстрація ---------------------------------------------------------

    def issue_enroll_code(
        self, ttl_seconds: int = 900, note: Optional[str] = None
    ) -> str:
        """Створює одноразовий код реєстрації; повертає його у форматі XXXX-XXXX-..."""
        if ttl_seconds <= 0:
            raise ValueError("термін дії коду має бути додатним")
        code = random_bytes(8).hex().upper()
        now = utc_now()
        expires = now + timedelta(seconds=ttl_seconds)
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO enroll_codes(code, created_at, expires_at, note) "
                "VALUES (?, ?, ?, ?)",
                (
                    code,
                    now.isoformat(timespec="seconds"),
                    expires.isoformat(timespec="seconds"),
                    note,
                ),
            )
        return format_enroll_code(code)

    def enroll_user(
        self,
        code: str,
        user_id: str,
        algorithm: str,
        secret: bytes,
        media_serial: Optional[str] = None,
    ) -> str:
        """Атомарно витрачає код і створює користувача.

        Повертає один із статусів ENROLL_*.
        """
        normalized_code = normalize_enroll_code(code)
        user_id = validate_user_id(user_id)
        algorithm = normalize_algorithm(algorithm)
        if not isinstance(secret, (bytes, bytearray)) or not 16 <= len(secret) <= 64:
            raise ValueError("секрет токена має містити від 16 до 64 байтів")
        if media_serial is not None and len(media_serial) > 32:
            raise ValueError("серійний номер носія задовгий")

        now = utc_now()
        now_text = now.isoformat(timespec="seconds")
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT used_at, expires_at FROM enroll_codes WHERE code = ?",
                    (normalized_code,),
                ).fetchone()
                if row is None:
                    return ENROLL_BAD_CODE
                if row["used_at"]:
                    return ENROLL_CODE_USED
                try:
                    expires_at = parse_iso(row["expires_at"])
                except ValueError:
                    return ENROLL_CODE_EXPIRED
                if expires_at <= now:
                    return ENROLL_CODE_EXPIRED
                if conn.execute(
                    "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
                ).fetchone():
                    return ENROLL_USER_EXISTS
                updated = conn.execute(
                    "UPDATE enroll_codes SET used_at = ?, used_by = ? "
                    "WHERE code = ? AND used_at IS NULL",
                    (now_text, user_id, normalized_code),
                )
                if updated.rowcount != 1:
                    return ENROLL_CODE_USED
                conn.execute(
                    "INSERT INTO users(user_id, algorithm, secret, media_serial, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (user_id, algorithm, bytes(secret), media_serial, now_text),
                )
                return ENROLL_OK
        except sqlite3.IntegrityError:
            # Паралельна реєстрація того самого id — код відкотився разом із транзакцією.
            return ENROLL_USER_EXISTS
