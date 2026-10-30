"""Допоміжні функції для роботи з часом."""

from __future__ import annotations

import sys
from datetime import datetime, timezone


def configure_stdio() -> None:
    """Вмикає UTF-8 для stdout/stderr, щоб кирилиця не ламалася при
    перенаправленні виводу у файл.  У консолі Windows кодування вже UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


def utc_now() -> datetime:
    """Повертає поточний момент у UTC (timezone-aware)."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Поточний момент у форматі ISO 8601 (UTC, секундна точність)."""
    return utc_now().isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime:
    """Розбирає ISO 8601; наївні значення трактуються як UTC."""
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment
