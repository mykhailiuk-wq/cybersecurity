"""Каталог подій журналу аудиту (лабораторна 10).

Журнал аудиту реєструє не лише відмови, а й успішні дії.  Кожен запис має
стабільний код події (``event``), категорію важливості (``severity``) та
службові поля ``peer``/``session_id``/``details``.  Коди подій будуються за
єдиною схемою:

    AUTH-SUCCESS / AUTH-FAILURE / AUTH-LOCKED
    ENROLL-SUCCESS / ENROLL-FAILURE
    OBJECT-<ACTION>-ALLOW / OBJECT-<ACTION>-DENY
    ADMIN-<ACTION>-ALLOW / ADMIN-<ACTION>-DENY

Така схема дозволяє фільтрувати журнал за подією, користувачем, об'єктом і
результатом, не розбираючи текст причини.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional

AUTH_SUCCESS = "AUTH-SUCCESS"
AUTH_FAILURE = "AUTH-FAILURE"
AUTH_LOCKED = "AUTH-LOCKED"
ENROLL_SUCCESS = "ENROLL-SUCCESS"
ENROLL_FAILURE = "ENROLL-FAILURE"

SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_ALERT = "ALERT"

# Події, які стосуються не об'єктів, а сеансу або адміністрування.
_SESSION_ACTIONS = {"whoami"}
_ADMIN_ACTIONS = {"audit", "inventory"}

EVENT_TITLES = {
    AUTH_SUCCESS: "успішна автентифікація",
    AUTH_FAILURE: "невдала автентифікація",
    AUTH_LOCKED: "відмова через тимчасове блокування",
    ENROLL_SUCCESS: "успішна реєстрація токена",
    ENROLL_FAILURE: "невдала реєстрація токена",
    "OBJECT-CREATE-ALLOW": "створення об'єкта дозволено",
    "OBJECT-CREATE-DENY": "створення об'єкта заборонено",
    "OBJECT-READ-ALLOW": "читання об'єкта дозволено",
    "OBJECT-READ-DENY": "читання об'єкта заборонено",
    "OBJECT-WRITE-ALLOW": "заміну вмісту дозволено",
    "OBJECT-WRITE-DENY": "заміну вмісту заборонено",
    "OBJECT-APPEND-ALLOW": "дописування дозволено",
    "OBJECT-APPEND-DENY": "дописування заборонено",
    "OBJECT-DELETE-ALLOW": "видалення об'єкта дозволено",
    "OBJECT-DELETE-DENY": "видалення об'єкта заборонено",
    "OBJECT-GRANT-ALLOW": "призначення прав дозволено",
    "OBJECT-GRANT-DENY": "призначення прав заборонено",
    "OBJECT-REVOKE-ALLOW": "відбирання прав дозволено",
    "OBJECT-REVOKE-DENY": "відбирання прав заборонено",
    "OBJECT-INFO-ALLOW": "перегляд метаданих дозволено",
    "OBJECT-INFO-DENY": "перегляд метаданих заборонено",
    "OBJECT-LIST-ALLOW": "перегляд списку об'єктів дозволено",
    "OBJECT-LIST-DENY": "перегляд списку об'єктів заборонено",
    "SESSION-WHOAMI-ALLOW": "перевірка власного допуску",
    "SESSION-WHOAMI-DENY": "перевірку власного допуску відхилено",
    "ADMIN-AUDIT-ALLOW": "перегляд журналу аудиту дозволено",
    "ADMIN-AUDIT-DENY": "перегляд журналу аудиту заборонено",
    "ADMIN-INVENTORY-ALLOW": "інвентаризацію дозволено",
    "ADMIN-INVENTORY-DENY": "інвентаризацію заборонено",
}


def event_code(action: str, allowed: bool) -> str:
    """Повертає стабільний код події для дії та результату."""
    action = (action or "unknown").strip().lower()
    result = "ALLOW" if allowed else "DENY"

    if action == "login":
        return AUTH_SUCCESS if allowed else AUTH_FAILURE
    if action == "enroll":
        return ENROLL_SUCCESS if allowed else ENROLL_FAILURE
    if action in _ADMIN_ACTIONS:
        return f"ADMIN-{action.upper()}-{result}"
    if action in _SESSION_ACTIONS:
        return f"SESSION-{action.upper()}-{result}"
    return f"OBJECT-{action.upper()}-{result}"


def severity_for(event: str, allowed: bool) -> str:
    """Важливість події: відмови й блокування виділяються окремо."""
    if event == AUTH_LOCKED:
        return SEVERITY_ALERT
    if not allowed:
        return SEVERITY_WARNING
    return SEVERITY_INFO


def event_title(event: str) -> str:
    """Людський опис події для протоколу та довідки."""
    return EVENT_TITLES.get(event, event)


def _field(row: Any, *keys: str, default: Any = "") -> Any:
    """Читає поле із sqlite3.Row або словника, підтримуючи кілька назв.

    Сервер повертає клієнту поле ``user`` замість ``user_id`` та ``object``
    замість ``object_name``, тому форматер приймає обидва варіанти.
    """
    for key in keys:
        try:
            value = row[key]
        except (KeyError, IndexError, TypeError):
            continue
        if value is not None:
            return value
    return default


def format_event(row: Any) -> str:
    """Однорядкове подання запису аудиту (для таблиці «дія — журнал»)."""
    raw_allowed = _field(row, "allowed", default=0)
    allowed = bool(raw_allowed)
    event = str(
        _field(row, "event", default="")
        or event_code(str(_field(row, "action", default="?")), allowed)
    )
    parts = [
        f"#{_field(row, 'id', default='?')}",
        str(_field(row, "at", default="")),
        str(_field(row, "user_id", "user", default="-") or "-"),
        event,
        "ALLOW" if allowed else "DENY",
    ]
    object_name = _field(row, "object_name", "object", default="")
    if object_name:
        parts.append(f"object={object_name}")
    peer = _field(row, "peer", default="")
    if peer:
        parts.append(f"peer={peer}")
    session_id = _field(row, "session_id", default="")
    if session_id:
        parts.append(f"session={str(session_id)[:8]}")
    reason = _field(row, "reason", default="")
    if reason:
        parts.append(f"reason={reason}")
    details = _field(row, "details", default="")
    if details:
        parts.append(f"details={details}")
    return " | ".join(parts)


def format_audit_table(entries: Iterable[Any]) -> List[str]:
    """Формує текстовий журнал із заголовком (спільний для сервера й клієнта)."""
    entries = list(entries)
    lines = [
        f"{'ID':>5} {'TIME':<19} {'USER':<12} {'EVENT':<24} "
        f"{'OBJECT':<14} {'RESULT':<6} PEER"
    ]
    lines.append("-" * 116)
    for row in entries:
        allowed = bool(_field(row, "allowed", default=0))
        event = str(
            _field(row, "event", default="")
            or event_code(str(_field(row, "action", default="?")), allowed)
        )
        lines.append(
            f"{str(_field(row, 'id', default='?')):>5} "
            f"{str(_field(row, 'at', default='')):<19} "
            f"{str(_field(row, 'user_id', 'user', default='-') or '-'):<12} "
            f"{event:<24} "
            f"{str(_field(row, 'object_name', 'object', default='-') or '-'):<14} "
            f"{'allow' if allowed else 'deny':<6} "
            f"{str(_field(row, 'peer', default='-') or '-')}"
        )
        reason = _field(row, "reason", default="")
        if reason:
            lines.append(f"{'':>5} {'':<19} {'':<12} {'':<24} "
                         f"{'':<14} {'':<6} └─ {reason}")
    return lines
