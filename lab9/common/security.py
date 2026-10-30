"""Політика контролю доступу: модель Белла-ЛаПадула без категорій.

Модель використовує лише рівні секретності (без категорій/«need-to-know»).
Рівні утворюють повний порядок:

    1 UNCLASSIFIED < 2 CONFIDENTIAL < 3 SECRET < 4 TOP_SECRET

Мандатні правила (mandatory policy):

    read    — «no read up»:   рівень суб'єкта >= рівня об'єкта
    append  — «no write down»: рівень суб'єкта <= рівня об'єкта
    write   — заміна вмісту (читання + запис): рівні мають бути рівні
    delete  — мандатною моделлю не регулюється (дискреційне право)

Дискреційний рівень (ACL) дає змогу власнику об'єкта призначати права
іншим користувачам.  Мандатні правила діють поверх ACL: навіть із правом
read користувач не прочитає об'єкт вищого рівня.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Set, Tuple, Union

LEVEL_NAMES = {
    1: "UNCLASSIFIED",
    2: "CONFIDENTIAL",
    3: "SECRET",
    4: "TOP_SECRET",
}
LEVEL_RANKS = {name: rank for rank, name in LEVEL_NAMES.items()}
MIN_LEVEL = min(LEVEL_NAMES)
MAX_LEVEL = max(LEVEL_NAMES)

LEVEL_ALIASES = {
    "U": 1,
    "UNCLASS": 1,
    "UNCLASSIFIED": 1,
    "PUBLIC": 1,
    "C": 2,
    "CONF": 2,
    "CONFIDENTIAL": 2,
    "S": 3,
    "SECRET": 3,
    "TS": 4,
    "TOP": 4,
    "TOPSECRET": 4,
    "TOP_SECRET": 4,
}

RIGHT_OWNER = "owner"
RIGHT_READ = "read"
RIGHT_APPEND = "append"
RIGHT_WRITE = "write"
RIGHT_DELETE = "delete"

# Права, які можна передавати іншим користувачам через ACL.
GRANTABLE_RIGHTS: Tuple[str, ...] = (
    RIGHT_READ,
    RIGHT_APPEND,
    RIGHT_WRITE,
    RIGHT_DELETE,
)
# Повний перелік прав, включно з правом власника.
ALL_RIGHTS: Tuple[str, ...] = (RIGHT_OWNER,) + GRANTABLE_RIGHTS

RIGHT_ALIASES = {
    "r": RIGHT_READ,
    "read": RIGHT_READ,
    "a": RIGHT_APPEND,
    "append": RIGHT_APPEND,
    "w": RIGHT_WRITE,
    "write": RIGHT_WRITE,
    "d": RIGHT_DELETE,
    "rm": RIGHT_DELETE,
    "delete": RIGHT_DELETE,
}

OBJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _canonical_level(value: str) -> str:
    return re.sub(r"[\s\-]+", "_", value.strip().upper())


def parse_level(value: Union[int, str]) -> int:
    """Перетворює назву/номер рівня в ціле число 1..4."""
    if isinstance(value, bool):
        raise ValueError("рівень доступу не може бути логічним значенням")
    if isinstance(value, int):
        rank = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("рівень доступу не вказано")
        if text.isdigit():
            rank = int(text)
        else:
            key = _canonical_level(text)
            if key not in LEVEL_ALIASES:
                names = ", ".join(LEVEL_NAMES[rank] for rank in sorted(LEVEL_NAMES))
                raise ValueError(
                    f"невідомий рівень доступу {value!r}; доступні: {names}"
                )
            rank = LEVEL_ALIASES[key]
    else:
        raise ValueError("рівень доступу має бути назвою або числом")

    if rank not in LEVEL_NAMES:
        names = ", ".join(LEVEL_NAMES[item] for item in sorted(LEVEL_NAMES))
        raise ValueError(f"рівень {rank} поза діапазоном 1..4; доступні: {names}")
    return rank


def level_name(rank: int) -> str:
    return LEVEL_NAMES[parse_level(rank)]


def level_choices() -> str:
    return ", ".join(
        f"{rank}={name}" for rank, name in sorted(LEVEL_NAMES.items())
    )


def validate_object_name(value: str) -> str:
    if not isinstance(value, str) or not OBJECT_NAME_RE.match(value):
        raise ValueError(
            "ім'я об'єкта: 1-64 символи, лише латинські літери, цифри, '.', '_' або '-'"
        )
    return value


def parse_rights(
    value: Union[str, Iterable[str]], *, allow_empty: bool = False
) -> Set[str]:
    """Розбирає права виду "read,append" або ["read", "write"]."""
    if isinstance(value, str):
        raw = [part for part in re.split(r"[\s,]+", value.strip()) if part]
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("права мають бути рядками")
            raw.extend(part for part in re.split(r"[\s,]+", item.strip()) if part)
    else:
        raise ValueError("права мають бути рядком або списком рядків")

    result: Set[str] = set()
    for item in raw:
        key = item.strip().lower()
        if key == RIGHT_OWNER:
            raise ValueError(
                "право owner не можна призначати: воно належить лише власнику"
            )
        if key not in RIGHT_ALIASES:
            allowed = ", ".join(GRANTABLE_RIGHTS)
            raise ValueError(f"невідоме право {item!r}; доступні: {allowed}")
        result.add(RIGHT_ALIASES[key])

    if not result and not allow_empty:
        raise ValueError("потрібно вказати хоча б одне право")
    return result


def sorted_rights(rights: Iterable[str]) -> List[str]:
    present = set(rights)
    return [right for right in ALL_RIGHTS if right in present]


def rights_text(rights: Iterable[str]) -> str:
    ordered = sorted_rights(rights)
    return ", ".join(ordered) if ordered else "-"


ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLES: Tuple[str, ...] = (ROLE_USER, ROLE_ADMIN)

FILE_KIND_TEXT = "text"
FILE_KIND_FILE = "file"
OBJECT_KINDS: Tuple[str, ...] = (FILE_KIND_TEXT, FILE_KIND_FILE)


def parse_role(value: str) -> str:
    """Перевіряє назву ролі користувача."""
    if not isinstance(value, str):
        raise ValueError("роль має бути рядком")
    role = value.strip().lower()
    if role not in ROLES:
        raise ValueError(f"невідома роль {value!r}; доступні: {', '.join(ROLES)}")
    return role


def effective_rights(
    user_id: str, owner_id: str, acl_rights: Iterable[str]
) -> Set[str]:
    """Права суб'єкта на об'єкт з урахуванням права власника.

    Власник завжди має повний набір прав.  Інші користувачі отримують лише
    те, що їм явно призначено в ACL.  Мандатні правила перевіряються окремо
    й можуть заборонити дію навіть власнику.
    """
    if user_id == owner_id:
        return set(ALL_RIGHTS)
    return {right for right in acl_rights if right in GRANTABLE_RIGHTS}


def mandatory_create_check(
    subject_level: int, object_level: int
) -> Tuple[bool, str]:
    """Перевірка створення об'єкта за *-властивістю BLP.

    Створення об'єкта нижчого рівня, ніж допуск суб'єкта, означало б запис
    вниз («no write down»), тому заборонене.  Створення об'єкта вищого рівня
    (запис угору) моделлю дозволено, але прочитати його суб'єкт не зможе.
    """
    subject = parse_level(subject_level)
    obj = parse_level(object_level)
    if obj < subject:
        return (
            False,
            "no-write-down: "
            f"clearance {LEVEL_NAMES[subject]} > classification {LEVEL_NAMES[obj]}",
        )
    return True, ""


def authorize(
    action: str,
    *,
    user_id: str,
    owner_id: str,
    subject_level: int,
    object_level: int,
    acl_rights: Iterable[str],
) -> Tuple[bool, str]:
    """Спільна перевірка дискреційного права та мандатного правила.

    Повертає (дозволено, причина_відмови).  Право ``owner`` не є дією;
    власник отримує read/append/write/delete через ``effective_rights``.
    """
    action = action.strip().lower()
    if action not in GRANTABLE_RIGHTS:
        raise ValueError(f"невідома дія: {action!r}")

    rights = effective_rights(user_id, owner_id, acl_rights)
    if action not in rights:
        return (
            False,
            f"дискреційна відмова: немає права {action!r} в ACL об'єкта",
        )
    return mandatory_check(action, subject_level, object_level)


def mandatory_check(
    action: str, subject_level: int, object_level: int
) -> Tuple[bool, str]:
    """Перевірка мандатних правил Белла-ЛаПадула.

    Повертає (дозволено, причина_відмови).  Порожня причина означає дозвіл.
    """
    action = action.strip().lower()
    subject = parse_level(subject_level)
    obj = parse_level(object_level)
    subject_name = LEVEL_NAMES[subject]
    object_name_ = LEVEL_NAMES[obj]

    if action == RIGHT_DELETE:
        # Класична модель BLP не регулює знищення даних.
        return True, ""

    if action == RIGHT_READ:
        if subject >= obj:
            return True, ""
        return (
            False,
            f"no-read-up: clearance {subject_name} < classification {object_name_}",
        )

    if action == RIGHT_APPEND:
        if subject <= obj:
            return True, ""
        return (
            False,
            f"no-write-down: clearance {subject_name} > classification {object_name_}",
        )

    if action == RIGHT_WRITE:
        if subject == obj:
            return True, ""
        if subject > obj:
            return (
                False,
                f"no-write-down: clearance {subject_name} > classification {object_name_}",
            )
        return (
            False,
            "modify-requires-equal-level: "
            f"clearance {subject_name} < classification {object_name_}",
        )

    raise ValueError(f"невідома дія для мандатної перевірки: {action!r}")
