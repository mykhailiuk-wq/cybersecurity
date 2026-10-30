"""Визначення типу та серійного номера носія (флеш-диска).

На Windows використовуються функції ядра ``GetDriveTypeW`` та
``GetVolumeInformationW`` (серійний номер тому — це той самий ідентифікатор,
який показує команда ``vol``).  На інших платформах інформація про носій
недоступна без сторонніх бібліотек, тому повертаються значення ``None``.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from typing import Optional

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

DRIVE_TYPE_NAMES = {
    DRIVE_UNKNOWN: "unknown",
    DRIVE_NO_ROOT_DIR: "no-root",
    DRIVE_REMOVABLE: "removable",
    DRIVE_FIXED: "fixed",
    DRIVE_REMOTE: "remote",
    DRIVE_CDROM: "cdrom",
    DRIVE_RAMDISK: "ramdisk",
}


@dataclass(frozen=True)
class MediaInfo:
    path: str
    root: str
    label: Optional[str]
    serial: Optional[str]
    filesystem: Optional[str]
    drive_type: Optional[int]
    platform: str

    @property
    def removable(self) -> Optional[bool]:
        if self.drive_type is None:
            return None
        return self.drive_type == DRIVE_REMOVABLE

    @property
    def drive_type_name(self) -> str:
        if self.drive_type is None:
            return "unknown"
        return DRIVE_TYPE_NAMES.get(self.drive_type, f"type-{self.drive_type}")


def _windows_media(path: str) -> MediaInfo:
    absolute = os.path.abspath(path)
    drive, _ = os.path.splitdrive(absolute)
    root = (drive + "\\") if drive else absolute

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint
    drive_type = int(kernel32.GetDriveTypeW(root))

    label: Optional[str] = None
    serial: Optional[str] = None
    filesystem: Optional[str] = None

    if drive_type not in (DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR):
        kernel32.GetVolumeInformationW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        kernel32.GetVolumeInformationW.restype = ctypes.c_int

        volume_name = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        serial_number = ctypes.c_uint32(0)
        max_component = ctypes.c_uint32(0)
        flags = ctypes.c_uint32(0)

        ok = kernel32.GetVolumeInformationW(
            root,
            volume_name,
            len(volume_name),
            ctypes.byref(serial_number),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            fs_name,
            len(fs_name),
        )
        if ok:
            label = volume_name.value or None
            filesystem = fs_name.value or None
            serial = f"{serial_number.value:08X}"

    return MediaInfo(
        path=absolute,
        root=root,
        label=label,
        serial=serial,
        filesystem=filesystem,
        drive_type=drive_type,
        platform=sys.platform,
    )


def _posix_media(path: str) -> MediaInfo:
    absolute = os.path.abspath(path)
    return MediaInfo(
        path=absolute,
        root=os.path.abspath(os.sep),
        label=None,
        serial=None,
        filesystem=None,
        drive_type=None,
        platform=sys.platform,
    )


def describe_media(path: str) -> MediaInfo:
    """Повертає інформацію про носій, на якому розташовано ``path``."""
    if os.name == "nt":
        return _windows_media(path)
    return _posix_media(path)
