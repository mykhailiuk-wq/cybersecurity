"""Тести серверних об'єктів і політики Белла-ЛаПадула (лабораторна 9).

Модуль також додає корінь проєкту до ``sys.path``, щоб тести можна було
запускати не лише з кореня проєкту, а й як ``python -m lab9.tests...``
з батьківського каталогу.
"""

from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[:1] != [PROJECT_ROOT]:
    try:
        sys.path.remove(PROJECT_ROOT)
    except ValueError:
        pass
    sys.path.insert(0, PROJECT_ROOT)
