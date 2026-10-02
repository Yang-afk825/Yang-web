# -*- coding: utf-8 -*-
"""gui._panels_attack -- URL attack panel and SQLi-labs panel.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from .._deps import (LESSON_DB, SQLLabsEngine, scrolledtext, time, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_label)

# 重导出全部原子符号，保持 `from yang_web.gui._panels_attack import X` 契约不变
from ._url_attack import (UrlAttackPanel)
from ._sqli_labs import (SQLLabsPanel)
