# -*- coding: utf-8 -*-
"""gui._panels_tools -- Shell/stego/scripts/docs panels and the JS challenge game.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)

# 重导出全部原子符号，保持 `from yang_web.gui._panels_tools import X` 契约不变
from ._shell import (ShellPanel)
from ._stego import (StegoPanel)
from ._scripts import (ScriptsPanel)
from ._docs import (DocsPanel)
from ._jsgame import (JSGamePanel)
