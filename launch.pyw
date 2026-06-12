"""Yang-Web GUI å¯å¨å¨ (.pyw = æ æ§å¶å°çªå£)

åå»ç´æ¥å¯å¨ GUIãä¸ python -m yang_web --gui ç­æã
"""
import sys
import os

# ç¡®ä¿é¡¹ç®æ ¹ç®å½å¨ sys.path ä¸­
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from yang_web.__main__ import main_gui

if __name__ == "__main__":
    main_gui()
