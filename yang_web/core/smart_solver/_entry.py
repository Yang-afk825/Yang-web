"""yang_web.core.smart_solver 子模块 _entry（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any

from ._solver import (SmartSolver)



# ═══════════════════════════════════════════════════════════
#  CLI 入口
# ═══════════════════════════════════════════════════════════

def main():
    """CLI 测试入口."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m yang_web.core.smart_solver web <url>")
        print("  python -m yang_web.core.smart_solver crypto <ciphertext>")
        print("  python -m yang_web.core.smart_solver binary <filepath>")
        print("  python -m yang_web.core.smart_solver blockchain <source_file>")
        print("  python -m yang_web.core.smart_solver misc <filepath>")
        print("  python -m yang_web.core.smart_solver batch <problems_json>")
        return
    
    cmd = sys.argv[1]
    solver = SmartSolver()
    
    if cmd == "web" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Web Problem", "tags": [{"name": "Web"}], "problemType": 1},
            url=sys.argv[2]
        )
    elif cmd == "crypto" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Crypto Problem", "tags": [{"name": "Crypto"}]},
            ciphertext=sys.argv[2]
        )
    elif cmd == "binary" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Binary Problem", "tags": [{"name": "Reverse"}]},
            filepath=sys.argv[2]
        )
    elif cmd == "blockchain" and len(sys.argv) > 2:
        with open(sys.argv[2], 'r', encoding='utf-8') as f:
            source = f.read()
        result = solver.solve(
            metadata={"name": "Blockchain Problem", "tags": [{"name": "Blockchain"}]},
            source=source
        )
    elif cmd == "misc" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Misc Problem", "tags": [{"name": "Misc"}]},
            filepath=sys.argv[2]
        )
    elif cmd == "batch" and len(sys.argv) > 2:
        with open(sys.argv[2], 'r', encoding='utf-8') as f:
            data = json.load(f)
        problems = data.get("problems", data if isinstance(data, list) else [])
        containers = data.get("containers", {})
        attachments = data.get("attachments", {})
        results = solver.batch_solve(problems, containers, attachments)
        solver.print_summary(results)
        return
    else:
        print(f"Unknown command: {cmd}")
        return
    
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
