# -*- coding: utf-8 -*-
"""双模式入口：`python -m yang_web.core.multi_stage <cmd>` 或直接 `python <pkg>/__main__.py <cmd>`。"""
import os
import sys

# 以文件方式直接执行时把仓库根塞进 sys.path，这样下面的绝对导入才成立。
_root = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)

from yang_web.core.multi_stage._engine import (MultiStageEngine)



# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Multi-Stage Attack Engine CLI")
        print("  python -m yang_web.core.multi_stage <url>  — 自动多阶段解题")
        sys.exit(0)

    url = sys.argv[1]
    engine = MultiStageEngine()
    result = engine.solve(url, on_progress=lambda s, i, st: print(f"  [{s}] {i}: {st}"))
    print(f"\n{'='*50}")
    print(f"Success: {result['success']}")
    if result['flag']:
        print(f"FLAG: {result['flag']}")
    print(f"Stages: {result['stages_count']}")
    print(f"Time: {result['timing_ms']}ms")
    for log_entry in result['attack_log']:
        print(f"  Stage {log_entry['stage']}: {log_entry['type']} → {log_entry['result']}")
