# -*- coding: utf-8 -*-
"""双模式入口：`python -m yang_web.core.advanced_scanner <cmd>` 或直接 `python <pkg>/__main__.py <cmd>`。"""
import os
import sys

# 以文件方式直接执行时（scripts/runner.py 走这条），把仓库根塞进 sys.path，
# 这样下面的绝对导入才成立；用 -m 执行时这段是无害的幂等操作。
_root = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)

from yang_web.core.advanced_scanner._dict import (DictScanner)
from yang_web.core.advanced_scanner._port import (QuickPortScanner)
from yang_web.core.advanced_scanner._batch import (BatchRunner)
from yang_web.core.advanced_scanner._solver import (AdvancedSolver)



# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Advanced Scanner CLI")
        print("  python advanced_scanner.py scan <url>         — 深度扫描")
        print("  python advanced_scanner.py dict <url>         — 仅字典扫描")
        print("  python advanced_scanner.py ports <host>       — 端口扫描")
        print("  python advanced_scanner.py batch <url1> <url2>... — 批量处理")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "scan" and len(sys.argv) > 2:
        url = sys.argv[2]
        solver = AdvancedSolver()
        result = solver.deep_scan(url)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif cmd == "dict" and len(sys.argv) > 2:
        url = sys.argv[2]
        scanner = DictScanner(url)
        result = scanner.scan()
        for p in result["paths_found"]:
            print(f"  {p['status']:>3} | {p['path']:<40} | {p.get('body_len', 0):>5}B | {p.get('title', '')[:40]}")
        print(f"\nTotal: {result['count']} paths found in {result['timing_ms']}ms")

    elif cmd == "ports" and len(sys.argv) > 2:
        host = sys.argv[2]
        scanner = QuickPortScanner(host)
        result = scanner.scan()
        for p in result["open_ports"]:
            print(f"  {p['port']:>5}/tcp  {p['service']:<15} {p.get('banner', '')}")
        print(f"\nOpen: {result['open']}/{result['total']} in {result['timing_ms']}ms")

    elif cmd == "batch":
        urls = sys.argv[2:]
        if urls:
            runner = BatchRunner()
            results = runner.run(urls)
            for r in results:
                status = "✅" if r.get("flag") else "❌"
                print(f"  {status} {r['url']}: {r.get('flag', 'no flag')}")
