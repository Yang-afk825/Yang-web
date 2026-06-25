# -*- coding: utf-8 -*-
"""模拟 GUI _auto_solve 调用链路，排查崩溃原因"""
import sys, os, traceback
os.chdir(r'C:\Users\阳\.qclaw\workspace\Yang-web')
sys.path.insert(0, '.')
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("=== 1. 导入 url_analyzer ===")
try:
    from yang_web.core.url_analyzer import analyze_url, auto_exploit, SmartFingerprinter, ConcurrentEngine, AdaptiveScheduler
    print("   OK")
except Exception as e:
    print(f"   FAIL: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n=== 2. 分析目标 URL ===")
url = 'http://80-dd97d346-4448-4740-84d8-7c00b6a0c1f1.challenge.ctfplus.cn'
try:
    result = analyze_url(url)
    print(f"   OK: {len(result['results'])} results, fingerprint={'yes' if result.get('fingerprint') else 'no'}")
except Exception as e:
    print(f"   FAIL: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n=== 3. 模拟 _auto_solve 流程 ===")
import queue, threading
gui_queue = queue.Queue()

def _progress(stage, item, status):
    gui_queue.put(('progress', stage, item, status))

def _found(flag):
    gui_queue.put(('flag', flag))

def _process_queue():
    try:
        while True:
            msg = gui_queue.get_nowait()
            if msg[0] == 'progress':
                _, stage, item, status = msg
                print(f"   [progress] [{stage}] {str(item)[:30]}: {str(status)[:50]}")
            elif msg[0] == 'flag':
                _, flag = msg
                print(f"   🎉 FLAG: {flag}")
    except queue.Empty:
        pass

# Start thread
import time
def _run():
    try:
        final = auto_exploit(url, result['results'],
            on_progress=_progress, on_found=_found,
            fingerprint=result.get('fingerprint'))
        flag = final.get("flag")
        confirmed = final.get("vuln_confirmed", [])
        attacks = final.get("attacks_run", 0)
        timing = final.get("timing_ms", 0)
        print(f"\n=== 4. 结果 ===")
        print(f"   flag={flag}")
        print(f"   attacks={attacks} vulns_confirmed={len(confirmed)} timing={timing/1000:.1f}s")
    except Exception as e:
        print(f"\n   THREAD CRASH: {e}")
        traceback.print_exc()

threading.Thread(target=_run, daemon=True).start()

# Drain queue for a few seconds
t0 = time.time()
while time.time() - t0 < 10:
    _process_queue()
    time.sleep(0.05)

print("\n=== 完成 ===")
