# -*- coding: utf-8 -*-
"""Yang-Web v4.0 Web API 服务 — 本地 FastAPI 后端。

复用全部现有引擎 (decoder / hashid / jwt / url_analyzer / misc_crypto /
crypto_engine / chinese_ciphers / advanced_engines / scripts registry)，
对外暴露 REST + SSE 接口，供 Web UI 调用。

启动:  python -m yang_web.server
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .core import decoder, hashid, jwt as jwt_mod
from .core import misc_crypto, crypto_engine, chinese_ciphers, advanced_engines
from .core import url_analyzer
from .scripts import registry

app = FastAPI(title="Yang-Web API", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class DecodeReq(BaseModel):
    text: str
    mode: str = "auto"          # auto | chain | brute | detect
    max_steps: int = 30

class JwtReq(BaseModel):
    token: str
    action: str = "analyze"     # analyze | none | brute

class AttackReq(BaseModel):
    url: str
    param: Optional[str] = None
    payload: Optional[str] = None
    mode: str = "analyze"       # analyze | exploit | single
    timeout: int = 10

class ScriptReq(BaseModel):
    key: str
    args: Optional[List[str]] = None

class CryptoReq(BaseModel):
    op: str                     # aes_encrypt / aes_decrypt / rc4 / xor / md5 / sha1 / sha256
    algo: Optional[str] = None
    data: str
    key: Optional[str] = None
    iv: Optional[str] = None
    mode: Optional[str] = None

# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def _ok(data: Any) -> Dict:
    return {"ok": True, "data": data}

def _err(msg: str, code: int = 400):
    return HTTPException(status_code=code, detail=msg)

# ---------------------------------------------------------------------------
# 基础
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"ok": True, "name": "Yang-Web", "version": "4.0.0", "time": time.time()}

# ---------------------------------------------------------------------------
# 解码
# ---------------------------------------------------------------------------
@app.post("/api/decode")
def api_decode(req: DecodeReq):
    text = req.text
    if not text.strip():
        raise _err("输入不能为空")
    try:
        if req.mode == "chain":
            steps = decoder.chain_decode(text, max_depth=req.max_steps)
            return _ok({"type": "chain", "steps": steps,
                        "final": steps[-1][2] if steps else text})
        if req.mode == "brute":
            results = decoder.brute_decode(text)
            return _ok({"type": "brute", "results": results})
        if req.mode == "detect":
            det = decoder.detect_encoding(text)
            return _ok({"type": "detect", "detections": det})
        # auto: detect -> chain
        det = decoder.detect_encoding(text)
        steps = decoder.chain_decode(text, max_depth=req.max_steps)
        return _ok({"type": "auto", "detections": det, "steps": steps,
                    "final": steps[-1][2] if steps else text})
    except Exception as e:
        raise _err(f"解码失败: {e}")

@app.get("/api/decoders")
def api_decoders():
    return _ok(list(decoder.DECODERS.keys()))

# ---------------------------------------------------------------------------
# Hash 识别
# ---------------------------------------------------------------------------
@app.post("/api/hashid")
def api_hashid(req: DecodeReq):
    if not req.text.strip():
        raise _err("输入不能为空")
    try:
        result = hashid.identify(req.text)
        return _ok(result)
    except Exception as e:
        raise _err(f"Hash 识别失败: {e}")

# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
@app.post("/api/jwt")
def api_jwt(req: JwtReq):
    if not req.token.strip():
        raise _err("token 不能为空")
    try:
        if req.action == "analyze":
            return _ok(jwt_mod.analyze_jwt(req.token))
        if req.action == "none":
            new_token, payload = jwt_mod.none_attack(req.token)
            return _ok({"new_token": new_token, "payload": payload})
        if req.action == "brute":
            hits = jwt_mod.brute_jwt(req.token, jwt_mod.BUILTIN_WORDLIST)
            return _ok({"hits": hits})
        raise _err(f"未知 action: {req.action}")
    except Exception as e:
        raise _err(f"JWT 处理失败: {e}")

# ---------------------------------------------------------------------------
# URL 分析 / 自动攻击
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
def api_analyze(req: AttackReq):
    if not req.url.strip():
        raise _err("URL 不能为空")
    try:
        result = url_analyzer.analyze_url(req.url)
        return _ok(result)
    except Exception as e:
        raise _err(f"分析失败: {e}")

@app.post("/api/exploit")
def api_exploit(req: AttackReq):
    if not req.url.strip():
        raise _err("URL 不能为空")
    try:
        results: Dict[str, Any] = {"url": req.url, "findings": [], "flag": None}
        if req.param and req.payload:
            # 单点攻击
            r = url_analyzer.execute_attack(
                req.url, req.param, {"payload": req.payload}, timeout=req.timeout)
            results["findings"].append({"param": req.param, "payload": req.payload, "result": r})
        else:
            # 先分析再自动攻击
            try:
                analysis = url_analyzer.analyze_url(req.url)
                vuln_list = analysis["results"] if isinstance(analysis, dict) else analysis
            except Exception:
                vuln_list = []
            if not isinstance(vuln_list, list):
                vuln_list = []
            url_analyzer.auto_exploit(
                req.url, vuln_list,
                on_progress=lambda s, i, t: results.setdefault("progress", []).append([s, i, t]),
                on_found=lambda f, src=None: results.update({"flag": f, "flag_src": src}))
        return _ok(results)
    except Exception as e:
        raise _err(f"攻击失败: {e}")

@app.post("/api/attack-stream")
def api_attack_stream(req: AttackReq):
    """SSE 流式自动攻击 — 事件时间线实时推送 (BTFly 风格)。

    事件类型:
        progress: {stage, item, status}   阶段进度
        finding:  {type, detail}          漏洞发现
        flag:     {flag, src}             命中 flag
        done:     {summary}               完成汇总
        error:    {error}                 错误
    """
    import queue as _queue
    import concurrent.futures as _futures

    q: _queue.Queue = _queue.Queue()

    def _run():
        results: Dict[str, Any] = {"url": req.url, "findings": [], "flag": None}
        try:
            def on_progress(stage, item, status):
                q.put({"type": "progress", "stage": str(stage),
                       "item": str(item), "status": str(status)})
            def on_found(flag, src=None):
                q.put({"type": "flag", "flag": str(flag), "src": str(src or "")})
                results["flag"] = flag
                results["flag_src"] = src
            # 先做 URL 分析，再取 results 列表传给 auto_exploit
            try:
                analysis = url_analyzer.analyze_url(req.url)
                vuln_list = analysis["results"] if isinstance(analysis, dict) else analysis
            except Exception:
                vuln_list = []
            if not isinstance(vuln_list, list):
                vuln_list = []
            url_analyzer.auto_exploit(
                req.url, vuln_list,
                on_progress=on_progress,
                on_found=on_found)
            q.put({"type": "done", "summary": {
                "flag": results.get("flag"),
                "findings": results.get("findings", []),
                "attacks_run": results.get("attacks_run", 0),
                "stages": results.get("stages", []),
                "timing_ms": results.get("timing_ms", 0),
            }})
        except Exception as e:
            q.put({"type": "error", "error": str(e)})

    executor = _futures.ThreadPoolExecutor(max_workers=1)
    fut = executor.submit(_run)

    async def gen():
        try:
            while True:
                try:
                    evt = q.get(timeout=0.5)
                except _queue.Empty:
                    if fut.done():
                        break
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(evt, ensure_ascii=False)}\n\n"
                if evt.get("type") in ("done", "error"):
                    break
        finally:
            executor.shutdown(wait=False)

    return StreamingResponse(gen(), media_type="text/event-stream")

# ---------------------------------------------------------------------------
# 脚本库
# ---------------------------------------------------------------------------
@app.get("/api/scripts")
def api_scripts():
    try:
        cats = registry.list_scripts()
        return _ok({"categories": registry.CATEGORIES, "scripts": cats})
    except Exception as e:
        raise _err(f"加载脚本库失败: {e}")

@app.post("/api/scripts/run")
def api_scripts_run(req: ScriptReq):
    meta = registry.get_script(req.key)
    if not meta:
        raise _err(f"脚本不存在: {req.key}")
    try:
        path = registry.get_script_path(req.key)
        # 用子进程执行脚本（避免污染 API 进程）
        import subprocess, sys, os
        cmd = [sys.executable, path] + (req.args or [])
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=60, cwd=os.path.dirname(path))
        return _ok({"key": req.key, "returncode": proc.returncode,
                    "stdout": proc.stdout[-8000:], "stderr": proc.stderr[-4000:]})
    except subprocess.TimeoutExpired:
        raise _err(f"脚本执行超时: {req.key}")
    except Exception as e:
        raise _err(f"脚本执行失败: {e}")

# ---------------------------------------------------------------------------
# 密码学 / 编码引擎
# ---------------------------------------------------------------------------
@app.post("/api/crypto")
def api_crypto(req: CryptoReq):
    try:
        op = req.op.lower()
        # 散列
        if op in ("md5", "sha1", "sha256", "sha512", "sha224", "sha384"):
            import hashlib
            h = hashlib.new(op)
            h.update(req.data.encode("utf-8", errors="replace"))
            return _ok({"op": op, "result": h.hexdigest()})
        # XOR
        if op == "xor":
            if not req.key:
                raise _err("XOR 需要 key")
            key = req.key.encode("utf-8", errors="replace")
            data = req.data.encode("utf-8", errors="replace")
            out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            return _ok({"op": "xor", "result_hex": out.hex(),
                        "result_b64": __import__("base64").b64encode(out).decode(),
                        "result_text": _try_utf8(out)})
        # 委托 crypto_engine
        if hasattr(crypto_engine, op) or op in dir(crypto_engine):
            fn = getattr(crypto_engine, op)
            kwargs = {}
            if req.key is not None:
                kwargs["key"] = req.key
            if req.iv is not None:
                kwargs["iv"] = req.iv
            if req.mode is not None:
                kwargs["mode"] = req.mode
            try:
                res = fn(req.data, **kwargs)
            except TypeError:
                res = fn(req.data)
            return _ok({"op": op, "result": res})
        raise _err(f"不支持的 crypto op: {op}")
    except HTTPException:
        raise
    except Exception as e:
        raise _err(f"Crypto 失败: {e}")

def _try_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# 中文密码 / 高级编码
# ---------------------------------------------------------------------------
@app.post("/api/chinese-cipher")
def api_chinese_cipher(req: DecodeReq):
    """中文特色密码: 与佛论禅/核心价值观/百家姓/熊曰/兽音等。"""
    if not req.text.strip():
        raise _err("输入不能为空")
    try:
        out = []
        for name, fn in _list_chinese_funcs():
            try:
                res = fn(req.text)
                if res:
                    out.append({"name": name, "result": res})
            except Exception:
                pass
        return _ok({"results": out})
    except Exception as e:
        raise _err(f"中文密码处理失败: {e}")

def _list_chinese_funcs():
    funcs = []
    for name in dir(chinese_ciphers):
        if name.startswith("_"):
            continue
        fn = getattr(chinese_ciphers, name)
        if callable(fn) and getattr(fn, "__module__", "") == chinese_ciphers.__name__:
            funcs.append((name, fn))
    return funcs

# ---------------------------------------------------------------------------
# 高级编码
# ---------------------------------------------------------------------------
@app.get("/api/advanced-encoders")
def api_advanced_encoders():
    names = [n for n in dir(advanced_engines)
             if not n.startswith("_") and callable(getattr(advanced_engines, n))]
    return _ok(names)

@app.post("/api/advanced-encode")
def api_advanced_encode(req: DecodeReq):
    if not req.text.strip():
        raise _err("输入不能为空")
    try:
        fn = getattr(advanced_engines, req.mode)
        if not callable(fn):
            raise _err(f"编码器不存在: {req.mode}")
        res = fn(req.text)
        return _ok({"encoder": req.mode, "result": res})
    except AttributeError:
        raise _err(f"编码器不存在: {req.mode}")
    except Exception as e:
        raise _err(f"编码失败: {e}")

# ---------------------------------------------------------------------------
# 古典密码
# ---------------------------------------------------------------------------
@app.get("/api/ciphers")
def api_ciphers():
    try:
        return _ok({"categories": misc_crypto.get_categories(),
                    "ciphers": misc_crypto.list_ciphers()})
    except Exception as e:
        raise _err(f"加载古典密码失败: {e}")

# ---------------------------------------------------------------------------
# 内嵌浏览器代理 — 请求/响应回显 (BP 风格)
# ---------------------------------------------------------------------------
class ProxyReq(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    timeout: int = 15

@app.post("/api/proxy")
def api_proxy(req: ProxyReq):
    """代理请求任意 URL，返回完整响应供浏览器回显。支持自定义 Headers/Cookie。"""
    import urllib.request as _ur
    from urllib.error import HTTPError as _HE, URLError as _UE
    import ssl as _ssl
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) YangWeb/4.0",
            "Accept": "*/*",
        }
        if req.headers:
            headers.update({k: str(v) for k, v in req.headers.items()})
        data = None
        if req.body:
            data = req.body.encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        start = time.time()
        try:
            r = _ur.Request(req.url, data=data, headers=headers, method=req.method)
            resp = _ur.urlopen(r, timeout=req.timeout, context=ctx)
            status = resp.status
            resp_headers = dict(resp.headers)
            raw = resp.read()
        except _HE as e:
            status = e.code
            resp_headers = dict(e.headers)
            raw = e.read()
        except _UE as e:
            raise _err(f"网络错误: {e.reason}")
        elapsed = int((time.time() - start) * 1000)
        # 解码 body
        ctype = resp_headers.get("Content-Type", "").lower()
        charset = "utf-8"
        if "charset=" in ctype:
            try:
                charset = ctype.split("charset=")[-1].split(";")[0].strip()
            except Exception:
                pass
        try:
            body_str = raw.decode(charset, errors="replace")
        except Exception:
            body_str = raw.decode("utf-8", errors="replace")
        return _ok({
            "ok": True, "status": status, "headers": resp_headers,
            "body": body_str[:20000], "body_len": len(raw),
            "elapsed_ms": elapsed,
        })
    except HTTPException:
        raise
    except Exception as e:
        raise _err(f"代理请求失败: {e}")

@app.get("/api/proxy-view")
def api_proxy_view(url: str):
    """服务端拉取目标页面并以 HTML 返回，供 iframe 内嵌预览 (避免 CORS)。"""
    import urllib.request as _ur
    from urllib.error import HTTPError as _HE
    try:
        req = _ur.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) YangWeb/4.0",
        })
        resp = _ur.urlopen(req, timeout=15)
        data = resp.read()
        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" in ctype or "text" in ctype:
            charset = "utf-8"
            if "charset=" in ctype:
                try:
                    charset = ctype.split("charset=")[-1].split(";")[0].strip()
                except Exception:
                    pass
            try:
                text = data.decode(charset, errors="replace")
            except Exception:
                text = data.decode("utf-8", errors="replace")
            return Response(content=text, media_type="text/html; charset=utf-8")
        # 非 HTML (图片/文件) 直接转发
        return Response(content=data, media_type=ctype or "application/octet-stream")
    except _HE as e:
        return Response(content=f"<h3>HTTP {e.code} — {e.reason}</h3>", media_type="text/html")
    except Exception as e:
        return Response(content=f"<h3>加载失败: {e}</h3>", media_type="text/html")

# ---------------------------------------------------------------------------
# 静态文件 (Web UI)
# ---------------------------------------------------------------------------
_WEB_DIR = Path(__file__).resolve().parent / "web"
if _WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR)), name="static")

    @app.get("/")
    def index():
        return FileResponse(str(_WEB_DIR / "index.html"))

# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main():
    import uvicorn
    port = int(os.environ.get("YANGWEB_PORT", "8765"))
    url = f"http://127.0.0.1:{port}"

    # 启动日志 (无窗口 exe 排查用) — 写到 exe/工作目录，不写 _MEI 临时目录
    import io as _io
    _LOG = None
    _log_dir = None
    if getattr(sys, 'frozen', False):
        try:
            _log_dir = os.path.dirname(os.path.abspath(sys.executable))
        except Exception:
            _log_dir = None
    if not _log_dir:
        _log_dir = os.getcwd()
    try:
        _LOG = open(os.path.join(_log_dir, "yangweb_start.log"), "w", encoding="utf-8")
    except Exception:
        _LOG = None

    def _log(*args):
        if _LOG:
            try:
                _LOG.write(" ".join(str(a) for a in args) + "\n")
                _LOG.flush()
            except Exception:
                pass

    _log("main() start, port=", port)

    # 后台线程启动 API 服务
    def _run_server():
        try:
            _log("uvicorn.run starting...")
            # log_config=None: 避免 windowed 模式 (sys.stdout=None) 下
            # uvicorn 日志配置崩溃 (AttributeError: isatty)
            uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning",
                        log_config=None, access_log=False)
        except Exception as e:
            import traceback
            _log("uvicorn FAIL:", repr(e))
            _log(traceback.format_exc())

    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    # 等待服务就绪
    import urllib.request
    for _ in range(50):
        try:
            urllib.request.urlopen(url + "/api/health", timeout=1)
            _log("health OK")
            break
        except Exception as e:
            time.sleep(0.2)
    else:
        _log("health NOT ready after 10s")

    print(f"Yang-Web v4.0 API 服务: {url}")

    # 优先用 pywebview 独立窗口 (无浏览器标签栏，工具箱形态)
    try:
        import webview
        _log("webview creating window...")
        webview.create_window(
            "Yang-Web v4.0 — CTF 综合工具箱",
            url,
            width=1360, height=860,
            min_size=(980, 640),
            background_color="#0f1117",
        )
        _log("webview.start()...")
        webview.start()
        _log("webview closed")
    except ImportError:
        # 无 pywebview 时回退到默认浏览器
        import webbrowser
        print("pywebview 不可用，改用默认浏览器打开…")
        webbrowser.open(url)
        input("按回车停止服务…")
    except Exception as e:
        import traceback
        _log("webview FAIL:", repr(e))
        _log(traceback.format_exc())

if __name__ == "__main__":
    main()
