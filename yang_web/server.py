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
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
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
            url_analyzer.auto_exploit(req.url, results)
        return _ok(results)
    except Exception as e:
        raise _err(f"攻击失败: {e}")

@app.post("/api/attack-stream")
def api_attack_stream(req: AttackReq):
    """SSE 流式自动攻击 — 进度实时推送。"""
    async def gen():
        results: Dict[str, Any] = {"url": req.url, "findings": [], "flag": None}
        def on_progress(msg: str):
            pass  # 进度通过 on_found / findings 汇总
        def on_found(flag: str, src: str):
            results["flag"] = flag
            results["flag_src"] = src
        try:
            url_analyzer.auto_exploit(
                req.url, results,
                on_progress=lambda m: None,
                on_found=on_found)
            yield f"data: {json.dumps({'type': 'done', 'data': results}, ensure_ascii=False)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)}, ensure_ascii=False)}\n\n"
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
    import webbrowser
    port = int(os.environ.get("YANGWEB_PORT", "8765"))
    url = f"http://127.0.0.1:{port}"
    print(f"Yang-Web v4.0 启动: {url}")
    print("按 Ctrl+C 停止服务 (浏览器可关闭)")
    # 延迟打开浏览器，等服务就绪
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

if __name__ == "__main__":
    main()
