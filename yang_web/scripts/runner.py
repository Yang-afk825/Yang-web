"""CTF èæ¬è¿è¡å¨ â å¨æå è½½æ§è¡èæ¬."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import traceback
from typing import Optional, Dict, Any

from .registry import get_script, get_script_path, SCRIPTS

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_script(key: str, args: Optional[list] = None) -> Dict[str, Any]:
    """æ§è¡æå®èæ¬å¹¶è¿åç»æ.

    Returns:
        {"success": bool, "stdout": str, "stderr": str, "exit_code": int}
    """
    path = get_script_path(key)
    if not path:
        meta = get_script(key)
        if meta and meta["name"].endswith(".zip"):
            return {
                "success": False,
                "stdout": "",
                "stderr": f"èæ¬ '{key}' æ¯ zip åç¼©åï¼è¯·åè§£åå° scripts/ ç®å½",
                "exit_code": 1,
            }
        return {
            "success": False,
            "stdout": "",
            "stderr": f"æªæ¾å°èæ¬: {key}",
            "exit_code": 1,
        }

    cmd = [sys.executable, path]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.path.dirname(path),
            encoding="utf-8",
            errors="replace",
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"èæ¬æ§è¡è¶æ¶ (300s): {key}",
            "exit_code": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"æ§è¡å¼å¸¸: {e}",
            "exit_code": -1,
        }


def run_script_live(key: str, args: Optional[list] = None):
    """ç´æ¥å¨åå°æ§è¡èæ¬ï¼è¾åºå°ç»ç«¯ï¼."""
    path = get_script_path(key)
    if not path:
        print(f"æªæ¾å°èæ¬: {key}")
        sys.exit(1)

    cmd = [sys.executable, path]
    if args:
        cmd.extend(args)

    os.execv(sys.executable, cmd)


def auto_solve(input_data: str, input_type: str = "text") -> Dict[str, Any]:
    """ä¸é®æºè½è§£é¢: æ ¹æ®è¾å¥ç±»åèªå¨å°è¯ç¸å³èæ¬.

    Args:
        input_data: è¾å¥æ°æ® (ææ¬åå®¹ææä»¶è·¯å¾)
        input_type: è¾å¥ç±»å (text / file / apk)

    Returns:
        {"results": [...], "tried": int, "successes": int}
    """
    results = []
    tried = 0
    successes = 0

    # æ ¹æ®è¾å¥ç±»åç­éèæ¬
    if input_type == "text":
        # åå°è¯ææè§£ç ç±»èæ¬
        priority_categories = ["crypto"]
        for key, meta in SCRIPTS.items():
            if meta["input_type"] != "text":
                continue
            if meta["category"] not in priority_categories:
                continue
            tried += 1
            result = run_script(key)
            entry = {
                "script": key,
                "title": meta["title"],
                "category": meta["category"],
                "success": result["success"],
                "output": result["stdout"][:2000] if result["success"] else result["stderr"][:500],
            }
            if result["success"]:
                successes += 1
            results.append(entry)
    elif input_type == "file":
        # æä»¶ç±»ï¼å°è¯éåãåè¯ç¸å³èæ¬
        for key, meta in SCRIPTS.items():
            if meta["input_type"] not in ("file", "pcap"):
                continue
            tried += 1
            result = run_script(key, args=[input_data])
            entry = {
                "script": key,
                "title": meta["title"],
                "category": meta["category"],
                "success": result["success"],
                "output": result["stdout"][:2000] if result["success"] else result["stderr"][:500],
            }
            if result["success"]:
                successes += 1
            results.append(entry)

    return {
        "results": results,
        "tried": tried,
        "successes": successes,
    }
