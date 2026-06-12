# -*- coding: utf-8 -*-
"""CTF 脚本运行器 — 动态加载执行脚本."""

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
    """执行指定脚本并返回结果.

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
                "stderr": f"脚本 '{key}' 是 zip 压缩包，请先解压到 scripts/ 目录",
                "exit_code": 1,
            }
        return {
            "success": False,
            "stdout": "",
            "stderr": f"未找到脚本: {key}",
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
            "stderr": f"脚本执行超时 (300s): {key}",
            "exit_code": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"执行异常: {e}",
            "exit_code": -1,
        }


def run_script_live(key: str, args: Optional[list] = None):
    """直接在前台执行脚本（输出到终端）."""
    path = get_script_path(key)
    if not path:
        print(f"未找到脚本: {key}")
        sys.exit(1)

    cmd = [sys.executable, path]
    if args:
        cmd.extend(args)

    os.execv(sys.executable, cmd)


def auto_solve(input_data: str, input_type: str = "text") -> Dict[str, Any]:
    """一键智能解题: 根据输入类型自动尝试相关脚本.

    Args:
        input_data: 输入数据 (文本内容或文件路径)
        input_type: 输入类型 (text / file / apk)

    Returns:
        {"results": [...], "tried": int, "successes": int}
    """
    results = []
    tried = 0
    successes = 0

    # 根据输入类型筛选脚本
    if input_type == "text":
        # 先尝试所有解码类脚本
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
        # 文件类：尝试隐写、取证相关脚本
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
