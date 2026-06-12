# -*- coding: utf-8 -*-
"""依赖管理 — 检测 / 安装脚本所需第三方库."""

from __future__ import annotations

import importlib
import subprocess
import sys
from typing import List, Dict, Tuple, Set

from .registry import SCRIPTS


def collect_all_deps() -> Set[str]:
    """收集所有脚本需要的依赖包名."""
    deps = set()
    for meta in SCRIPTS.values():
        for dep in meta["deps"]:
            deps.add(_pip_name(dep))
    return deps


def _pip_name(dep: str) -> str:
    mapping = {
        "py3base92": "py3base92", "base36": "base36", "base58": "base58",
        "base62": "base62", "base91": "base91", "requests": "requests",
        "paramiko": "paramiko", "scapy": "scapy", "pyautogui": "pyautogui",
        "gmssl": "gmssl",
    }
    return mapping.get(dep, dep)


def _import_name(dep: str) -> str:
    return _pip_name(dep)


def check_dep(dep: str) -> bool:
    try:
        importlib.import_module(_import_name(dep))
        return True
    except ImportError:
        return False


def check_all_deps() -> Dict[str, Dict]:
    results = {}
    for key, meta in SCRIPTS.items():
        if not meta["deps"]:
            continue
        dep_list = []
        for dep in meta["deps"]:
            dep_list.append({"name": dep, "installed": check_dep(dep)})
        results[key] = {
            "meta": meta,
            "deps": dep_list,
            "all_ok": all(d["installed"] for d in dep_list),
        }
    return results


def get_missing_deps() -> Set[str]:
    missing = set()
    for meta in SCRIPTS.values():
        for dep in meta["deps"]:
            if not check_dep(dep):
                missing.add(_pip_name(dep))
    return missing


def install_dep(dep: str) -> Tuple[bool, str]:
    pip_name = _pip_name(dep)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name],
            capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace",
        )
        if result.returncode == 0:
            if check_dep(dep):
                return True, f"{dep} installed"
            return False, f"{dep} pip ok but import failed"
        err = result.stderr.strip().split("\n")[-1] if result.stderr else "unknown"
        return False, f"{dep}: {err}"
    except subprocess.TimeoutExpired:
        return False, f"{dep} timeout"
    except Exception as e:
        return False, f"{dep}: {e}"


def install_all_missing() -> List[Dict]:
    results = []
    for dep in sorted(get_missing_deps()):
        ok, msg = install_dep(dep)
        results.append({"dep": dep, "success": ok, "message": msg})
    return results


def install_deps_for_script(key: str) -> List[Dict]:
    meta = SCRIPTS.get(key)
    if not meta:
        return [{"dep": key, "success": False, "message": f"not found: {key}"}]
    results = []
    for dep in meta["deps"]:
        if not check_dep(dep):
            ok, msg = install_dep(dep)
            results.append({"dep": dep, "success": ok, "message": msg})
    return results


def get_scripts_by_dep(dep: str) -> List[str]:
    return [meta["title"] for key, meta in SCRIPTS.items() if dep in meta["deps"]]
