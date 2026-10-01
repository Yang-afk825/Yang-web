# -*- coding: utf-8 -*-
"""RSA 攻击工具箱 —— 兼容入口。

实现已**上提为引擎** ``yang_web.core.crypto_attack``，本文件只保留脚本形式与
命令行调用方式，供旧有调用方与 ``scripts`` 脚本库无缝过渡。

上提的原因：独立脚本只能被手动运行，无法被自动解题编排、CLI 或 GUI 面板复用。
新代码请直接 ``from yang_web.core.crypto_attack import solve_rsa``。

命令行用法::

    python rsa_toolkit.py --n N --e 3 --c C
    python rsa_toolkit.py --n N --e1 3 --e2 5 --c1 C1 --c2 C2   # 共模
    python rsa_toolkit.py --p P --q Q --e 65537 --c C            # 已知因子
"""
from __future__ import annotations

import os
import sys

# 允许脚本被独立执行（此时项目根不在 sys.path 上）
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from yang_web.core.crypto_attack import (  # noqa: E402
    RSA_ATTACKS,
    attack_broadcast,
    attack_common_modulus,
    attack_fermat,
    attack_low_exponent,
    attack_small_e,
    attack_wiener,
    crt,
    egcd,
    int_to_str,
    iroot,
    isqrt,
    modinv,
    rsa_decrypt,
    solve_rsa,
    str_to_int,
)

__all__ = [
    "egcd", "modinv", "crt", "int_to_str", "str_to_int", "isqrt", "iroot",
    "rsa_decrypt", "attack_low_exponent", "attack_small_e",
    "attack_common_modulus", "attack_wiener", "attack_fermat",
    "attack_broadcast", "solve_rsa", "RSA_ATTACKS", "main",
]


def _parse_args(argv: list) -> dict:
    """把 ``--key value`` 解析为关键字参数；数值自动转 int。"""
    kwargs = {}
    i = 0
    while i < len(argv):
        token = argv[i]
        if token.startswith("--"):
            key = token[2:]
            raw = argv[i + 1] if i + 1 < len(argv) else ""
            try:
                kwargs[key] = int(raw)
            except ValueError:
                kwargs[key] = raw
            i += 2
        else:
            i += 1
    return kwargs


def main(argv=None) -> int:
    """命令行入口：自动尝试所有可行的 RSA 攻击。"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("RSA Attack Toolkit — yang_web.core.crypto_attack")
        print("用法: python rsa_toolkit.py --n N --e E --c C")
        print()
        for name, (desc, params) in RSA_ATTACKS.items():
            print(f"  {name:16} {desc}   参数: {', '.join(params)}")
        return 0

    result = solve_rsa(**_parse_args(argv))
    if not result["success"]:
        tried = ", ".join(result["tried"]) or "(参数不足，未触发任何攻击)"
        print(f"未命中。已尝试: {tried}")
        return 1

    for name, value in result["results"].items():
        print(f"[{name}] {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
