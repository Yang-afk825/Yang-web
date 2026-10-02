# -*- coding: utf-8 -*-
"""CLI 入口 — Yang-Web 命令行界面.

子命令:
    decode   智能链式解码
    encode   编码文本
    ssti     SSTI Payload 生成
    sqli     SQL 注入 Payload
    lfi      路径遍历 / 文件包含 Payload
    ssrf     SSRF Payload
    xss      XSS Payload
    rce      命令注入 Payload
    php      PHP 技巧 Payload
    hashid   识别 Hash 类型
    jwt      JWT 解析 / 攻击
    scan     目录扫描 (离线词库)
    scripts  内嵌 CTF 脚本库 (41 个脚本)
    solve    一键智能解题（题型识别 → 路径推荐 → 自动尝试）
    crypto   RSA / 现代密码学攻击引擎
    misc     20+ 常见密码类型知识库（编码/解码/参考图）

管道示例:
    yang-web decode "ZmxhZ3t0ZXN0fQ==" --raw | yang-web solve
    yang-web decode --raw "$(cat secret.txt)" | yang-web crypto --raw
"""
import argparse
import sys
import json
import os
import re

from ..core.utils import banner, bold, red, green, yellow, blue, magenta, cyan, dim
from ..core.decoder import (
    chain_decode, brute_decode, detect_encoding,
    DECODERS, ENCODING_DETECTORS,
)
from ..core.hashid import identify as hash_identify
from ..core.triage import triage, parse_rsa_params
from ..core.crypto_attack import RSA_ATTACKS, attack_fermat, solve_rsa_auto
from ..core.jwt import (
    decode_jwt, analyze_jwt, none_attack,
    brute_jwt, BUILTIN_WORDLIST, forge_hs256,
)
from ..payloads import ssti as _ssti_mod
from ..payloads import sqli as _sqli_mod
from ..payloads import lfi as _lfi_mod
from ..payloads import ssrf as _ssrf_mod
from ..payloads import xss as _xss_mod
from ..payloads import php as _php_mod
from ..payloads import upload as _upload_mod
from ..core.misc_crypto import (
    CIPHER_TYPES, list_ciphers, search_ciphers, get_cipher,
    get_image_path, get_categories, encode as mc_encode, decode as mc_decode,
)
from ..scripts import (
    list_scripts, search_scripts, get_script, get_script_path,
    run_script, CATEGORIES,
    check_all_deps, get_missing_deps, install_all_missing,
    install_deps_for_script,
)

# Aliases for function-level use
ssti = _ssti_mod
sqli = _sqli_mod
lfi = _lfi_mod
ssrf = _ssrf_mod
xss = _xss_mod
php = _php_mod
upload = _upload_mod
lfi = _lfi_mod
ssrf = _ssrf_mod
xss = _xss_mod
php = _php_mod

# RCE Payloads are defined inline (avoid Windows Defender false positive)



# 重导出全部原子模块符号（保持 `yang_web.cli` 的对外契约不变）
from ._codec import (print_json, cmd_decode, cmd_encode, cmd_hashid, cmd_jwt,
                     cmd_misc, cmd_crypto, _to_int)
from ._web import (cmd_ssti, cmd_sqli, cmd_lfi, cmd_ssrf_cmd, cmd_xss_cmd,
                   cmd_rce_cmd, cmd_php_cmd, cmd_upload, cmd_scan,
                   ALL_EXTENSIONS, CASE_VARIANTS, DOUBLE_EXT, NTFS_BYPASS,
                   _cmd_upload_analyze)
from ._solve import (cmd_scripts, _KIND_ICON, _solve_attempt, cmd_solve)
from ._entry import build_parser, main
