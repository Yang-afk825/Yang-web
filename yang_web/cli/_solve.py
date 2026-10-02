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




# ═══════════════════════════════════════════════════════════
#  脚本库子命令
# ═══════════════════════════════════════════════════════════

def cmd_scripts(args):
    """内置脚本库命令."""
    # 依赖检查
    if getattr(args, 'check_deps', False):
        status = check_all_deps()
        if not status:
            print(green("\n[依赖] all scripts are zero-dependency"))
            return
        print(bold(f"\n[依赖] check result ({len(status)} scripts with deps):"))
        for key, info in status.items():
            ok = green("OK") if info["all_ok"] else red("MISS")
            print(f"\n  {bold(info['meta']['title'])}  {ok}")
            for d in info["deps"]:
                icon = green("  v") if d["installed"] else red("  x")
                print(f"    {icon} {d['name']}")
        return

    # 安装依赖
    if getattr(args, 'install_deps', None):
        if args.install_deps == "all":
            missing = get_missing_deps()
            if not missing:
                print(green("\n[依赖] all deps installed"))
                return
            print(bold(f"\n[依赖] installing {len(missing)} pkgs: {', '.join(sorted(missing))}"))
            print()
            results = install_all_missing()
            for r in results:
                icon = green("v") if r["success"] else red("x")
                print(f"  {icon} {r['dep']}: {r['message']}")
        else:
            key = args.install_deps
            meta = get_script(key)
            if not meta:
                print(red(f"\n   script not found: {key}"))
                return
            if not meta["deps"]:
                print(green(f"\n[依赖] '{meta['title']}' is zero-dependency"))
                return
            print(bold(f"\n[依赖] installing '{meta['title']}': {', '.join(meta['deps'])}"))
            print()
            results = install_deps_for_script(key)
            for r in results:
                icon = green("v") if r["success"] else red("x")
                print(f"  {icon} {r['dep']}: {r['message']}")
        return

    if args.search:
        results = search_scripts(args.search)
        if not results:
            print(yellow(f"\n   未找到匹配 '{args.search}' 的脚本"))
            return
        print(bold(f"\n[脚本] 搜索 '{args.search}' 结果 ({len(results)} 个):"))
        for key, meta in results:
            cat_icon = CATEGORIES.get(meta["category"], "?")
            print(f"\n  {bold(meta['title'])}  {dim(cat_icon)}")
            print(f"  {dim('|')}  {meta['description']}")
            print(f"  {dim('|')}  {cyan('用法:')} {meta['usage']}")
            if meta["deps"]:
                print(f"  {dim('|')}  {yellow('依赖:')} {', '.join(meta['deps'])}")
        return

    if args.run:
        key = args.run
        meta = get_script(key)
        if not meta:
            results = search_scripts(key)
            if len(results) == 1:
                key, meta = results[0]
            elif len(results) > 1:
                print(yellow(f"\n   多个匹配 '{key}', 请指定:"))
                for k, m in results:
                    print(f"     {cyan(k)}")
                return
            else:
                print(red(f"\n   未找到脚本: {key}"))
                return

        script_args = args.args.split() if args.args else []
        print(bold(f"\n[运行] {cyan(meta['title'])}"))
        print(f"  {dim('描述:')} {meta['description']}")
        print(f"  {dim('路径:')} {get_script_path(key)}")
        print()
        result = run_script(key, args=script_args)
        if result["stdout"]:
            print(result["stdout"])
        if result["stderr"]:
            print(red(result["stderr"]))
        if result["success"]:
            print(green(f"\n  [OK] 脚本执行成功"))
        else:
            print(red(f"\n  [FAIL] 脚本执行失败 (exit={result['exit_code']})"))
        return

    category = args.category
    results = list_scripts(category=category)

    if category:
        cat_name = CATEGORIES.get(category, category)
        print(bold(f"\n[脚本] {cat_name} - {len(results)} 个脚本"))
    else:
        print(bold(f"\n[脚本] 内嵌 CTF 脚本库 - 共 {len(results)} 个脚本"))
        print(dim("   yang-web scripts --search <kw>      search"))
        print(dim("   yang-web scripts --run <name>       run"))
        print(dim("   yang-web scripts --category <cat>   filter"))
        print(dim("   yang-web scripts --check-deps        check deps"))
        print(dim("   yang-web scripts --install-deps      install deps"))
        print(dim("   yang-web solve <input>               auto-solve"))
        print()

    cats_shown = {}
    for key, meta in results:
        cat = meta["category"]
        if cat not in cats_shown:
            cats_shown[cat] = []
        cats_shown[cat].append((key, meta))

    for cat in CATEGORIES:
        if cat not in cats_shown:
            continue
        print(f"\n  {bold(CATEGORIES[cat])} ({len(cats_shown[cat])} 个)")
        for key, meta in cats_shown[cat]:
            deps_str = f" {yellow('[需: ' + ','.join(meta['deps']) + ']')}" if meta["deps"] else ""
            print(f"    {dim('>')} {bold(meta['title'])}{deps_str}")
            print(f"      {dim(meta['description'])}")
            print(f"      {dim('运行:')} {cyan('yang-web scripts --run ' + repr(key))}")


# ═══════════════════════════════════════════════════════════
#  智能解题 —— 先识别题型, 再给路径
# ═══════════════════════════════════════════════════════════

_KIND_ICON = {
    "rsa": "🧮", "hash": "#", "encoded": "🔤", "ciphertext": "🔐",
    "plaintext": "🏁", "url": "🌐", "text": "📄", "unknown": "❓",
}


def _solve_attempt(text, report):
    """对识别结果执行**安全的离线**首选动作, 返回 [(label, ok, output)]。

    只做本地计算, 绝不发起网络请求 —— 涉及目标的路径 (url / scan) 仅作建议列出。
    """
    attempts = []
    kind = report["kind"]

    if kind == "encoded" and text:
        chain = chain_decode(text)
        if chain:
            steps = " → ".join(step[0] for step in chain)
            attempts.append((f"链式解码 ({steps})", True, chain[-1][2]))
        else:
            attempts.append(("链式解码", False, "未能自动解码, 可试 --brute"))
        return attempts

    if kind == "hash" and text:
        results = hash_identify(re.sub(r"\s+", "", text))
        if results:
            listing = ", ".join(f"{algo}[{cat}]" for algo, cat, _ in results[:6])
            attempts.append((f"Hash 识别 ({len(results)} 个匹配)", True, listing))
        else:
            attempts.append(("Hash 识别", False, "未匹配已知散列算法"))
        return attempts

    if kind == "rsa" and text:
        params = {
            key: value for key, value in parse_rsa_params(text).items()
            if key in ("n", "e", "c", "p", "q", "e1", "e2", "c1", "c2")
        }
        if not params:
            attempts.append(("RSA 参数解析", False,
                             "未能解析出 n / p —— 需要形如 n = <大整数> 的输入"))
            return attempts
        r = solve_rsa_auto(**params)
        if r["success"]:
            plain = r["results"].get("plaintext")
            attempts.append((f"RSA 自动攻击 (命中 {', '.join(r['results'])})", True,
                             plain if plain is not None else str(r["results"])))
        else:
            attempts.append((f"RSA 自动攻击 (尝试 {', '.join(r['tried']) or '无可行攻击'})", False,
                             "未命中 —— 可能需要已知 p/q、公钥文件或更多密文组"))
        return attempts

    return attempts


def cmd_solve(args):
    """一键智能解题 —— 先识别题型, 再给路径, 并自动尝试首选离线动作."""
    text = args.input
    file_path = None
    if args.file:
        file_path = args.file
        if not os.path.isfile(file_path):
            print(red(f"文件不存在: {file_path}"))
            return
    elif not text and not sys.stdin.isatty():
        text = sys.stdin.read().strip()

    if not text and not file_path:
        print(red("请提供输入文本或文件路径"))
        print(dim("  yang-web solve <文本>"))
        print(dim("  yang-web solve --file <文件路径>"))
        print(dim("  echo <文本> | yang-web solve"))
        return

    plan_only = getattr(args, "plan", False)
    as_json = getattr(args, "json", False)

    report = triage(text=text or "", file_path=file_path)

    if as_json:
        payload = {"triage": report}
        if not plan_only:
            payload["attempts"] = [
                {"label": label, "ok": ok, "output": output}
                for label, ok, output in _solve_attempt(text or "", report)
            ]
        print_json(payload)
        return

    print(bold("\n[解题] 题型识别" + ("（--plan 不执行）" if plan_only else "")))
    icon = _KIND_ICON.get(report["kind"], "•")
    print(f"  {dim('判断:')} {icon} {green(report['kind'])}  {dim('置信度')} {report['confidence']}%")
    print(f"  {dim('依据:')} {report['evidence']}")

    if report["paths"]:
        print(bold("\n[路径] 推荐动作:"))
        for i, path in enumerate(report["paths"], 1):
            print(f"  [{i}] {cyan(path['tool']):10s} {path['hint']}")
            if path["cmd"]:
                print(f"      {dim('$ ' + path['cmd'])}")

    if report["alternatives"]:
        print(bold("\n[其他可能]:"))
        for alt in report["alternatives"][:3]:
            print(f"  {dim('•')} {alt['kind']} ({alt['confidence']}%) — {alt['evidence']}")

    if plan_only:
        return

    attempts = _solve_attempt(text or "", report)
    if attempts:
        print(bold("\n[尝试] 自动执行首选动作:"))
        for label, ok, output in attempts:
            print(f"  {green('v') if ok else yellow('-')} {label}")
            if output:
                for line in str(output).strip().split("\n")[:8]:
                    print(f"      {dim(line)}")
