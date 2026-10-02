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


def print_json(obj, pretty=True):
    """输出 JSON 格式."""
    indent = 2 if pretty else None
    print(json.dumps(obj, indent=indent, ensure_ascii=False, default=str))


def cmd_decode(args):
    """智能解码命令."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()
    raw = getattr(args, "raw", False)

    if not text:
        print(red("错误: 请提供要解码的文本"))
        return

    if args.brute:
        # 尝试所有解码器
        results = brute_decode(text)
        if raw:
            # 管道模式: 每行 "<编码>\t<结果>", 无结果则静默退出
            for enc_id, enc_desc, result, _readable in results:
                print(f"{enc_id}\t{result}")
            return
        print(bold("\n📋 输入:"))
        print(f"  {text[:200]}{'...' if len(text) > 200 else ''}")
        print()
        print(bold("🔍 尝试所有解码器:"))
        if not results:
            print(yellow("  ── 无结果"))
            return
        for enc_id, enc_desc, result, readable in results:
            marker = green(readable) if "✓" in readable else dim(readable)
            print(f"  {cyan(enc_id):12s} {dim('→')} {marker} {dim('→')} {result[:100]}")
        return

    if args.manual:
        # 指定编码类型手动解码
        enc_id = args.manual
        if enc_id not in DECODERS:
            print(red(f"不支持的编码: {enc_id}"))
            print(yellow(f"可用: {', '.join(DECODERS.keys())}"))
            return
        decoder = DECODERS[enc_id][0]
        result = decoder(text)
        if raw:
            print(result)
            return
        print(bold(f"\n🔓 使用 {cyan(enc_id)} 解码:"))
        print(f"  {result}")
        return

    # 自动链式解码
    chain = chain_decode(text)

    if raw:
        # 管道模式: 只输出最终明文; 解不出来就原样透传, 保证管道不断流
        print(chain[-1][2] if chain else text)
        return

    print(bold("\n📋 输入:"))
    print(f"  {text[:200]}{'...' if len(text) > 200 else ''}")
    print()
    print(bold("🔓 智能链式解码:"))

    if not chain:
        print(yellow("  ── 未能识别编码, 尝试 --brute 暴力尝试所有解码器"))
        # 显示检测结果
        detections = detect_encoding(text)
        if detections:
            print(bold("\n📊 检测到的可能的编码:"))
            for enc_id, desc, conf in detections[:5]:
                print(f"  {cyan(enc_id):12s} {desc:20s} 置信度: {conf}%")
        return

    # 显示解码链
    for i, (enc_id, enc_desc, result) in enumerate(chain, 1):
        print(f"\n  {bold(f'Step {i}:')} {green(enc_id)} ({dim(enc_desc)})")
        preview = result[:300] + ("..." if len(result) > 300 else "")
        print(f"  {dim('→')} {preview}")

    print(f"\n{bold('✅ 最终结果:')}")
    final = chain[-1][2]
    print(f"  {green(final)}")


def cmd_encode(args):
    """编码命令."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()

    if args.list:
        print(bold("📋 可用编码类型:"))
        for enc_id, (_, encoder) in DECODERS.items():
            print(f"  {cyan(enc_id):12s} {dim(encoder.__doc__ or '')}")
        return

    enc_id = args.type
    if enc_id not in DECODERS:
        print(red(f"不支持的编码类型: {enc_id}"))
        print(yellow(f"可用: {', '.join(DECODERS.keys())}"))
        return

    _, encoder = DECODERS[enc_id]
    try:
        result = encoder(text)
        if getattr(args, "raw", False):
            print(result)
            return
        print(bold(f"\n🔒 {enc_id} 编码结果:"))
        print(f"  {result}")
    except Exception as e:
        print(red(f"编码失败: {e}"))


def cmd_hashid(args):
    """Hash 识别命令."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()

    if not text:
        print(red("错误: 请提供 hash 值"))
        return

    print(bold(f"\n🔍 Hash: {text[:80]}{'...' if len(text) > 80 else ''}"))
    print(f"  长度: {len(text)} 字符")

    results = hash_identify(text)
    if results:
        print(bold(f"\n📊 可能的算法 ({len(results)} 个匹配):"))
        for algo, category, _ in results:
            print(f"  {dim('•')} {yellow(algo)} {dim(f'[{category}]')}")
    else:
        print(yellow("\n  ── 未能识别该 Hash 类型"))


def cmd_jwt(args):
    """JWT 工具命令."""
    token = args.token
    if not token:
        token = sys.stdin.read().strip()

    if not token:
        print(red("错误: 请提供 JWT Token"))
        return

    if args.none:
        new_token, payload = none_attack(token)
        print(bold("\n⚠️ None 算法攻击:"))
        print(f"\n  {bold('新 Token (alg=none):')}")
        print(f"  {green(new_token)}")
        print(f"\n  {bold('Payload:')}")
        print_json(payload)
        return

    if args.brute:
        print(bold("\n🔑 弱密钥爆破 (内建词库)..."))
        results = brute_jwt(token, BUILTIN_WORDLIST)
        if results:
            print(green(f"\n  ✅ 找到 {len(results)} 个匹配!"))
            for secret, new_token in results:
                print(f"  密钥: {bold(secret)}")
        else:
            print(yellow("  ── 内建弱密码库未匹配, 尝试 --wordlist 指定字典"))

    if args.forge:
        if not args.secret:
            print(red("伪造签名需要 --secret 参数"))
            return
        new_token = forge_hs256(token, args.secret)
        print(bold(f"\n🔏 伪造的 JWT:"))
        print(f"  {new_token}")
        return

    # 默认: 分析
    analysis = analyze_jwt(token)
    if "error" in analysis:
        print(red(f"错误: {analysis['error']}"))
        return

    print(bold("\n🔐 JWT 分析:"))
    print(f"\n  {bold('Header:')}")
    print_json(analysis["header"])

    print(f"\n  {bold('Payload:')}")
    print_json(analysis["payload"])

    print(f"\n  {bold('签名:')} {analysis['signature']}")
    print(f"  {bold('算法:')} {cyan(analysis['algorithm'])}")

    if analysis.get("info"):
        print(f"\n  {dim('ℹ ' + analysis['info'])}")

    if analysis["warnings"]:
        print(bold(f"\n  ⚠️ 风险警告:"))
        for w in analysis["warnings"]:
            print(f"  {yellow(w)}")

    if analysis["tips"]:
        print(bold(f"\n  💡 攻击建议:"))
        for t in analysis["tips"]:
            print(f"  {green(t)}")

    print(f"\n{dim('尝试: yang_web jwt --none 进行 None 算法攻击')}")


# ═══════════════════════════════════════════════════════════
#  Misc Crypto 子命令
# ═══════════════════════════════════════════════════════════

def cmd_misc(args):
    """Misc Crypto 知识库命令."""
    # --list: 列出所有密码类型
    if args.category or (not args.search and not args.id and not args.encode and not args.decode):
        ciphers = list_ciphers(args.category)
        if args.category:
            print(bold(f"\n📂 分类: {args.category} ({len(ciphers)} 种)"))
        else:
            cats = get_categories()
            print(bold(f"\n🔐 Misc Crypto 知识库 — {len(ciphers)} 种密码类型"))
            print(dim(f"  分类: {', '.join(cats)}"))
            print(dim(f"  用法: yang-web misc --id <类型>      查看详情"))
            print(dim(f"        yang-web misc --encode <类型> -t 明文  编码"))
            print(dim(f"        yang-web misc --decode <类型> -t 密文  解码"))
            print(dim(f"        yang-web misc --search <关键词>    搜索\n"))

        for c in ciphers:
            tag = green("🔧") if c.get("encode") else blue("📖")
            img = dim(" [图]") if c.get("image") else ""
            print(f"  {tag} {bold(c['name']):12s} {dim('(')}{c['id']:20s}{dim(')')} {c['category']}{img}")

        if not args.category:
            print(dim(f"\n  共 {len(ciphers)} 种 — 使用 --category <分类> 筛选"))
        return

    # --search: 搜索
    if args.search:
        results = search_ciphers(args.search)
        if not results:
            print(yellow(f"未找到 '{args.search}' 相关密码类型"))
            return
        print(bold(f"\n🔍 搜索 '{args.search}' → {len(results)} 条结果:\n"))
        for r in results:
            print(f"  {bold(r['name'])} ({r['id']}) — {r['description']}")
        return

    # --id: 查看详情
    if args.id:
        info = get_cipher(args.id)
        if not info:
            print(red(f"未知密码类型: {args.id}"))
            print(dim("使用 yang-web misc 查看所有可用类型"))
            return
        print(bold(f"\n📖 {info['name']} ({args.id})"))
        print(f"  分类: {info['category']}")
        print(f"  别名: {', '.join(info.get('aliases', []))}")
        print(f"  描述: {info['description']}")
        if info.get("features"):
            print(f"  特征: {', '.join(info['features'])}")
        if info.get("encode"):
            print(f"  {green('✓')} 支持编码/解码")
        else:
            print(f"  {blue('ℹ')} 仅提供参考图")
        img = get_image_path(args.id)
        if img:
            print(f"  🖼 参考图: {img}")
        return

    # --encode: 编码
    if args.encode:
        if not args.text:
            print(red("请提供 -t/--text 参数"))
            return
        key = args.key or ""
        result = mc_encode(args.encode, args.text, key=key)
        print(bold(f"\n🔒 {args.encode} 编码:"))
        print(f"  {green(result)}")
        return

    # --decode: 解码
    if args.decode:
        if not args.text:
            print(red("请提供 -t/--text 参数"))
            return
        key = args.key or ""
        result = mc_decode(args.decode, args.text, key=key)
        print(bold(f"\n🔓 {args.decode} 解码:"))
        print(f"  {green(result)}")
        return


def cmd_crypto(args):
    """RSA / 现代密码学攻击命令."""
    if getattr(args, "list", False):
        print(bold("\n🔐 RSA 攻击引擎 — 可用攻击"))
        for name, (desc, need) in RSA_ATTACKS.items():
            print(f"  {cyan(name):16s} {desc}")
            print(f"  {dim(' ' * 16 + '需要: ' + ', '.join(need))}")
        print(dim("\n用法:"))
        print(dim("  yang-web crypto --n <n> --e <e> --c <c>"))
        print(dim("  yang-web crypto --p <p> --q <q> --e <e> --c <c>"))
        print(dim("  yang-web crypto --fermat <n>"))
        print(dim("  yang-web crypto --broadcast --e <e> --n <n1,n2,..> --c <c1,c2,..>"))
        return

    as_json = getattr(args, "json", False)
    as_raw = getattr(args, "raw", False)

    # ── Fermat 单点分解 ──
    if getattr(args, "fermat", None):
        pair = attack_fermat(_to_int(args.fermat))
        if as_json:
            print_json({"fermat": {"p": pair[0], "q": pair[1]} if pair else None})
        elif pair:
            print(bold("\n🔓 Fermat 分解成功"))
            print(f"  p = {pair[0]}")
            print(f"  q = {pair[1]}")
        else:
            print(yellow("\n  ── Fermat 分解失败 (p、q 差距较大, 不是近似分解题)"))
        return

    n_raw = getattr(args, "n", None)
    c_raw = getattr(args, "c", None)
    e = _to_int(getattr(args, "e", None))

    # ── stdin: 从上游管道抓大整数, 依次视作 n、e、c ──
    if not any((n_raw, c_raw, e)) and not sys.stdin.isatty():
        nums = [int(x) for x in re.findall(r"\d+", sys.stdin.read())]
        if len(nums) >= 3:
            n_raw, e, c_raw = nums[0], nums[1], nums[2]
        elif len(nums) == 2:
            n_raw, e = nums
        elif len(nums) == 1:
            n_raw = nums[0]

    if getattr(args, "broadcast", False):
        moduli = [_to_int(x) for x in str(n_raw).split(",") if x.strip()]
        ciphers = [_to_int(x) for x in str(c_raw).split(",") if x.strip()]
        result = solve_rsa_auto(broadcast_cs=ciphers, broadcast_ns=moduli, broadcast_e=e or 3)
    else:
        result = solve_rsa_auto(
            n=_to_int(n_raw), e=e, c=_to_int(c_raw),
            p=_to_int(getattr(args, "p", None)), q=_to_int(getattr(args, "q", None)),
            e1=_to_int(getattr(args, "e1", None)), e2=_to_int(getattr(args, "e2", None)),
            c1=_to_int(getattr(args, "c1", None)), c2=_to_int(getattr(args, "c2", None)),
        )

    if as_json:
        print_json(result)
        return

    if as_raw:
        plain = result["results"].get("plaintext")
        if plain is not None:
            print(plain)
        return

    print(bold("\n🔐 RSA 攻击结果"))
    print(f"  {dim('已尝试:')} {', '.join(result['tried']) or '(无可行攻击)'}")

    if not result["success"]:
        print(yellow("\n  ── 未命中任何攻击"))
        print(dim("  可能原因: 需要已知 p/q、公钥文件, 或密文不止一组"))
        print(dim("  yang-web crypto --list   查看全部可用攻击"))
        return

    res = result["results"]
    if res.get("plaintext") is not None:
        print(green(f"\n  ✅ 明文: {res['plaintext']}"))
    for name, value in res.items():
        if name == "plaintext":
            continue
        if isinstance(value, dict):
            print(f"  {cyan(name):16s} " + ", ".join(f"{k}={v}" for k, v in value.items()))
        else:
            print(f"  {cyan(name):16s} {value}")


# ═══════════════════════════════════════════════════════════
#  RSA / 现代密码学攻击引擎
# ═══════════════════════════════════════════════════════════

def _to_int(value):
    """宽松整数解析: 空值 / 非法值一律当 0。"""
    if value is None or value == "":
        return 0
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0
