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


from ._codec import (print_json, cmd_decode, cmd_encode, cmd_hashid, cmd_jwt,
                     cmd_misc, cmd_crypto, _to_int)
from ._web import (cmd_ssti, cmd_sqli, cmd_lfi, cmd_ssrf_cmd, cmd_xss_cmd,
                   cmd_rce_cmd, cmd_php_cmd, cmd_upload, cmd_scan,
                   ALL_EXTENSIONS, CASE_VARIANTS, DOUBLE_EXT, NTFS_BYPASS,
                   _cmd_upload_analyze)
from ._solve import (cmd_scripts, _KIND_ICON, _solve_attempt, cmd_solve)



# ═══════════════════════════════════════════════════════════
#  主入口
# ═══════════════════════════════════════════════════════════

def build_parser():
    """构建命令行解析器."""
    parser = argparse.ArgumentParser(
        prog="yang_web",
        description="Yang-Web — 离线 CTF Web 瑞士军刀",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  yang_web decode "ZmxhZ3t0ZXN0fQ=="      智能链式解码
  yang_web decode --brute "dGVzdA=="      暴力尝试所有解码器
  yang_web decode "ZmxhZ3t0ZXN0fQ==" --raw  管道模式: 只输出明文
  yang_web encode base64 "hello"          编码
  yang_web ssti --exploit --engine "Jinja2"  SSTI 利用 Payload
  yang_web sqli --db MySQL                 SQL 注入 Payload
  yang_web lfi --traversal                 路径遍历 Payload
  yang_web hashid "5d41402abc4b2a76b9719d911017c592"
  yang_web jwt "eyJ..."                   JWT 分析
  yang_web php --magic                     PHP Magic Hash
  yang_web solve "ZmxhZ3t0ZXN0fQ=="       先识别题型, 再给路径并自动试
  yang_web solve --file challenge.png      按文件魔数识别
  yang_web crypto --n <n> --e <e> --c <c>  RSA 攻击引擎
  yang_web crypto --list                   列出全部 RSA 攻击
  yang_web scan dir --search config        搜索敏感目录

管道:
  yang_web decode "ZmxhZ3t0ZXN0fQ==" --raw | yang_web solve
        """,
    )

    sub = parser.add_subparsers(dest="command", help="子命令")

    # ── decode ──
    p_decode = sub.add_parser("decode", help="智能解码 (自动检测编码 → 链式解码)")
    p_decode.add_argument("text", nargs="?", help="待解码文本 (或通过管道 stdin)")
    p_decode.add_argument("--brute", action="store_true", help="暴力尝试所有解码器")
    p_decode.add_argument("--manual", metavar="ENCODING", help="指定编码类型手动解码")
    p_decode.add_argument("--raw", action="store_true",
                          help="管道模式: 只输出最终明文 (解不出则原样透传)")

    # ── encode ──
    p_encode = sub.add_parser("encode", help="编码文本")
    p_encode.add_argument("type", nargs="?", help="编码类型 (如 base64/base32/hex/url)")
    p_encode.add_argument("text", nargs="?", help="待编码文本 (或通过管道 stdin)")
    p_encode.add_argument("--list", action="store_true", help="列出可用编码类型")
    p_encode.add_argument("--raw", action="store_true", help="管道模式: 只输出编码结果")

    # ── ssti ──
    p_ssti = sub.add_parser("ssti", help="SSTI Payload 生成")
    p_ssti.add_argument("--detect", action="store_true", help="显示检测 Payload")
    p_ssti.add_argument("--exploit", action="store_true", help="显示利用 Payload")
    p_ssti.add_argument("--engine", metavar="ENGINE", help="指定模板引擎")
    p_ssti.add_argument("--bypass", action="store_true", help="显示绕过过滤技巧")
    p_ssti.add_argument("--search", metavar="KW", help="搜索 Payload")
    p_ssti.add_argument("--list", action="store_true", help="列出支持引擎")

    # ── sqli ──
    p_sqli = sub.add_parser("sqli", help="SQL 注入 Payload")
    p_sqli.add_argument("--detect", action="store_true", help="显示检测 Payload")
    p_sqli.add_argument("--db", metavar="DB", help="指定数据库类型")
    p_sqli.add_argument("--category", metavar="CAT", help="检测类别")
    p_sqli.add_argument("--blind", action="store_true", help="显示盲注模板")
    p_sqli.add_argument("--search", metavar="KW", help="搜索 Payload")
    p_sqli.add_argument("--list", action="store_true", help="列出支持数据库")
    p_sqli.add_argument("--waf", type=str, nargs='?', const='all', metavar="CAT", help="SQL WAF 绕过技巧")

    # ── lfi ──
    p_lfi = sub.add_parser("lfi", help="LFI / Path Traversal Payload")
    p_lfi.add_argument("--traversal", action="store_true", help="路径遍历 Payload")
    p_lfi.add_argument("--files", action="store_true", help="敏感文件列表")
    p_lfi.add_argument("--php", action="store_true", help="PHP 伪协议")
    p_lfi.add_argument("--os", metavar="OS", help="操作系统 (Linux/Windows)")
    p_lfi.add_argument("--windows", action="store_true", help="显示 Windows 路径遍历")
    p_lfi.add_argument("--category", metavar="CAT", help="PHP 伪协议类别")

    # ── ssrf ──
    p_ssrf = sub.add_parser("ssrf", help="SSRF Payload")
    p_ssrf.add_argument("--cloud", metavar="PROVIDER", nargs="?", const="all", help="云元数据地址")
    p_ssrf.add_argument("--bypass", dest="bypass_ssrf", action="store_true", help="SSRF 绕过技巧")
    p_ssrf.add_argument("--ports", action="store_true", help="常见内网端口")

    # ── xss ──
    p_xss = sub.add_parser("xss", help="XSS Payload")
    p_xss.add_argument("--detect", dest="detect_xss", action="store_true", help="检测 Payload")
    p_xss.add_argument("--exfil", action="store_true", help="数据外传 Payload")
    p_xss.add_argument("--steal", metavar="URL", help="生成 Cookie 窃取器")
    p_xss.add_argument("--keylogger", metavar="URL", help="生成键盘记录器")
    p_xss.add_argument("--bypass", dest="bypass_xss", action="store_true", help="WAF 绕过 Payload")
    p_xss.add_argument("--category", metavar="CAT", help="绕过类别筛选")

    # ── rce ──
    p_rce = sub.add_parser("rce", help="命令注入 / RCE Payload")
    p_rce.add_argument("--shell", metavar="TYPE", help="反弹 Shell 类型")
    p_rce.add_argument("--ip", metavar="IP", help="攻击者 IP (--shell 时使用)")
    p_rce.add_argument("--port", metavar="PORT", type=int, help="攻击者端口 (--shell 时使用)")
    p_rce.add_argument("--list-shells", action="store_true", dest="list_shells", help="列出反弹 Shell 类型")
    p_rce.add_argument("--bypass", dest="bypass_rce", action="store_true", help="命令注入 Bypass 技巧")

    # ── php ──
    p_php = sub.add_parser("php", help="PHP 技巧 Payload")
    p_php.add_argument("--magic", nargs="?", const="all", help="Magic Hash")
    p_php.add_argument("--type-juggle", action="store_true", dest="type_juggle", help="弱类型比较")
    p_php.add_argument("--deserialize", action="store_true", help="反序列化技巧")
    p_php.add_argument("--waf-php", action="store_true", help="PHP RCE WAF 绕过技巧")
    p_php.add_argument("--rce", dest="rce_php", action="store_true", help="RCE Bypass 技巧")

        # ── upload ──
    p_upload = sub.add_parser("upload", help="文件上传 Payload")
    p_upload.add_argument("--ext", action="store_true", help="后缀名绕过")
    p_upload.add_argument("--mime", action="store_true", help="Content-Type 伪造")
    p_upload.add_argument("--content", action="store_true", help="图片马内容绕过")
    p_upload.add_argument("--parse", type=str, help="解析漏洞 (nginx/apache/iis/all)")
    p_upload.add_argument("--htaccess", action="store_true", help=".htaccess Payload")
    p_upload.add_argument("--userini", action="store_true", help=".user.ini Payload")
    p_upload.add_argument("--advanced", action="store_true", help="高级绕过技巧")
    p_upload.add_argument("--analyze", type=str, metavar="BLACKLIST", help="分析靶场黑名单 (如: php,php3,phtml)")

# ── hashid ──
    p_hashid = sub.add_parser("hashid", help="Hash 类型识别")
    p_hashid.add_argument("text", nargs="?", help="Hash 字符串 (或通过管道 stdin)")

    # ── jwt ──
    p_jwt = sub.add_parser("jwt", help="JWT 分析 / 攻击")
    p_jwt.add_argument("token", nargs="?", help="JWT Token (或通过管道 stdin)")
    p_jwt.add_argument("--none", action="store_true", help="None 算法攻击")
    p_jwt.add_argument("--brute", action="store_true", help="弱密钥爆破")
    p_jwt.add_argument("--forge", action="store_true", help="伪造签名")
    p_jwt.add_argument("--secret", metavar="KEY", help="签名密钥")
    p_jwt.add_argument("--wordlist", metavar="FILE", help="自定义字典路径")

    # ── scripts ──
    p_scripts = sub.add_parser("scripts", help="内嵌 CTF 脚本库")
    p_scripts.add_argument("--category", metavar="CAT", help="按分类筛选 (crypto/web/reverse/misc)")
    p_scripts.add_argument("--search", metavar="KW", help="搜索脚本")
    p_scripts.add_argument("--run", metavar="NAME", dest="run", help="Run script")
    p_scripts.add_argument("--args", metavar="ARGS", help="Args for script")
    p_scripts.add_argument("--check-deps", action="store_true", dest="check_deps",
                            help="Check dependency status")
    p_scripts.add_argument("--install-deps", metavar="NAME", nargs="?", const="all",
                            dest="install_deps",
                            help="Install deps (default: all, or script name)")

    # ── solve ──
    p_solve = sub.add_parser("solve", help="一键智能解题 (先识别题型, 再给路径)")
    p_solve.add_argument("input", nargs="?", help="输入文本 (编码串/密文等, 或通过管道 stdin)")
    p_solve.add_argument("--file", metavar="PATH", help="文件路径模式 (按魔数识别)")
    p_solve.add_argument("--plan", action="store_true", help="只识别并给出路径, 不执行")
    p_solve.add_argument("--json", action="store_true", help="结构化 JSON 输出")

    # ── crypto ──
    p_crypto = sub.add_parser("crypto", help="RSA / 现代密码学攻击引擎")
    p_crypto.add_argument("--n", metavar="N", help="模数 n (广播模式可用逗号分隔多组)")
    p_crypto.add_argument("--e", metavar="E", help="公钥指数 e")
    p_crypto.add_argument("--c", metavar="C", help="密文 c (广播模式可用逗号分隔多组)")
    p_crypto.add_argument("--p", metavar="P", help="素因子 p (已知分解)")
    p_crypto.add_argument("--q", metavar="Q", help="素因子 q (已知分解)")
    p_crypto.add_argument("--e1", metavar="E1", help="共模攻击: 第一个指数")
    p_crypto.add_argument("--e2", metavar="E2", help="共模攻击: 第二个指数")
    p_crypto.add_argument("--c1", metavar="C1", help="共模攻击: 第一组密文")
    p_crypto.add_argument("--c2", metavar="C2", help="共模攻击: 第二组密文")
    p_crypto.add_argument("--fermat", metavar="N", help="仅执行 Fermat 分解")
    p_crypto.add_argument("--broadcast", action="store_true", help="Håstad 广播攻击")
    p_crypto.add_argument("--list", action="store_true", help="列出所有可用攻击")
    p_crypto.add_argument("--json", action="store_true", help="结构化 JSON 输出")
    p_crypto.add_argument("--raw", action="store_true", help="管道模式: 只输出明文")

    # ── misc ──
    p_misc = sub.add_parser("misc", help="Misc Crypto 知识库 (20+ 密码类型)")
    p_misc.add_argument("--category", metavar="CAT", help="按分类筛选")
    p_misc.add_argument("--search", metavar="KW", help="搜索密码类型")
    p_misc.add_argument("--id", metavar="ID", help="查看指定密码详情")
    p_misc.add_argument("--encode", metavar="ID", help="编码密码类型")
    p_misc.add_argument("--decode", metavar="ID", help="解码密码类型")
    p_misc.add_argument("-t", "--text", metavar="TEXT", help="输入文本")
    p_misc.add_argument("-k", "--key", metavar="KEY", help="密钥 (维吉尼亚等需要)")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="目录扫描 (离线词库)")
    p_scan.add_argument("type", nargs="?", choices=["dir", "file"], default="dir", help="词库类型 (dir/file)")
    p_scan.add_argument("--all", action="store_true", help="显示全部词条")
    p_scan.add_argument("--search", metavar="KW", help="搜索词库")

    return parser


def main():
    """程序入口."""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print(banner())
        parser.print_help()
        return

    # 路由到对应命令
    commands = {
        "decode": cmd_decode,
        "encode": cmd_encode,
        "ssti": cmd_ssti,
        "sqli": cmd_sqli,
        "lfi": cmd_lfi,
        "ssrf": cmd_ssrf_cmd,
        "xss": cmd_xss_cmd,
        "rce": cmd_rce_cmd,
        "php": cmd_php_cmd,
        "upload": cmd_upload,
        "hashid": cmd_hashid,
        "jwt": cmd_jwt,
        "scan": cmd_scan,
        "scripts": cmd_scripts,
        "misc": cmd_misc,
        "solve": cmd_solve,
        "crypto": cmd_crypto,
    }

    func = commands.get(args.command)
    if func:
        func(args)


if __name__ == "__main__":
    main()
