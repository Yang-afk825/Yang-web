"""CTF èæ¬æ³¨åè¡¨ â åæ°æ®ãåç±»ãä¾èµä¿¡æ¯."""

from __future__ import annotations
from typing import Dict, List, TypedDict, Optional
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

class ScriptMeta(TypedDict):
    name: str           # èæ¬æä»¶å
    title: str          # ä¸­æå
    category: str       # åç±»: crypto / web / reverse / misc / forensics
    description: str    # åè½ç®è¿°
    usage: str          # ä½¿ç¨ç¤ºä¾
    deps: List[str]     # ä¾èµåº (éæ ååº)
    input_type: str     # è¾å¥ç±»å: text / file / apk / pcap / url
    output_type: str    # è¾åºç±»å: text / flag / decode


# ââ èæ¬æ³¨åè¡¨ ââ

SCRIPTS: Dict[str, ScriptMeta] = {
    # âââ Crypto / ç¼ç  âââ
    "Baseå®¶æå è§£å¯": {
        "name": "Baseå®¶æå è§£å¯.py",
        "title": "Baseå®¶æå è§£å¯",
        "category": "crypto",
        "description": "ä¸ç«å¼ base16/32/36/58/62/64/85/91/92 ç¼è§£ç ï¼æ¯ææ¹éæä½",
        "usage": 'python scripts/Baseå®¶æå è§£å¯.py',
        "deps": ["base36", "base58", "base62", "base91", "py3base92"],
        "input_type": "text",
        "output_type": "text",
    },
    "base64æ¹éå è§£å¯": {
        "name": "base64æ¹éå è§£å¯.py",
        "title": "Base64 æ¹éå è§£å¯",
        "category": "crypto",
        "description": "æ¹é base64 ç¼è§£ç ï¼å½©è² ASCII èºæ¯è¾åº",
        "usage": 'echo "sometext" | python scripts/base64æ¹éå è§£å¯.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "base64å¼æ": {
        "name": "base64å¼æ.py",
        "title": "Base64 + XOR çç ´",
        "category": "crypto",
        "description": "base64 è§£ç åéå­èå¼æçç ´ (0-199) æ¾åºææ",
        "usage": 'python scripts/base64å¼æ.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "base64éå": {
        "name": "base64éå.py",
        "title": "Base64 éåæå",
        "category": "crypto",
        "description": "ä» base64 ç¼ç ç '=' å¡«åä½ä¸­æåéåæ°æ®",
        "usage": 'python scripts/base64éå.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "base64ç¬è«": {
        "name": "base64ç¬è«.py",
        "title": "Base64 ç¬è«çç ´",
        "category": "web",
        "description": "base64 ç¼ç åæ°éåè¯·æ± URLï¼éå CTF ç¬è«é¢ï¼",
        "usage": 'python scripts/base64ç¬è«.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },
    "baseèªå¨è¿ç»­è§£å¯èæ¬": {
        "name": "baseèªå¨è¿ç»­è§£å¯èæ¬.py",
        "title": "Base èªå¨è¿ç»­è§£å¯",
        "category": "crypto",
        "description": "èªå¨æ£æµ base16/32/64 æ ¼å¼å¹¶è¿ç»­è§£ç è³ææ",
        "usage": 'python scripts/baseèªå¨è¿ç»­è§£å¯èæ¬.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "2è¿å¶ææ¬è½¬æ¢ascii": {
        "name": "2è¿å¶ææ¬è½¬æ¢ascii.py",
        "title": "äºè¿å¶è½¬ ASCII",
        "category": "crypto",
        "description": "äºè¿å¶å­ç¬¦ä¸²è½¬ ASCIIï¼æ¯æ 7/8bitãä½ç¿»è½¬ãå­èååº",
        "usage": 'python scripts/2è¿å¶ææ¬è½¬æ¢ascii.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "4å­è16è¿å¶è½¬æµ®ç¹": {
        "name": "4å­è16è¿å¶è½¬æµ®ç¹.py",
        "title": "Hex è½¬æµ®ç¹æ°",
        "category": "crypto",
        "description": "4 å­è hex â float äºè½¬ï¼å¤§ç«¯/å°ç«¯ï¼",
        "usage": 'python scripts/4å­è16è¿å¶è½¬æµ®ç¹.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "TLLéå": {
        "name": "TLLéå.py",
        "title": "TLL åç´ éå",
        "category": "misc",
        "description": "åç´ å¼(63â00,127â01,191â10,255â11)æ å°æåéåæ°æ®",
        "usage": 'python scripts/TLLéå.py',
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "å­ç¬¦ä¸²ç»è®¡": {
        "name": "å­ç¬¦ä¸²ç»è®¡.py",
        "title": "å­ç¬¦ä¸²ç»è®¡å¯¹æ¯",
        "category": "crypto",
        "description": "ä¸¤å­ç¬¦ä¸²éå­èç»è®¡/å¯¹æ¯å·®å¼",
        "usage": 'python scripts/å­ç¬¦ä¸²ç»è®¡.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "å­é¢ç»è®¡": {
        "name": "å­é¢ç»è®¡.py",
        "title": "å­æ¯é¢çç»è®¡",
        "category": "crypto",
        "description": "å­æ¯é¢çç»è®¡æåºï¼æé¢æ¬¡éåºæ¼æ¥è¾åº",
        "usage": 'python scripts/å­é¢ç»è®¡.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },

    # âââ Hash / çç ´ âââ
    "md5": {
        "name": "md5.py",
        "title": "MD5 çç ´",
        "category": "crypto",
        "description": "5 å±åµå¥å¾ªç¯çç ´ MD5ï¼æ¨¡æ¿å­ç¬¦ä¸²å¹éé¨å hashï¼",
        "usage": 'python scripts/md5.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "md5çç ´": {
        "name": "md5çç ´.py",
        "title": "MD5 çç ´ (v2)",
        "category": "crypto",
        "description": "ä¸ md5.py é»è¾ä¸è´ï¼éå¯¹ä¸åæ ¼å¼æ¨¡æ¿",
        "usage": 'python scripts/md5çç ´.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "crc32": {
        "name": "crc32.py",
        "title": "CRC32 ç¢°æ",
        "category": "crypto",
        "description": "ç»å® CRC32 éåçç ´ 4 å­èå¯æå°å­ç¬¦ææ",
        "usage": 'python scripts/crc32.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "crcçç ´": {
        "name": "crcçç ´.py",
        "title": "PNG CRC ä¿®å¤",
        "category": "misc",
        "description": "PNG å®½é« CRC çç ´ï¼ç»å® CRC32 æ¢å¤æ­£ç¡®å¾çå®½é«",
        "usage": 'python scripts/crcçç ´.py',
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "sm2": {
        "name": "sm2.py",
        "title": "å½å¯ SM2",
        "category": "crypto",
        "description": "å½å¯ SM2 å å¯/è§£å¯æ¨¡æ¿ï¼é gmsslï¼",
        "usage": 'python scripts/sm2.py',
        "deps": ["gmssl"],
        "input_type": "text",
        "output_type": "text",
    },

    # âââ Web âââ
    "æ­£å¸¸ç²æ³¨": {
        "name": "æ­£å¸¸ç²æ³¨.py",
        "title": "SQL ç²æ³¨æ¨¡æ¿",
        "category": "web",
        "description": "SQL ç²æ³¨ Payload æ¨¡æ¿ï¼äºåæ³éå­ç¬¦æ³¨å¥ï¼åºå/è¡¨å/åå/æ°æ®ï¼",
        "usage": 'python scripts/æ­£å¸¸ç²æ³¨.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },
    "IISæä»¶ä¸ä¼ ": {
        "name": "IISæä»¶ä¸ä¼ .py",
        "title": "IIS PUT ä¸ä¼ å©ç¨",
        "category": "web",
        "description": "IIS PUT æä»¶ä¸ä¼ æ¼æ´å©ç¨ï¼httplib å®ç°ï¼",
        "usage": 'python scripts/IISæä»¶ä¸ä¼ .py',
        "deps": [],
        "input_type": "url",
        "output_type": "text",
    },
    "sshå¼±å£ä»¤å æåflag": {
        "name": "sshå¼±å£ä»¤å æåflag.py",
        "title": "SSH å¼±å£ä»¤ + æå Flag",
        "category": "web",
        "description": "SSH å¼±å£ä»¤æ«æ + è¿ç¨æ§è¡ cat flagï¼paramikoï¼",
        "usage": 'python scripts/sshå¼±å£ä»¤å æåflag.py',
        "deps": ["paramiko"],
        "input_type": "url",
        "output_type": "flag",
    },
    "èªå¨æäº¤flag": {
        "name": "èªå¨æäº¤flag.py",
        "title": "èªå¨æäº¤ Flag",
        "category": "web",
        "description": "CTF æ¯èµèªå¨è·å flag å¹¶æäº¤å°è®¡åå¹³å°ï¼requests sessionï¼",
        "usage": 'python scripts/èªå¨æäº¤flag.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },

    # âââ Reverse âââ
    "APKéåSolver": {
        "name": "APK éå Solver.py",
        "title": "APK éå Solver",
        "category": "reverse",
        "description": "éç¨ SCM time-capsule APK æ±è§£å¨ï¼4æ®µ6å­èå¯æå°key â SHA256 â RC4 è§£å¯ flag.enc",
        "usage": 'python "scripts/APK éå Solver.py" attachment.apk',
        "deps": [],
        "input_type": "apk",
        "output_type": "flag",
    },

    # âââ Misc / æµé âââ
    "ICMP": {
        "name": "ICMP.py",
        "title": "ICMP Ping æ«æ",
        "category": "misc",
        "description": "ICMP Ping æ«æï¼scapy, å¤çº¿ç¨, æ¯æ IP æ®µåæä»¶è¾å¥ï¼",
        "usage": 'python scripts/ICMP.py',
        "deps": ["scapy"],
        "input_type": "url",
        "output_type": "text",
    },
    "ICMPæ°æ®ådataé¿åº¦æå": {
        "name": "ICMPæ°æ®ådataé¿åº¦æå.py",
        "title": "ICMP Data æå",
        "category": "misc",
        "description": "ä» PDML æå ICMP data.len â base64 è§£ç éåä¿¡æ¯",
        "usage": 'python scripts/ICMPæ°æ®ådataé¿åº¦æå.py',
        "deps": [],
        "input_type": "file",
        "output_type": "decode",
    },
    "ä¸åäºæ¬¡æ¹ç¨": {
        "name": "ä¸åäºæ¬¡æ¹ç¨.py",
        "title": "ä¸åäºæ¬¡æ¹ç¨æ±è§£",
        "category": "misc",
        "description": "è§£ä¸åäºæ¬¡æ¹ç¨ï¼CTF èªå¨åæµç¨è¾å©ï¼",
        "usage": 'python scripts/ä¸åäºæ¬¡æ¹ç¨.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "é®é¼ æ§å¶": {
        "name": "é®é¼ æ§å¶.py",
        "title": "pyautogui åèå¤§å¨",
        "category": "misc",
        "description": "pyautogui æä½åèï¼é¼ æ /é®ç/æªå¾/å¾åå®ä½ç­å®æ´ API",
        "usage": 'python scripts/é®é¼ æ§å¶.py',
        "deps": ["pyautogui"],
        "input_type": "text",
        "output_type": "text",
    },
    "ç«èµèæ¬": {
        "name": "ç«èµèæ¬.zip",
        "title": "ç«èµèæ¬åé",
        "category": "misc",
        "description": "é¢å¤çæªåç±» CTF ç«èµèæ¬æåï¼éè§£åä½¿ç¨ï¼",
        "usage": "è§£å scripts/ç«èµèæ¬.zip åæ¥ç",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    # === v1.3 new scripts ===
    "aes_crypto": {
        "name": "aes_crypto.py",
        "title": "AES å è§£å¯",
        "category": "crypto",
        "description": "AES ECB/CBC å è§£å¯ é¶ä¾èµ",
        "usage": "python aes_crypto.py [mode] [text]",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "classic_crypto": {
        "name": "classic_crypto.py",
        "title": "å¤å¸å¯ç å·¥å·ç®±",
        "category": "crypto",
        "description": "Morse/ROT/Atbash/Caesar/Bacon ç¼è§£ç +èªå¨è¯å«",
        "usage": "python classic_crypto.py <text>",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "time_sqli": {
        "name": "time_sqli.py",
        "title": "æ¶é´ç²æ³¨ SQLi",
        "category": "web",
        "description": "æ¶é´ç²æ³¨SQLæ³¨å¥ æ¯æMySQL/PG/MSSQL/SQLite",
        "usage": "python time_sqli.py <URL> <QUERY>",
        "deps": [],
        "input_type": "url",
        "output_type": "text",
    },
    "qr_tools": {
        "name": "qr_tools.py",
        "title": "QR ç å·¥å·",
        "category": "misc",
        "description": "QRç çæ/ä¿®å¤/è§£æ é¶ä¾èµ",
        "usage": "python qr_tools.py gen <text> | read <img>",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "zip_tools": {
        "name": "zip_tools.py",
        "title": "ZIP åæå·¥å·",
        "category": "misc",
        "description": "ZIPç»æ/CRCçç ´/PKCRACKæå",
        "usage": "python zip_tools.py <zip> | --crc CRC LEN",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "zlib_tools": {
        "name": "zlib_tools.py",
        "title": "åç¼©è§£åå·¥å·ç®±",
        "category": "misc",
        "description": "zlib/gzip/bzip2/lzma èªå¨è§£å+base64",
        "usage": "python zlib_tools.py <base64> [--auto]",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "pcap_tools": {
        "name": "pcap_tools.py",
        "title": "PCAP æµéåæ",
        "category": "misc",
        "description": "æåICMP/HTTP/DNSæ°æ® é¶ä¾èµ",
        "usage": "python pcap_tools.py <file.pcap>",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "string_convert": {
        "name": "string_convert.py",
        "title": "é«çº§å­ç¬¦ä¸²è½¬æ¢",
        "category": "crypto",
        "description": "128ä½/æµ®ç¹/XOR/è¿å¶è½¬æ¢/å·®å¼å¯¹æ¯",
        "usage": "python string_convert.py <cmd> <args>",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },

    # === v1.3.1 new scripts ===
    "bool_inject": {
        "name": "bool_inject.py",
        "title": "å¸å°ç²æ³¨ SQLi",
        "category": "web",
        "description": "å¸å°ç²æ³¨SQLæ³¨å¥ èªå¨æåæ°æ®",
        "usage": "python bool_inject.py <URL> <QUERY>",
        "deps": [],
        "input_type": "url",
        "output_type": "text",
    },
    "rce_bypass": {
        "name": "rce_bypass.py",
        "title": "æ å­ç¬¦RCEç»è¿",
        "category": "web",
        "description": "OR/XOR/NOT æ æ°å­å­æ¯RCE payloadçæå¨",
        "usage": "python rce_bypass.py <cmd> [--or|--xor|--not]",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "phpinfo_lfi": {
        "name": "phpinfo_lfi.py",
        "title": "PHPInfoæ¡ä»¶ç«äºLFI",
        "category": "web",
        "description": "PHPInfo race condition LFIâRCE",
        "usage": "python phpinfo_lfi.py <phpinfo> <lfi_url>",
        "deps": [],
        "input_type": "url",
        "output_type": "text",
    },
    "wordlist_helper": {
        "name": "wordlist_helper.py",
        "title": "CTF åç½®å­å¸",
        "category": "misc",
        "description": "å¸¸ç¨å¯ç /ç¨æ·å/ç®å½/æä»¶å åç½®å­å¸",
        "usage": "python wordlist_helper.py <type>",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },

    # === v1.3.2 search-optimized ===
    "rsa_toolkit": {
        "name": "rsa_toolkit.py",
        "title": "RSA æ»å»å·¥å·ç®±",
        "category": "crypto",
        "description": "RSAæ»å»:ä½ææ°/å±æ¨¡/Wiener/Fermat/å¹¿æ­ é¶ä¾èµ",
        "usage": "python rsa_toolkit.py --mode low_e --n N --e E --c C",
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "img_stego": {
        "name": "img_stego.py",
        "title": "å¾çéååæ",
        "category": "misc",
        "description": "LSBæå/PNGåå/EOFéè/å­ç¬¦ä¸²æç´¢ é¶ä¾èµ",
        "usage": "python img_stego.py <image.png> [--lsb|--chunks]",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "file_analyzer": {
        "name": "file_analyzer.py",
        "title": "æä»¶å¤´åæå¨",
        "category": "misc",
        "description": "Magic bytesæ£æµ/HEX dump/Strings/ååµæä»¶æ«æ",
        "usage": "python file_analyzer.py <file> [--hex|--strings]",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },

}


# ââ åç±»æ å° ââ
CATEGORIES: Dict[str, str] = {
    "crypto": "ð å¯ç  / ç¼ç ",
    "web": "ð Web",
    "reverse": "ð§ éå",
    "misc": "ð¦ æé¡¹ / Misc",
    "forensics": "ð åè¯ / éå",
}


def list_scripts(category: Optional[str] = None) -> List[tuple]:
    """ååºèæ¬ï¼å¯æåç±»ç­éï¼ï¼è¿å (key, meta) åè¡¨."""
    results = []
    for key, meta in SCRIPTS.items():
        if category and meta["category"] != category:
            continue
        results.append((key, meta))
    return sorted(results, key=lambda x: x[0])


def search_scripts(query: str) -> List[tuple]:
    """æå³é®è¯æç´¢èæ¬."""
    q = query.lower()
    results = []
    for key, meta in SCRIPTS.items():
        if (q in key.lower() or q in meta["title"].lower()
                or q in meta["description"].lower()
                or q in meta["category"].lower()):
            results.append((key, meta))
    return sorted(results, key=lambda x: x[0])


def get_script(key: str) -> Optional[ScriptMeta]:
    """è·ååä¸ªèæ¬åæ°æ®."""
    return SCRIPTS.get(key)


def get_script_path(key: str) -> Optional[str]:
    """è·åèæ¬çç»å¯¹è·¯å¾."""
    meta = SCRIPTS.get(key)
    if not meta:
        return None
    path = os.path.join(SCRIPT_DIR, meta["name"])
    if os.path.isfile(path):
        return path
    return None
