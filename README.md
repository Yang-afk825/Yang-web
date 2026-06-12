# Yang-Web ð ï¸ v1.4.0

> **CTF ä¸ç«å¼å·¥å·ç®±** â æºè½è§£ç  + 23ç§å¯ç /ç¼ç  + JWTæ»å» + Payloadåº + é¶åºåæ + GUIå¾å½¢çé¢

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green.svg)]()
[![GUI](https://img.shields.io/badge/GUI-tkinter-purple.svg)]()
[![Ciphers](https://img.shields.io/badge/ciphers-23-orange.svg)]()
[![Scripts](https://img.shields.io/badge/scripts-41-red.svg)]()
[![Payloads](https://img.shields.io/badge/payloads-8_mods-blue.svg)]()

---

## ð ç®ä»

Yang-Web æ¯ä¸æ **CTF å¨æ¹åççå£«åå**ï¼è¦çç¼ç è§£ç ãå¯ç ç ´è§£ãPayload çæãé¶åºåæå°æ»å»å©ç¨ãåç½® **å¾å½¢çé¢ (GUI)**ï¼æ¯æ CLI â GUI ä¸é®åæ¢ãå®å¨ç¦»çº¿ï¼é¶ç¬¬ä¸æ¹ä¾èµã

**14 ä¸ªå­å½ä»¤ + æºè½è§£ç å¨(14ç§ç¼ç ) + 23ç§å¯ç (Baseå¨ç³»+å¤å¸+é®ç+ä¸­æ) + 41ä¸ªååµCTFèæ¬ + JWTæ»å»é¾ + 8å¤§Payloadæ¨¡å + ðé¶åºé»åååæã**

---

## â¨ æ ¸å¿ä¼å¿

- ð´ **å®å¨ç¦»çº¿** â é¶ pip ä¾èµï¼Python æ ååºä¸ææ¢­
- ð§  **æºè½è§£ç å¨** â ç²è´´å³ç¨ï¼èªå¨è¯å«14ç§ç¼ç  + ä¸é®è§£ç  + æ´åå¨è¯ + é¾å¼éå½
- ð **23ç§å¯ç ** â Baseå¨ç³» + å¤å¸(å¯æ/æ æ /çªå/å¹æ ¹/VigenÃ¨re/ADFGX/æ©æ¯) + é®çæ å° + ä¸­æç¼ç 
- ð¦ **41ä¸ªååµèæ¬** â Crypto/Web/Misc/Reverse å¨è¦çï¼ä¸é®è¿è¡
- ð¯ **é¶åºåæ(`--analyze`)** â ð ç²è´´é»ååï¼èªå¨åè¯ä½ åªäºåç¼/ç»è¿è½ç¨
- ð¥ï¸ **å¾å½¢çé¢** â GUI â CLI ä¸é®åæ¢ï¼å¯ç é¢æ¿å³çå³ç¨
- ð¯ **8å¤§Payloadæ¨¡å** â SSTI/SQLi/LFI/SSRF/XSS/RCE/PHP/Upload
- ð¡ï¸ **WAF ç»è¿** â 30+ SQL WAF + 12ç±» PHP RCE ç»è¿
- ð **JWT æ»å»é¾** â è§£æâNoneæ»å»âå¼±å¯é¥çç ´âä¼ªé ä»¤ç

---

## ð¦ å®è£

```bash
pip install yang-web

# æ GitHub
git clone https://github.com/Yang-afk825/Yang-web.git
cd Yang-web
python -m yang_web
```

---

## ð å­å½ä»¤è¯¦è§£

### 1. æºè½è§£ç  `decode`

èªå¨æ£æµç¼ç æ ¼å¼å¹¶é¾å¼è§£ç ãæ¯æ **base64/32/16/58/85ãURLãHTMLå®ä½ãROT13ãäºè¿å¶/å«è¿å¶/åè¿å¶ASCIIãUnicodeè½¬ä¹ãæ©æ¯çµç **ã

```bash
$ yang-web decode "ZmxhZ3t0ZXN0fQ=="
â flag{test}

$ yang-web decode --brute "dGVzdA=="      # æ´åå¨è¯
```

---

### 2. ç¼ç  `encode`

ææ â ç¼ç ã

```bash
$ yang-web encode base64 "hello world"
$ yang-web encode url "admin' OR 1=1--"
```

---

### 3. SSTI æ¨¡æ¿æ³¨å¥ `ssti`

8 ç§å¼æï¼Jinja2/Twig/Smarty/Mako/ERB/FreeMarker/Velocity/Djangoï¼ã

```bash
$ yang-web ssti --list                    # ååºå¼æ
$ yang-web ssti --exploit --engine Jinja2  # RCE Payload
$ yang-web ssti --bypass --engine Twig    # è¿æ»¤ç»è¿
```

---

### 4. SQL æ³¨å¥ `sqli`

MySQL/PostgreSQL/MSSQL/Oracle/SQLite + 30ç§WAFç»è¿ + ðè®¤è¯ç»è¿ã

```bash
$ yang-web sqli --list
$ yang-web sqli --db MySQL                # å¨é¨MySQL Payload
$ yang-web sqli --blind                   # ç²æ³¨æ¨¡æ¿
$ yang-web sqli --waf ç©ºç½ç¬¦ç»è¿           # WAFç»è¿
$ yang-web sqli --search "ç»è¿ç»å½"        # ðè®¤è¯ç»è¿Payload
```

---

### 5. LFI / æä»¶åå« `lfi`

```bash
$ yang-web lfi --traversal                # è·¯å¾éå
$ yang-web lfi --linux / --windows        # æææä»¶
$ yang-web lfi --php                      # ä¼ªåè®®
$ yang-web lfi --filter-chain             # PHP filter chain
```

---

### 6. SSRF `ssrf`

```bash
$ yang-web ssrf --cloud aws               # äºåæ°æ®
$ yang-web ssrf --internal                # åç½æ¢æµ
$ yang-web ssrf --protocol                # åè®®å©ç¨
$ yang-web ssrf --bypass                  # ç»è¿æå·§
```

---

### 7. XSS `xss`

```bash
$ yang-web xss --detect
$ yang-web xss --steal cookie
$ yang-web xss --bypass
```

---

### 8. RCE `rce`

```bash
$ yang-web rce --inject                   # å½ä»¤æ³¨å¥Payload
$ yang-web rce --shell bash --ip 10.0.0.1 --port 4444
```

---

### 9. PHP æå·§ `php`

Magic Hash Ã27 + å¼±ç±»å Ã14 + WAFç»è¿ Ã12ã

```bash
$ yang-web php --magic
$ yang-web php --waf-php
$ yang-web php --rce
```

---

### 10. ð æä»¶ä¸ä¼  `upload`

è¦çæä»¶ä¸ä¼ å¨æ»å»é¢ + ðé¶åºåæã

```bash
$ yang-web upload --ext                   # åç¼åç»è¿
$ yang-web upload --mime                  # Content-Typeä¼ªé 
$ yang-web upload --content               # å¾çé©¬åå®¹ç»è¿
$ yang-web upload --parse apache          # è§£ææ¼æ´
$ yang-web upload --htaccess / --userini  # éç½®æä»¶å©ç¨
$ yang-web upload --advanced              # é«çº§æå·§

# ð é¶åºé»åååæ
$ yang-web upload --analyze "php,php3,php5,php7,phtml,shtml,cgi"
â ð¯ é¶åºé»åååæ
  å·²æ¦æª: cgi, php, php3, php5, php7, phtml, shtml
  â å¯ç¨åç¼: phar, php4, php8, phps, pht
    ð¯ æ¨è .pht â æå¸¸è§çç»è¿åç¼
  ð¤ å¤§å°åæ··å: Php â / PHP â / pHp5 â
  ð¦ ååç¼: shell.php.jpg
  ð¾ NTFS æ°æ®æµ: shell.php::$DATA
```

---

### 11. Hash è¯å« `hashid`

40+ ç§ Hash ç®æ³è¯å«ã

```bash
$ yang-web hashid "e10adc3949ba59abbe56e057f20f883e"
ð MD5 / NTLM / MD4
```

---

### 12. JWT æ»å» `jwt`

```bash
$ yang-web jwt "eyJ..." --none           # Noneæ»å»
$ yang-web jwt "eyJ..." --brute          # å¼±å¯é¥çç ´
$ yang-web jwt "eyJ..." --forge --secret "key" --claim '{"admin":true}'
```

---

### 13. ç¦»çº¿æ«æ `scan`

```bash
$ yang-web scan dir --search flag
$ yang-web scan file --search backup
```

---

### 14. ååµèæ¬åº `scripts`

41 ä¸ª CTF èæ¬ï¼Crypto/Web/Misc/Reverseï¼ã

```bash
$ yang-web scripts                       # ååºå¨é¨
$ yang-web scripts --category crypto     # æåç±»
$ yang-web scripts --run rsa_toolkit     # è¿è¡èæ¬
$ yang-web scripts --check-deps          # ä¾èµæ£æ¥
```

---

## ð å®æå·¥ä½æµ

### SQL æ³¨å¥ â ç»å½ç»è¿
```bash
# 1. é¶åºè¿å "ç¨æ·åæå¯ç éè¯¯"
# 2. Yang-Web æ¾è®¤è¯ç»è¿
$ yang-web sqli --db MySQL | grep "ä¸è½å¯ç "
# 3. ç¨ admin' OR '1'='1 ç»å½ â
```

### æä»¶ä¸ä¼  â åç¼ç»è¿
```bash
# 1. ä¸ä¼  shell.php â BLOCKED: .php not allowed
# 2. åæé»åå
$ yang-web upload --analyze "php,php3,php5,php7,phtml,shtml,cgi"
# 3. æ¨è .pht â ä¸ä¼ æå â
```

### ç¼ç è§£ç 
```bash
$ yang-web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="
# Step 1: base64 â Step 2: base16 â "Robot easy" â
```

---

## ð GUI Misc Crypto å¯ç é¢æ¿

**23 ç§** CTF å¸¸è§å¯ç ï¼æ¯æä¸é® Encode/Decodeã

| åç±» | å¯ç  |
|------|------|
| åºç¡ç¼ç  | Base64/32/16/58/85, URL, HTML, Unicode, äºè¿å¶/å«è¿å¶/åè¿å¶ |
| å¤å¸æ¿æ¢ | å¯æãåç¹å·´ä»ãROT13ãç»´åå°¼äºãADFGX |
| æ£ç/åæ  | çªåãå¹æ ¹ãæ³¢å©æ¯å¥¥æ¯ãæ æ ãé®çQWE/æ£ç/åæ  |
| ä¸­æ/ç¹æ® | å½éºãæ°æéè½¬è½®ãæ©æ¯ãäºè¿å¶å å¯ãååºãå­æ¯è¡¨é¡ºåºãæ°å­åæ  |
| å¶ä» | æ åé¶æ²³å­æ¯ãææºé®çãéæ¯è±¡å½¢æå­ãèå­æå¡ |

### GUI å¯å¨
```bash
yang-web gui
# æåå»æ¡é¢ Yang-Web å¿«æ·æ¹å¼
```

---

## ð é¡¹ç®ç»æ

```
Yang-web/
âââ pyproject.toml
âââ README.md
âââ yang_web/
â   âââ __init__.py / __main__.py
â   âââ cli.py                      # CLI (14å­å½ä»¤)
â   âââ gui.py                      # GUI (å¾å½¢çé¢)
â   âââ core/                       # æ ¸å¿å¼æ
â   â   âââ decoder.py              # æºè½è§£ç  (14ç§ç¼ç )
â   â   âââ misc_crypto.py          # å¯ç å¼æ (23ç§)
â   â   âââ hashid.py / jwt.py     # Hashè¯å« / JWTæ»å»
â   âââ payloads/                   # 8å¤§Payloadæ¨¡å
â   â   âââ sqli.py (ðè®¤è¯ç»è¿)
â   â   âââ upload.py (ð--analyze)
â   â   âââ ssti.py / lfi.py / ssrf.py
â   â   âââ xss.py / rce.py / php.py
â   âââ scripts/                    # 41ä¸ªCTFèæ¬
â   âââ wordlists/                  # å­å¸æ°æ®
```

---

## v1.4.0 æ´æ°

- ð **Upload é¶åºåæ** â `--analyze` ç²è´´é»ååï¼èªå¨æ¨èç»è¿æ¹æ¡ï¼CLI+GUIåæ¯æï¼
- ð **SQLi è®¤è¯ç»è¿** â 8 æ¡ä¸è½å¯ç  Payloadï¼`admin' OR '1'='1`ç­ï¼
- ð§ **GUI åç±»ä¿®å¤** â ä¸ææ¡éä¸­åæ­£ç¡®å è½½æ°æ®
- ð§ **GUI åè¡¨å±å¼** â ä¸åæªæ­æ¾ç¤ºï¼å¨é¨ Payload å¯è§
- ð§ **å¯ç å¼æè¡¥å¨** â Atbash/Caesar/ROT13/Rail Fence/Morse ç­è¡¥å¨
- ð§ **GUI æç´¢ä¼å** â è¾å¥æ¡æ¯æåè½¦è§¦åæç´¢
- ð **bugfix** â AES è§£å¯è½®å¯é¥é¡ºåºä¿®å¤ãpyproject.toml æå»ºåç«¯ä¿®å¤

---

## ð® èç³»

3303257524@qq.com

## ð License

MIT â è¯¦è§ [LICENSE](LICENSE)
