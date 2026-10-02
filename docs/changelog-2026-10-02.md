# 2026-10-02 工程化修复记录

承接 [2026-10-01 记录](changelog-2026-10-01.md)，这是第二轮工程化体检与修复。
本轮**新增 7 个提交**，并连同 10-01 积压未推的 5 个提交一起推送（共 12 个，`845fd53..11b7df2`），
同时完成了 **exe 分发方式改造**与项目的**首次自动化发布**。

体检结论先行：功能本体已经健康（主代码零裸 `except`、TODO 命中全为误报、82 项测试全过），
问题集中在**对外承诺**与**仓库体积**两块。

---

## 一、对外失真与隐私泄露（本轮最该先修的一类）

公开仓库里有三处写死了开发者的本机路径，其中两处**含 Windows 账户名**。
危害是双重的：陌生人照抄必然失败，且公开发布等于把本机目录结构一并公开。

| 位置 | 修改前 | 修改后 |
|---|---|---|
| `GUIDE.md` CLI 示例 | `cd C:\Users\<用户名>\.qclaw\workspace\Yang-web` | `cd <Yang-Web 克隆目录>` |
| `README.md` 知识库说明 | `~/.qclaw/workspace/Des-CTF-Knowledge` | `~/Des-CTF-Knowledge` |
| `scripts/ctfplus_batch_solver.py` | `sys.path.insert(0, r'C:\Users\...\yang_web')`、硬编码 JSON 绝对路径 | 按 `__file__` 上溯定位包根；JSON 路径支持环境变量覆盖 |
| `core/knowledge_base.py` | 把 `.qclaw/workspace/...` 当「常见位置」候选 | 剥掉私有前缀，改为 `~/<name>` + 仓库同级目录 |

其中 `ctfplus_batch_solver.py` 最严重：它是注册进脚本库、会被实际执行的内置脚本，
在他人机器上**必然失败**。

> 收集来的第三方脚本（如 `scripts/键鼠控制.py`）里保留着原作者路径，属外部资料，
> 本次未动。

## 二、代码与文档缺陷

### 1. 同名函数覆盖 = 164 行静默死代码

`core/url_analyzer/_attacks.py` 里 `_try_bashfuck_exploit` 被定义了两次：

- 第 693 行起：v3.3 自研实现（内联 WAF 字符集探测 + payload 生成）
- 第 1136 行起：v3.7 实现（委托 `core/bashfuck_solver.auto_solve`）

Python 模块级后定义覆盖先定义，而调用点（`auto_exploit` 内）按运行时解析函数名，
**因此实际生效的一直是 v3.7，v3.3 那份从未被执行过**。删除后文件 1165 → 1001 行。

> 坑：该区间内还夹着 7 个被 `__init__.py` 导出的顶层函数
> （`_try_length_limit_rce_exploit` / `_try_flag_paths` / `_try_sqli_extract` 等），
> 若按"删到下一个 def 为止"的直觉处理会整段误删。删除前必须断言区间内无其它顶层定义。

### 2. `.gitignore` 通配吞掉了必需资源

`.gitignore` 的 `*.ico` 把 `icon.ico` 一并忽略，导致**仓库里根本没有图标文件**。
`Yang-Web.spec` 用 `os.path.exists()` 做了兜底，所以打包不会报错——
只是别人 clone 后构建出的 exe **静默没有图标**，长期无人发现。

补 `!icon.ico` 放行并入库。

### 3. 文档与实现/事实不符

- `README.md` 称 exe 为 24MB，实际不符（见下方"体积数字的修正过程"）；
- `GUIDE.md` 声称"顶部有 Tab 标签页"——**经核对属实**（`_app.py` 用 `ttk.Notebook`），未改；
- `gui/__init__.py` 的 docstring 写"布局：左侧功能树 + 右侧内容区"，
  但 `_app.py` 里既无 `Treeview` 也无 `PanedWindow`，实际是标题栏 + Notebook 标签页，已按实现改正。

### 4. 体积数字的修正过程（记一笔，避免后人重复踩）

先后写了两个不同的数：`24MB` → `约 32MB` → `约 23MB`。

原因是我先拿本地 `dist/` 里 2026-09-08 构建的旧 exe（32.2MB）当参照物，
但 CI 从当前源码构建的产物实测 **22.94MB**。
**工作区里来路不明的旧产物不是可靠参照**——写进文档的数字应当取自可复现的构建结果。

顺带查清了 9MB 差异**不是组件缺失**：CI 日志确认 `pythonnet hook dir: ...\_pyinstaller`
正常生效；`Python.Runtime.dll` / `webview` / `uvicorn` / `fastapi` / `pydantic`
在新旧 exe 中的出现次数一致；差异来自旧包以**源码目录**形式塞入了 pythonnet
（相关路径字符串出现 100 次 vs 4 次）。两个 exe 均不含 tkinter——exe 版走 pywebview + FastAPI，
tkinter 是源码版的形态。

## 三、分发方式改造：exe 出库 + 自动化发布

`dist/Yang-Web.exe`（32MB）此前被 git 追踪，历史里至少 3 个版本。
PyInstaller 每次构建产物都不同、**无法去重**，等于每发一版就往历史里再写 32MB。

**体检时的关键发现**：`dist/` 里那个 exe 落后源码 **10 个提交**——
其中包含 10-01 才修复的「解码把明文解成乱码」bug。也就是说，
**手工打包 + 手工上传这条流程，已经在产出"版本与源码不一致"的包了**。

因此本次做了三件事：

1. `dist/` 整体加入 `.gitignore`，`git rm --cached dist/Yang-Web.exe`（本地文件保留）；
2. README 的「免安装」入口、代码块、目录树三处改指向 GitHub Releases；
3. 新增 `.github/workflows/release.yml`：

   - 触发：推送 `v*` tag，或手动 `workflow_dispatch` 指定 tag（不存在则自动创建）
   - 流程：装依赖 → **先跑全量单元测试（不过则不发布）** → PyInstaller 构建
     → 校验产物存在且体积合理（<10MB 判为构建不完整）→ 生成 SHA256 → 发布 Release

**首次发布（v4.0.0）**：`Yang-Web.exe` 22.94 MB + `.sha256`，已下载核验校验和一致。

> 说明：本次只停止「继续入库」。已推送历史里的旧 exe 仍在 pack 中（约 38MB），
> 未做 `filter-repo` 重写——那需要 force push，会让他人已有的 clone 失效。

## 四、仓库健康与 CI 门禁

- `git gc --prune=now`：`.git` **133 MB → 61 MB**（回收 72MB 松散对象）；
- 本地残留移出仓库（**移动而非删除**，收纳于仓库同级备份目录）：
  `build/` 43MB、`_archive_2026-10-01/` 11MB、根目录 `__pycache__/`；
  仓库总计 247 MB → 122 MB。保留了本地分支 `backup-before-gongzhonghao`（它是有价值的备份）；
- **新增 `.github/workflows/ci.yml`**：`windows-latest` 上以 **Python 3.8 / 3.10 / 3.12**
  三个版本跑 `compileall` + 全部单元测试 + CLI 解码冒烟。
  此前 82 项测试没有任何门禁，只在开发者本机跑过。

## 五、验证

- **CI 全绿**：3.8 / 3.10 / 3.12 三版本编译检查、82 项测试、CLI 冒烟全部通过
  ——顺带实测坐实了 `pyproject.toml` 中 `requires-python = ">=3.8"` 这个声明；
- 本地系统 Python 3.12：82 项测试通过；
- CLI 端到端：`python -m yang_web decode "ZmxhZ3t0ZXN0fQ==" --raw` → `flag{test}`；
- Release 产物：SHA256 与所附校验文件一致。

> 说明：`requires-python >= 3.8` 一度被怀疑失真——主包有 7 处 PEP 604 联合注解
> （`str | None` 等）。核查后确认**属实**：主包 34 个文件均含
> `from __future__ import annotations`，注解惰性求值；且全仓未命中任何 3.9+ 运行时 API
> （`removeprefix` / `functools.cache` / `zoneinfo` / `tomllib` / `ExceptionGroup` 等）。
> 结论：不要仅凭 `X | None` 的出现就判定版本声明失真。

## 六、仍未处理（需要决定）

- **历史里的旧 exe（约 38MB pack）**：要真正回收需 `git filter-repo` + force push，
  属破坏性操作，会影响他人已有 clone；
- **`knowledge/Des-CTF-Knowledge` 子模块 17 处未提交改动**（含 11 项删除）：
  已完整备份到仓库同级备份目录（210KB patch + 从 HEAD 恢复的 11 个被删文件原件），
  **未擅自恢复**。10-01 记录判定为 Windows Defender 活体查杀截断 webshell 样本；
- **巨型文件拆分**：`core/smart_solver.py` 84KB、`cli.py` 61KB、
  `core/advanced_scanner.py` 56KB、`core/misc_crypto.py` 52KB——动静最大，单独确认。
  **→ 已于本日完成，见第八节。**

## 七、本轮提交

| 提交 | 内容 |
|---|---|
| `f2ca583` | fix: 移除硬编码本机路径与泄露的 Windows 用户名 |
| `d86a676` | fix(core): 删除 `_try_bashfuck_exploit` 的重复定义 |
| `7804d25` | chore: 放行 icon.ico 并新增 CI 门禁 |
| `d95f1f2` | chore: exe 分发改走 GitHub Releases，dist/ 不再入库 |
| `611141b` | ci: 新增 Release workflow —— 打包 exe 并发布到 GitHub Releases |
| `7c4830c` | docs(gui): 修正与实现不符的布局描述 |
| `11b7df2` | docs: 按 Release 实测值修正 exe 体积（约 32MB → 约 23MB） |

同批推送的 10-01 积压提交：`6494a70`、`7886b98`、`2604c08`、`540b9b8`、`15d5d73`。

## 八、巨型文件拆分（本轮补完）

四个巨型文件全部拆为分层包。拆分标准是 **对外契约零变化**——类方法集合、方法签名、
顶层函数签名、顶层数据对象逐项与拆分前比对，全部一致。

| 原文件 | 行数 | 拆分为 | 最大单文件 |
|---|---|---|---|
| `yang_web/cli.py` | 1482 | `cli/` 6 模块（`_codec`/`_entry`/`_solve`/`_web`/`__init__`/`__main__`） | 602 |
| `yang_web/core/smart_solver.py` | 2004 | `smart_solver/` 8 原子模块（16 文件）+ `WebSmartSolver` 再拆 6 Mixin | 250 |
| `yang_web/core/advanced_scanner.py` | 1335 | `advanced_scanner/` 9 模块（按引擎一间一模块，11 文件） | 292 |
| `yang_web/core/misc_crypto.py` | 1381 | `misc_crypto/` 8 模块（按密码族分组，9 文件） | 326 |

单文件最大规模从 **2004 行降到 602 行**。

### 拆分中踩到并修掉的三个坑

1. **「第一个 def 之前」不等于头部。** `smart_solver.py` 的 `import urllib.*` 与
   `from typing import ...` 写在第一个函数**之后**；`misc_crypto.py` 则有 443 行常量
   排在所有函数之前。按位置判断会把 import 关进某个子模块、或把 300 行常量表复制进
   每个子模块。改为：头部只取「编码行 + module docstring + 全部模块级 import」，
   常量赋值一律作为可分组节点。

2. **正则找引用会被字符串误伤。** `_http_headers` 里的
   `"User-Agent": "Mozilla/5.0 Yang-Web SmartSolver/2.1"` 让 `_common` 被判定引用了
   `_solver`，进而报出假的循环依赖。改为 AST 采集真实 `Name` 节点。

3. **嵌在 `try/except` 里的相对导入会漏改。** `misc_crypto.py` 的
   `try: from . import cipher_classic, ... except ImportError: import ...` 不是模块级
   `Import` 节点，`tree.body` 扫不到。拆成包后 `from .` 会指向错误的层级。
   改为 `ast.walk` 全树扫描 `ImportFrom(level>0)`，按行精确升一层。

### 顺带修掉的对外引用

- `scripts/registry.py` 中 6 条记录把 `../core/smart_solver.py` 当**可执行文件路径**
  （`runner.py` 用 `subprocess.run([sys.executable, path])` 直接跑文件），拆包后该路径
  失效。改为指向 `../core/smart_solver/__main__.py`，并让 `__main__.py` 同时支持
  `python -m yang_web.core.smart_solver` 与按文件路径直接执行两种方式。
- README 目录树与 `usage` 说明同步更新。

### 验证方式

- AST 顶层符号差集：**零缺失**；
- `inspect.signature` 逐类方法、逐顶层函数比对：**全部 MATCH**；
- `python -m compileall` 全绿；82 项单元测试全绿；
- 功能冒烟：`misc_crypto` 95 种密码注册正常、base64/morse 编解码正确；
  `advanced_scanner` 双模式入口打印用法正常。

---
---

# 第三轮：v4.1.0 → v4.1.1

第三轮由一句用户反馈启动：**「这不还是 V4.0 嘛」**。
v4.1.0 已经发布出去了，但用户打开看到的仍是旧版本号。顺着这条线往下查，
牵出了一批「看着对、实际错」的东西。本轮共 11 个提交。

## 一、版本号漂移的根因（用户唯一直接可见的缺陷）

`yang_web/web/index.html` 的 `<title>` 和左上角 logo **各写死了一份 `v4.0`**。
exe 启动后用户眼睛落到的就是这个文件，而发版时只改了 `__init__.py` 和 `pyproject.toml`。

更关键的是**守卫测试为什么没拦住**：它的 `SCAN_EXT` 只有
`.py/.spec/.toml/.yml/.yaml` —— **不含 `.html`**。测试全绿，缺陷照旧。

修法分三层：

1. **消除重复真相**：HTML 改占位符 `__VERSION__`，由 `server.py` 的 `/` 路由
   现读现替换。改前端不必重启服务，也不再需要在两个地方同步改数字。
2. **扩大守卫面**：`SCAN_EXT` 加入 `.html`；正则从 1 种扩到 3 种
   （展示串 `Yang-Web vX.Y.Z` / 字面量 `version = "X.Y.Z"` / UA 串 `YangWeb/X.Y.Z`）；
   新增 README 标题校验与一条**端到端**用例（真起 FastAPI，断言渲染结果 == `__version__`
   且无占位符残留）。
3. **删掉负债**：所有 docstring 里的版本前缀一律去掉。
   `v4.1` 这种短格式遇到 `4.1.1` 必然漂移 —— 留着一个"迟早要改、但没人会记得改"的数字，
   比不留更危险。

## 二、编解码引擎的 12 处静默失效

`advanced_engines` 注册表里有 18 个引擎，**一条测试都没有**。
`tests/test_ciphers.py` 覆盖的是 `misc_crypto`，两者不是一回事。

本轮引入两条通用检查手法，一次把它们全揪出来：

- **注册表全引擎往返扫描**：`dec(x) == x` 对每个引擎过一遍；
- **标准库对标**：能对标准库的就对标准库（UUEncode → `binascii`；base91/92 → PyPI 包）。

| 引擎 | 症状 | 根因 |
|---|---|---|
| `base91_decode` | `HELLO` → `HELL\x80` | 收尾 `(v \| b << n)` 应为 `(b \| v << n)`，位序颠倒 |
| `base92` | 任何输入都解不回原文 | 编码按 13 bit 分组、尾部按「模 92」，解码按 `value*92` 递推，成对不自洽 |
| `rot18_encode` | 恒返回空串 | 函数体第一行 `return rot5_encode(rot47_encode(text)[:0])`，切片恒空 → 真实现成死代码 |
| `jsfuck_decode` | 连自己的输出都解不回 | 正则 `fromCharCode\)\(` 与产出 `["fromCharCode"](72)` 不匹配 |
| `quoted_printable` | `'a b'` → `'a_b'` | 编码把空格写成 `_`，解码从不还原（单向丢失） |
| `brainfuck` / `ook` | 中文生成上千个 `+` | 用 `ord(c)` 取码点当字节 |
| `shellcode` | 产出 `\x4e2d` 四位伪字节 | `f'{ord(c):02x}'` 的 `02` 只是**最小**宽度 |
| `zerowidth` | emoji 之后全部错位 | `f'{ord(c):016b}'` 的 16 同理，码点 > U+FFFF 输出 17 位 |
| `uuencode` | 解不开任何外部数据 | 直接套 `base64.b64encode`，根本不是 uuencode |

### base91 的隐蔽之处

它只在**编码串长度为奇数**时现形：

```
HELLO       -> '>O$G+3A'      (7 字符，末组单字符) -> 解错
flag{test}  -> '@iH<,{!eaUo{B' (13 字符)           -> 解错
abc         -> '#G(I'          (4 字符)            -> 正确
test123     -> 'fPNK,i~RD'     (10 字符)           -> 正确
```

偶数长度恰好把缺陷盖住了。**这解释了它为什么能活这么久**：随手试两个例子，
成功率大约一半。若不是用「注册表轮询 + 权威实现逐字符比对」，它还会继续潜伏。

### 验证

- base91/base92 对 PyPI 权威实现：**408 条文本编码 + 407 条全字节解码，零不一致**；
- UUEncode 对 `binascii.b2a_uu`/`a2b_uu`：**207 样本双向互解，零失败**
  （顺带确认标准库对 `0` 值的空格/反引号两种约定都接受，所以编码端选更抗空白裁剪的反引号）；
- `aaencode`/`jjencode` 确需 JS 运行时，在测试里显式登记为 `ONE_WAY_BY_DESIGN`，
  而不是混进"漏测"或"假装修好"。

## 三、巨型文件清零

`>800 行` 的文件：**8 个 → 0 个**，单文件最大 2004 → 728 行。

| 原文件 | 行数 | 拆为 |
|---|---|---|
| `core/multi_stage.py` | 1062 | 10 模块（含 4 Mixin） |
| `core/url_analyzer/_attacks.py` | 1001 | 6 模块 |
| `core/cipher_keyed.py` | 978 | 9 模块 |
| `gui/_panels_attack.py` | 976 | 3 模块 |
| `scripts/registry.py` | 947 | 4 模块 |
| `core/decoder.py` | 875 | 9 模块 |
| `core/advanced_engines.py` | 846 | 7 模块 |
| `gui/_panels_tools.py` | 809 | 6 模块 |

每次拆分都跑 `diff_api`（方法集合 / 方法签名 / 顶层数据对象三类比对），全部 MATCH。

### 拆分器自身修掉的三个 bug

工具是被真实缺陷打磨出来的，本轮在它身上也踩了坑：

1. **`try/except` 里的纯导入块会被漏掉。** `cipher_keyed` 拆完后
   `fernet: NameError: name 'crypto_engine' is not defined` ——
   `try: from .. import X / except: import X` 这种"可选依赖兜底"不是模块级 `Import` 节点，
   `tree.body` 扫不到，于是整段被当作普通行归给了某个分组，
   跨组引用者一运行就炸。**AST 扫描、`diff_api`、`compileall` 三重掩护全都看不出来，
   只有真的调用才暴露** —— 最后是 `tests/test_ciphers.py` 的全密码 roundtrip 逮住的。
2. **`diff_api` 遇到 TypedDict 会崩**：`builtin has invalid signature` → 加兜底返回 `<unavailable>`。
3. **`selftest` 的夹具无法复现该缺陷**（原本是组内引用，改为跨组引用后才回归得住）。

### 为什么 GUI 那两个文件没做 Mixin 拆分

每个面板的 `__init__` 都调 `super().__init__(parent, bg=BG)`。
把 `__init__` 挪进 Mixin 后，`super()` 的落点取决于 MRO 里 Mixin 的位置 ——
文件从 728 降到 ~300 的收益，不值这个风险。包拆分已足够把两个文件压到 800 以下。

## 四、工程化

- **测试 82 → 116 项**。两把真正管用的钥匙：
  `test_advanced_engines.py` 的「注册表全引擎往返」，和
  `test_package_layout.py` 的「14 个面板**真构造**再销毁」——
  `hasattr` 通过只说明名字在，构造期缺符号照样炸，而那正是拆包最容易伤到的地方。
- **CI 消除 Node.js 20 弃用告警**：`checkout` / `setup-python` / `gh-release`
  升到声明 `using: node24` 的版本（v7/v7/v3），py3.8 / 3.10 / 3.12 三档全绿。
- **清掉历史格式化残留**：早期批量 `re.sub` 把 `\n` 写成 `\n\n`，
  `registry.py` 里塞了 368 行空行（38.9%），连 `TypedDict` 字段之间、
  `tk.Text(...)` 参数之间都被插空行；另有同一行重复导入被拆分器原样带进 9 个文件。

## 五、仍已知未修（留档）

- **`rot8000` 只旋转可打印 ASCII**，不是整个 BMP。它能自洽往返，且
  "ROT8000" 在社区有多个互不兼容的定义，改动会让它和某一边对不上 —— 故保持现状。
- **`xxencode` 的解码对最后一行依赖循环变量**，能往返但写法脆弱；
  本轮给它补了与 uuencode 一致的 `begin/end` 信封，未重写分组逻辑。
- `shellcode_decode` 对「无 `\x` 前缀的裸十六进制」走 `bytes.fromhex` 兜底，
  奇数长度输入会落到 `'[!] 无法解析'`。

## 验证方式

- `python -m unittest discover -s tests -t .` → **116 项全绿**（跳过 3 项，均为 fastapi 相关）；
- 用带 tkinter 的系统 Python 3.12 复跑，跳过数从 14 降到 3 —— **GUI 路径这次是真的跑过了**
  （托管 Python 3.13 无 tkinter，此前的 GUI 测试长期静默 skip）；
- `python -m compileall yang_web tests` 全绿；
- 8 次拆分的 `diff_api` 输出全部 `全部一致`。

