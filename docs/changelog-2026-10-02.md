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
