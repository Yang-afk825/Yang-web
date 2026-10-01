# 2026-10-01 工程化修复记录

本轮针对 v4.0 做了一次工程化体检并修复，共 3 个提交。

## 一、修复：解码器的真实 bug

**现象**：README 里承诺的示例本身就是坏的。

```bash
$ yang-web decode "ZmxhZ3t0ZXN0fQ=="
→ FMoUA␦W␦        # 实际输出（乱码）
→ flag{test}      # README 承诺
```

**根因**（三个缺陷叠加）：

1. `_is_base91` 的「特殊字符」判据里包含 `{` `}` `_` `.`，于是**任何 `flag{...}` 形式的明文**都拿到 80 分，被判为 base91。而 `chain_decode` 的停止阈值是「置信度 < 75 才停」，80 分顺利放行，明文被继续解码成乱码并作为最终结果输出。
2. `is_printable()` 认为 `U+FFFD`（替换字符）可打印，因此兜不住乱码。
3. `_is_base58` 只做字符集匹配就给固定 85 分。而 **hex 字符集（0-9a-f）是 base58 字母表的子集**，导致 hex 串被 base58 抢走优先解码，base16 反而轮不上。

**修复**：

- 新增 `utils.text_quality()`，对 `U+FFFD` 重罚；
- `chain_decode` 增加「质量回退即终止」护栏 —— 仅在链**已产出可读结果后**启用，避免误伤 base58 这类解码产物本就是二进制的编码类型；
- 收紧 `_is_base91` / `_is_base92` / `_is_base58` 判据（`{}_.` 不再计入特殊字符；去掉无条件兜底分；要求最小长度）；
- `detect_encoding` 中把 `base58` 的注册顺序移到 `base64` 之后 —— 同分时让更常见的 base64 优先。

**验证**：base64 / hex / base32 / URL / base64×2 / hex→base64 均正确解出；明文不再被二次解码成乱码。

## 二、配置与元数据

| 项 | 修改前 | 修改后 |
|---|---|---|
| `pyproject.toml` version | `2.0.0` | `4.0.0` |
| Repository / Homepage | `github.com/XiaoYang/yang-web`（不存在） | `github.com/Yang-afk825/Yang-web` |
| 作者邮箱 | `xiaoyang@example.com`（占位） | 真实邮箱 |
| 依赖声明 | 无 | `dependencies = []` + `optional-dependencies`（web / desktop / scripts） |
| `[tool.setuptools_scm]` | 存在但仓库无 tag、未安装 → 会污染构建版本 | 移除 |
| `requirements.txt` | 无 | 新增 |

README 中「完全离线，零第三方依赖」「零 pip 依赖，Python 标准库一把梭」等表述与实际不符 ——
核心引擎确实零依赖，但 **Web 界面依赖 FastAPI**。已改为准确表述并补上安装步骤。

## 三、仓库卫生

- 7 个调试产物（`*_debug.log`、`boot.log`、`bypass_response.txt`、`full_response.html`、`php_logic_test.json` 等）此前被 git 跟踪，已撤销跟踪；
- 10 份临时工作笔记与旧版文档移出根目录；
- `.git-rewrite/`（filter-repo 残留）、`_chrome_profile2/`（11 MB）移出；
- 以上全部**移动而非删除**，收纳于 `_archive_2026-10-01/`，确认无用后可整目录删除；
- `.gitignore` 补通配规则（`*.log`、`*_debug.*`、`_archive_*/`），并修正 `tests/_*` 会连带忽略 `tests/__init__.py` 的问题。

## 四、测试与代码质量

- 新增 `tests/` 测试套件，**零依赖**（标准库 unittest）：

  ```bash
  python -m unittest discover -s tests -t . -v
  ```

  覆盖解码器回归用例 + 95 种密码 roundtrip。当前 **15 tests passed**。

- 95 种密码 roundtrip 实测 89 项通过；以下 6 项为已知限制（历史遗留或设计使然，非回归）：

  | 密码 | 说明 |
  |---|---|
  | `pigpen` | 符号映射非单射（E 与 R 同符号），roundtrip 原理上不成立 |
  | `jefferson_wheel` | 需要特定转轮密钥格式 |
  | `fes_hieroglyph` | 设计为单向解码 |
  | `blue_punch_card` | 设计为单向解码 |
  | `ieee754` | float32 精度损失 |
  | `prime_factor` | 质因数分解为单向运算 |

- 25 处裸 `except:` 收窄为 `except Exception:` —— 裸 except 会连 `KeyboardInterrupt` 一起吞掉，导致长任务无法用 Ctrl-C 中断。

## 五、尚未处理

- `knowledge/Des-CTF-Knowledge` 子模块有 17 处未提交改动（`articles/*.meta.md` 被删/改，疑似 Windows Defender 拦截所致），**未擅自恢复**，以免覆盖意外工作；
- `pigpen` 符号表需要重做才能可逆；
- 巨型文件拆分（`gui.py` 165 KB、`url_analyzer.py` 121 KB）—— 动静最大，待单独评估。

---

# 第二轮：能力整合（2026-10-01 续）

第一轮解决的是「对不对」，这一轮解决的是**「能不能被复用和编排」**。
原先的核心能力都散在 `scripts/` 里当独立脚本跑，CLI 的子命令各管各的，
`solve` 则是把输入无脑丢给脚本库试跑 —— 命中全靠运气。

## 一、行尾规范化（独立提交）

**问题**：20 个文本文件的行尾被污染成 `\r\r\n`（多重 CR），且**已随历史提交入库**。
后果是任何一次编辑都会产生整文件级 diff，在 Linux/macOS 上协作时会污染字符串处理。

**处理**：

- 20 个文件统一 `\r\r\n` → `\r\n`（与仓库另 1387 个正常文件一致）；
- 新增 `.gitattributes`（`* text=auto` + 显式二进制标记），防止复发；
- 验证：`git diff --ignore-all-space` 下无实质差异，`compileall` 通过，测试全绿。

## 二、把纯算法上提为 core 引擎

`scripts/rsa_toolkit.py` 原先是一份只能手动运行的独立脚本，既无法被自动解题编排调用，
也无法被 CLI / GUI 复用。上提为 `core/crypto_attack.py` 后：

- 攻击实现：已知 p/q 解密、低指数、共模、Wiener、Fermat、Håstad 广播、小 e 枚举；
- 编排入口 `solve_rsa()`：按已知参数自动挑可行攻击，返回 `results` / `tried` / `success`；
- **修复原版 bug**：`attack_wiener()` 原先调用 `rsa_decrypt(p, q, e, None)`，`pow(None, ...)` 直接 TypeError；
- **修复语义不一致**：`fermat` 原先只在命中时才记入 `tried`，与其它攻击的 `_record` 语义相反，
  导致"为什么没结果"解释不完整；
- `scripts/rsa_toolkit.py` 保留为兼容壳，转发到引擎，旧调用方式不受影响。

新增 `solve_rsa_auto()`：**e 未知时枚举常见公钥指数**（65537 / 3 / 17 / 5 / 7）。
真实题目里题干只给 n、c 的情况并不少见，此时若把 e 当 0 传进去，低指数与 Wiener
都会失去入口，白白漏解。

## 三、`crypto` 子命令：让引擎能被直接使用

```
yang-web crypto --list
yang-web crypto --p <p> --q <q> --e <e> --c <c>
yang-web crypto --n <n> --e 3 --c <c>
yang-web crypto --n <n> --c <c>            # e 未知 → 自动枚举
yang-web crypto --fermat <n>
yang-web crypto --broadcast --e 3 --n <n1,n2,n3> --c <c1,c2,c3>
yang-web crypto ... --json | --raw
```

## 四、题型识别器 `core/triage.py`

自动解题的正确顺序是「先识别、后行动」。补上缺失的识别环节：

- `identify_bytes()`：按魔数识别 zip/png/jpeg/gif/pcap/pcapng/elf/pe/pdf/rar/7z/gzip/bzip2/tar 等；
- `parse_rsa_params()`：支持 `n = ...` 标签题面**也**支持裸大整数串；
- `triage()`：输出 `{"kind", "confidence", "evidence", "paths", "alternatives"}`，
  `paths[].cmd` 是**可直接复制执行**的下一步。

**过程中发现并修掉的两个问题**：

1. 最初的 RSA 判据是「≥2 个 20 位以上整数」。但 `e` 常常只有 5 位（65537）甚至 1 位（3），
   于是参数解析不全、自动攻击直接失败，生成的命令还把 `c` 误标成了 `e`。
   改为标签优先解析 + 裸串兜底后解决；
2. 识别为「编码」的门槛过低。编码检测器对**任意字母文本**都会给出
   `rot13 ≈ 50` / `rot47 ≈ 15` 这类兜底分（本质只是"都是字母"），
   并不构成编码证据 —— 普通英文会被判成编码题。实测真实编码串最低 75 分，
   因此加了一道 60 分下限。

## 五、管道数据流

- `decode --raw` / `encode --raw`：只输出结果本身，可直接接入管道；
- `solve` / `crypto` 支持从 stdin 读取（`crypto` 会从上游输出里抓整数当 n/e/c）；
- `solve --json` / `crypto --json`：结构化输出，便于脚本消费。

```bash
$ yang-web decode "ZmxhZ3t0ZXN0fQ==" --raw | yang-web solve
```

## 六、`solve` 改造为真的分类器

原先：把输入丢给脚本库盲目试跑，列出 48 个脚本的成功/失败。

现在：**识别 → 给依据 → 给可复制执行的路径 → 自动执行安全的离线动作**。
自动执行部分**只做本地计算**（解码 / 散列识别 / RSA 运算）；
涉及目标的 `url` / `scan` 路径**只作为建议列出，不会替你发起请求**。

## 七、GUI「送到下一步」

面板间数据流打通：

- 新增路由注册表 `register_route()` / `route_text()`；
- 解码 / 高级编码 / 中文密码 / 加解密 / Misc Crypto 五个面板挂上发送条；
- 路由在面板构造**之后**才注册，因此发送条按钮采用「注册时统一重建」的惰性方案；
- 送出内容依次尝试：显式 `_last_result` → 输出区末行 → 输入框原文；
  纯分隔线（`──` / `══`）不算有效内容 —— 否则链式解码送出去的会是那行 `═════`；
- 写入时自动区分 `Text` 与 `Entry`（Misc Crypto 用的是 Entry）。

## 八、测试

从 15 项扩到 **75 项**：

| 文件 | 覆盖 |
|---|---|
| `tests/test_triage.py` | 分类正确性、RSA 标签/裸串解析、大 e 与小 e、散文不误判、魔数、返回结构 |
| `tests/test_crypto_attack.py` | 数论工具、六种攻击各构造已知答案算例、`tried` 语义、`solve_rsa_auto` 枚举 |
| `tests/test_gui_routing.py` | 发送条重建、Text/Entry 双类型写入、空内容与未注册目标、末行跳过分隔线（无 tkinter 自动跳过） |

两个解释器都跑通：托管 Python 3.13（68 通过 + 7 跳过）、系统 Python 3.12 带 tkinter（75 通过）。

## 九、本轮仍未处理

- `gui.py` 存在**局部双倍行距**（`class DecodePanel` 等区域每个语句之间夹一个空行），
  纯可读性问题；自动折叠有踩坏多行字符串的风险，未做；
- `knowledge/Des-CTF-Knowledge` 子模块 17 处未提交改动，仍未擅自恢复；
- 巨型文件拆分（`gui.py`、`url_analyzer.py`）待单独评估。

