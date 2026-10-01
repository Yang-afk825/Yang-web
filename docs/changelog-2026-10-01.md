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
