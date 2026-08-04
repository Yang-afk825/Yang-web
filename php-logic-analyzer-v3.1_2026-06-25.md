# PHP Logic Analyzer v3.1 — 多层条件绕过求解器

## 背景
用户要求针对第三道题（http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn）优化引擎，
并强调"不是只做一道题的工具"，需要引擎能识别不同类型挑战自动分流。

## 问题本质
前三道题的区别：

| 题号 | 类型 | PHP 源码特征 | 引擎需要的能力 |
|------|------|-------------|---------------|
| 1 | RCE (system) | `system($_POST['a'])` | 漏洞指纹 + 命令注入 |
| 2 | RCE (eval) | `eval($_POST['a'])` | 漏洞指纹 + PHP代码包装 |
| 3 | PHP 多层绕过 | 5层if条件链 | **源码逻辑分析 + 条件求解** |

第三题是全新的题型——不是漏洞利用，而是 PHP 条件绕过。需要解析源码、
识别条件链、匹配绕过技巧。

## 完成的改进

### 1. HTML 实体解码修复 (SmartFingerprinter)
- `&nbsp;` 等 HTML 实体现在用 `html.unescape()` 完整解码
- 修复了 `system&nbsp;()` 无法匹配 `system\s*\(` 的 false-negative

### 2. 命令注入分隔符修复 (AdaptiveScheduler)
- flag 读取 payload 从 `replace` 改为 `append` + `;` 前缀
- 修复 `ping -c 1 cat /flag`（无注入）→ `ping -c 1 ;cat /flag`（正确注入）

### 3. eval() PHP 代码包装 (AdaptiveScheduler)
- 检测指纹中的 `eval()` → 自动包 `system('...');` 壳
- `eval('cat /flag')` 语法错误 → `eval("system('cat /flag');")` 正确

### 4. PHP Logic Analyzer 新模块 (`yang_web/core/php_logic.py`) ★核心

**架构：统一入口，自动分流**
```
analyze_url() → SmartFingerprinter
  ├─ 检测 PHP 源码
  ├─ 有 if 条件链? → PHP Logic Analyzer → PHP_BYPASS 类型
  └─ 无? → 现有漏洞引擎 → RCE/SQLi/LFI 利用
```

**条件提取：**
- 正则分解嵌套 if 条件
- 按 `&&` 拆分为子条件
- 提取 GET/POST 参数名

**绕过知识库（5 条规则）：**
1. `preg_match $ anchor + strict !==` → 末尾加 `\n`
2. `intval(x) < N && intval(x+1) > M` → 科学计数法如 `2022e1`
3. `sha1 collision` → 数组→"Array" 碰撞
4. `POST isset + truthy` → 数组绕过
5. `POST key with dot` → 尝试括号嵌套（当前未 work）

**测试结果：** 5/5 层全部识别，L1-L3 可自动求解，L4 因 PHP `.`→`_` 转换待研究。

### 5. 统一自动分流 (auto_exploit)
- 检测到 `PHP_BYPASS` 类型 → 走 bypass 引擎
- 否则走并发攻击引擎
- GUI 用户无感知，点"一键解题"自动选择策略

## 已知限制
- L4 (`$_POST['SYC_GEEK.2023']` 带点号) 的绕过需要 PHP 版本特定行为
  - 在 Apache 2.4.10 + PHP 5.5 上无法通过嵌套数组绕过
  - 可能需要在特定 PHP 版本或配置下才能工作
