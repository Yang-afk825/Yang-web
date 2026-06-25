# 智能攻击模块 v3.0 优化 — 2026-06-25

## 目标
优化 Yang-Web 项目的智能攻击模块，从"空壳子"变成真正能解决问题的工具。

## 测试目标
http://80-dd97d346-4448-4740-84d8-7c00b6a0c1f1.challenge.ctfplus.cn
- HelloCTF RCE-labs 题目
- `system($_POST['a']);` + `highlight_file(__FILE__);`
- Flag: `Geesec{19b7d146-27a7-4667-b8dc-8fbaea2f17fa}`

## 改动文件
- `yang_web/core/url_analyzer.py` — 核心引擎重构（新增 ~400 行）
- `yang_web/gui.py` — UI 适配 v3.0 引擎 + 线程安全修复

## 核心优化 (4 项)

### 1. SmartFingerprinter（智能指纹识别）
- 新增类：检测 CMS/WAF/PHP 源码漏洞
- 从响应中提取 `system()/exec()/shell_exec()/eval()` 等危险函数
- 提取 `$_GET/$_POST/$_REQUEST` 参数及方法（GET vs POST）
- CMS 指纹：WordPress/ThinkPHP/Flask/Django/Laravel/Spring 等
- WAF 指纹：阿里云/Cloudflare/360/ModSecurity/腾讯云等

### 2. ConcurrentEngine（并发攻击引擎）
- ThreadPoolExecutor 并发执行（默认 15 线程）
- 指数退避重试（最多 3 次）
- 早期退出：发现 flag 立即停止所有任务
- 线程安全：Lock 保护 flag 状态

### 3. AdaptiveScheduler（自适应调度器）
- 基于指纹结果重新排序攻击载荷
- 源码发现 `system()` → RCE 优先；发现 `include($var)` → LFI 优先
- 自动选择 HTTP 方法（源码头有 `$_POST` → 自动用 POST）
- 按 CTF 优先级排序：RCE > PHP > LFI > SQLi > SSTI > SSRF > Upload > XSS
- 低信心猜测（<20%）自动跳过

### 4. analyze_url 增强
- 新增 Step 0：始终获取页面做源码指纹分析
- 从源码提取的漏洞直接加成到 evidence（+40% 信心）
- 返回结果新增 `fingerprint` 字段供调度器使用

## Bug 修复 (共 6 项)

1. **POST 请求降级为 GET**：`execute_attack` 中 `form_inputs=None` 时 POST 被跳过 → 自动构造 `{param: payload}` body
2. **并发引擎 flag 丢失**：`attack_batch` 返回类型改为 `(results, flag)` 元组
3. **孤儿代码**：确认漏洞收集的 for 循环被意外删除 → 已修复
4. **硬编码调试路径**：移除 `C:\Users\阳\...\solve_debug.log`
5. **Flag 格式遗漏**：添加 `Geesec{`、`DASCTF{` 到 match 列表和 FLAG_RE
6. **GUI 线程崩溃 + NameError**（用户反馈"点击后消失"）：
   - 并发引擎 15 线程同时操作 tkinter → 主循环崩溃 → queue.Queue + after(50) 序列化到主线程
   - `_process_queue()` 调用在定义之前 → NameError → 重排定义顺序
   - `_auto_solve` 无异常保护 → 拆分 `_auto_solve`(外壳) + `_auto_solve_inner`(实现) 捕获所有异常

## 实测对比

| 指标 | v2.0 (旧) | v3.0 (新) |
|------|-----------|-----------|
| 分析准确度 | SQLi 30% + XSS 25%（全错） | RCE 100% + POST(a) ✓ |
| 攻击速度 | 串行 | 29 任务 / 0.1s 并发 |
| Flag 获取 | ❌ 无法获取 | ✅ Geesec{...} |
| 总耗时 | N/A | 0.3s |
| 指纹能力 | 无 | CMS/WAF/源码漏洞检测 |
| GUI 线程安全 | ❌ 并发崩溃 | ✅ queue + after 序列化 |

## 设计原则
- 零外部依赖（仅 stdlib：concurrent.futures、threading、urllib、queue）
- 向后兼容（旧 API 保留）
- 线程安全（Lock + queue 序列化）
