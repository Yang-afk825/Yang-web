# 2026-06-25 智能攻击面板修复

## 问题
用户测试 CTF URL `http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn` → 分析出0结果 → 无攻击按钮可点。

## 根因
1. **PHP源码参数检测缺失**: 页面是 `highlight_file(__FILE__)` 输出语法高亮的PHP源码，没有HTML表单。`crawl_page` 只看HTML表单/链接，找不到 `$_GET['cmd']`。
2. **返回按钮被裁剪**: v7 代码中 `hdr.pack_propagate(False)` + `height=36` 把 `⬅️ 返回漏洞列表` 按钮裁剪到不可见/不可点击。

## 修复
1. **url_analyzer.py**: 新增PHP源码参数扫描 → 先 `re.sub(r'<[^>]+>', '', body)` 去HTML标签 → 再regex匹配 `$_GET['xxx']`/`$_POST['xxx']`/`$_REQUEST['xxx']`
2. **gui.py v8**: 去掉 `pack_propagate(False)` → 返回按钮不再被裁剪

## 验证
```python
# CLI测试确认
analyze_url('http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn')
# → RCE, 90% confidence, params=['cmd'], 9 payloads
execute_attack(...)
# → HTTP 200, 3383B, 66ms (成功注入)
```

## 文件
- `yang_web/core/url_analyzer.py` — 新增 PHP 源码参数扫描
- `yang_web/gui.py` — v8: 去掉 pack_propagate, 标题 ★ v8 ★
