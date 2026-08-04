# -*- mode: python ; coding: utf-8 -*-
"""Yang-Web v4.0 PyInstaller 打包配置"""
import os

# SPECPATH 是 PyInstaller 提供的 spec 所在目录
project_root = os.path.abspath(SPECPATH)

# pythonnet 官方 PyInstaller hook (打包 clr 运行时 DLL)
import site as _site
_pn_hook = None
for _p in _site.getsitepackages() + [_site.getusersitepackages()]:
    _cand = os.path.join(_p, 'pythonnet', '_pyinstaller')
    if os.path.isdir(_cand):
        _pn_hook = _cand
        break
print('pythonnet hook dir:', _pn_hook)

a = Analysis(
    [os.path.join(project_root, 'launch_win.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        # Web UI 静态资源
        (os.path.join(project_root, 'yang_web', 'web'), 'yang_web/web'),
    ],
    hiddenimports=[
        # 引擎依赖
        'yang_web.core.decoder',
        'yang_web.core.hashid',
        'yang_web.core.jwt',
        'yang_web.core.misc_crypto',
        'yang_web.core.crypto_engine',
        'yang_web.core.chinese_ciphers',
        'yang_web.core.advanced_engines',
        'yang_web.core.url_analyzer',
        'yang_web.core.bashfuck',
        'yang_web.core.bashfuck_solver',
        'yang_web.core.js_challenge_solver',
        'yang_web.core.multi_stage',
        'yang_web.core.php_eval_rce',
        'yang_web.core.php_lfi',
        'yang_web.core.php_logic',
        'yang_web.core.php_unserialize',
        'yang_web.core.smart_solver',
        'yang_web.core.sqli_labs_solver',
        'yang_web.core.ssrf_rebind',
        'yang_web.core.advanced_scanner',
        'yang_web.scripts.registry',
        'yang_web.scripts.runner',
        'yang_web.payloads.ssti',
        'yang_web.payloads.sqli',
        'yang_web.payloads.lfi',
        'yang_web.payloads.ssrf',
        'yang_web.payloads.xss',
        'yang_web.payloads.php',
        'yang_web.payloads.upload',
        # webview + uvicorn
        'webview',
        'uvicorn',
        'fastapi',
        'pydantic',
    ],
    hookspath=[_pn_hook] if _pn_hook else [],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Yang-Web',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # 无控制台窗口
    disable_windowed_traceback=False,
    icon=os.path.join(project_root, 'icon.ico') if os.path.exists(os.path.join(project_root, 'icon.ico')) else None,
)
