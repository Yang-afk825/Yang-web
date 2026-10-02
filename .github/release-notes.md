Yang-Web —— CTF 一站式离线工具箱（Windows x64 桌面版）

## 下载
- **Yang-Web.exe** —— 独立桌面窗口，双击即用，无需安装 Python。
  运行需要系统具备 WebView2 运行时（Windows 10/11 通常已自带）。
- **Yang-Web.exe.sha256** —— 校验和，可用于核对下载是否完整。

## 关于这个包
- 由 GitHub Actions 在 windows-latest 上从对应 tag 的源码构建，
  **构建前会先跑一遍全部单元测试**，测试不过则不会发布。
- 核心引擎（解码 / 95 种密码 / Payload / 攻击引擎）零第三方依赖，仅用 Python 标准库。
- Web UI 形态需 FastAPI + uvicorn，按需安装，详见 README。
- CTF 知识库（Des-CTF-Knowledge）是独立仓，不随 exe 分发；
  需要时 clone 到 `~/Des-CTF-Knowledge` 或用环境变量 `CTF_KB_DIR` 指向其根目录。

## 历史版本与源码
- 每个 tag 对应一份源码快照，README 的「免安装」入口始终指向最新 Release。
- 源码形态：`git clone --recurse-submodules <repo>` 后
  `python -m yang_web --help` 即可用命令行，无需安装任何第三方包。
