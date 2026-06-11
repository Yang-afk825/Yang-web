"""内建 CTF Web 词库."""
import os


def get_wordlist_path(name: str) -> str:
    """获取词库文件路径.

    Args:
        name: 词库名 (dirs / files)
    """
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    return os.path.join(data_dir, f"{name}.txt")


def load_wordlist(name: str) -> list:
    """加载词库.

    Args:
        name: 词库名 (dirs / files)
    """
    path = get_wordlist_path(name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
