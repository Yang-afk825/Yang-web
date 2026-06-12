# -*- coding: utf-8 -*-
"""åå»º CTF Web è¯åº."""
import os


def get_wordlist_path(name: str) -> str:
    """è·åè¯åºæä»¶è·¯å¾.

    Args:
        name: è¯åºå (dirs / files)
    """
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    return os.path.join(data_dir, f"{name}.txt")


def load_wordlist(name: str) -> list:
    """å è½½è¯åº.

    Args:
        name: è¯åºå (dirs / files)
    """
    path = get_wordlist_path(name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
