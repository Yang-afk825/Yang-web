# -*- coding: utf-8 -*-
"""Built-in CTF wordlists â common passwords, usernames, directory names.

No external files needed â all wordlists embedded.
"""

from __future__ import annotations

COMMON_PASSWORDS = [
    "admin", "system", "administrator", "123456", "654321", "111111",
    "222222", "333333", "444444", "555555", "666666", "777777",
    "888888", "999999", "000000", "admin888", "admin123", "system123456",
    "password", "passwd", "pass", "root", "toor", "ctfshow", "ctf",
    "flag", "guest", "test", "user", "qwerty", "abc123", "12345678",
    "123456789", "iloveyou", "monkey", "dragon", "master", "letmein",
    "login", "welcome", "admin666", "admin@123", "P@ssw0rd",
]

COMMON_USERNAMES = [
    "user", "admin", "guest", "administrator", "system", "root",
    "test", "ctf", "ctfshow", "www", "web", "mysql", "oracle",
    "postgres", "ftp", "anonymous", "sa", "backup", "support",
]

COMMON_DIRS = [
    "admin", "login", "backup", "bk", "bak", "www", "web",
    "uploads", "upload", "files", "data", "db", "sql",
    "api", "v1", "v2", "test", "dev", "debug", "logs",
    "tmp", "temp", "cache", "config", "conf", "css", "js",
    "images", "img", "static", "assets", "robots.txt",
    "phpinfo.php", "info.php", "phpmyadmin", ".git",
    ".svn", ".hg", ".env", ".htaccess", "shell.php",
    "cmd.php", "1.php", "flag", "flag.txt", "flag.php",
]

COMMON_FILES = [
    "index.php", "index.html", "index.asp", "index.aspx",
    "index.jsp", "login.php", "admin.php", "config.php",
    "config.inc.php", "conn.php", "db.php", "database.php",
    "common.php", "function.php", "functions.php", "header.php",
    "footer.php", "global.php", "readme.txt", "README.md",
]


def get_username_wordlist() -> list:
    return COMMON_USERNAMES


def get_password_wordlist() -> list:
    return COMMON_PASSWORDS


def get_dir_wordlist() -> list:
    return COMMON_DIRS


def get_file_wordlist() -> list:
    return COMMON_FILES


def combined_wordlist(include_common: bool = True) -> list:
    """All wordlists combined, sorted by CTF relevance."""
    result = list(COMMON_DIRS) + list(COMMON_FILES)
    if include_common:
        result += COMMON_PASSWORDS + COMMON_USERNAMES
    return sorted(set(result))


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print("Usage: python wordlist_helper.py <type>")
        print("  pass     Common passwords")
        print("  user     Common usernames")
        print("  dir      Common directories")
        print("  file     Common filenames")
        print("  all      Combined wordlist")
        sys.exit(0)

    cmd = sys.argv[1]
    mapping = {
        "pass": COMMON_PASSWORDS,
        "user": COMMON_USERNAMES,
        "dir": COMMON_DIRS,
        "file": COMMON_FILES,
        "all": combined_wordlist(),
    }

    if cmd in mapping:
        for item in mapping[cmd]:
            print(item)
        print(f"\n[total: {len(mapping[cmd])}]")
    else:
        print(f"Unknown type: {cmd}")
