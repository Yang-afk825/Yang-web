# -*- coding: utf-8 -*-
"""Misc Crypto ç¥è¯åº â å¸¸è§å¯ç ç±»åç¼ç /è§£ç  + åèå¾è¡¨.

è¦ç CTF Misc æ¹å 30+ ç§å¸¸è§å¯ç /ç¼ç ç±»åï¼æä¾ç¼ç /è§£ç ç®æ³åè§è§åèã
"""
import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "data" / "misc_crypto"

# âââââââââââââââââââââââââââââââââââââââââââ
# æ°æ®è¡¨ / å¸¸é
# âââââââââââââââââââââââââââââââââââââââââââ

# çªåå¯ç  (Pigpen) â 4 å®«æ ¼åä½
PIGPEN_ENCODE = {
    'A': 'ð', 'B': 'ð', 'C': 'ð', 'D': 'ð', 'E': 'â',
    'F': 'â', 'G': 'â ', 'H': 'â¡', 'I': 'ð¥', 'J': 'ð§',
    'K': 'ð¤', 'L': 'â', 'M': 'â ', 'N': 'â¡', 'O': 'ð¢',
    'P': 'ð£', 'Q': 'ð¦', 'R': 'â', 'S': 'â', 'T': 'â¡',
    'U': 'â»ð­', 'V': 'â»â', 'W': 'â»â', 'X': 'â»â¡', 'Y': 'â»ð¤', 'Z': 'â»ð§',
}

# å¹æ ¹å¯ç  (Bacon) â 24 å­æ¯ A/B ç¼ç 
BACON_24 = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
    'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
    'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
    'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
    'Z': 'BBAAB',
}

# Polybius æ¹éµ (5x5, I/J merged)
POLYBIUS_GRID = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
]

# é®çåæ  (æ å QWERTY è¡)
KEYBOARD_ROWS = {
    'row1': 'QWERTYUIOP',
    'row2': 'ASDFGHJKL',
    'row3': 'ZXCVBNM',
}

# QWE å å¯æ³ (Q=A, W=B, E=C...)
_QWE_ORDER = "QWERTYUIOPASDFGHJKLZXCVBNM"
_ABC_ORDER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
QWE_ENCODE = dict(zip(_ABC_ORDER, _QWE_ORDER))
QWE_DECODE = dict(zip(_QWE_ORDER, _ABC_ORDER))

# é®çæ£çå¯ç  (1-9å®«æ ¼æ å°)
KEYBOARD_CHESSBOARD = {
    'Q': '11', 'W': '12', 'E': '13', 'R': '14', 'T': '15', 'Y': '16', 'U': '17', 'I': '18', 'O': '19', 'P': '10',
    'A': '21', 'S': '22', 'D': '23', 'F': '24', 'G': '25', 'H': '26', 'J': '27', 'K': '28', 'L': '29',
    'Z': '31', 'X': '32', 'C': '33', 'V': '34', 'B': '35', 'N': '36', 'M': '37',
}
CHESSBOARD_DECODE = {v: k for k, v in KEYBOARD_CHESSBOARD.items()}

# ææºé®çå¯ç  (T9)
PHONE_KEYPAD = {
    'A': '21', 'B': '22', 'C': '23', 'D': '31', 'E': '32', 'F': '33',
    'G': '41', 'H': '42', 'I': '43', 'J': '51', 'K': '52', 'L': '53',
    'M': '61', 'N': '62', 'O': '63', 'P': '71', 'Q': '72', 'R': '73', 'S': '74',
    'T': '81', 'U': '82', 'V': '83', 'W': '91', 'X': '92', 'Y': '93', 'Z': '94',
}
PHONE_DECODE = {v: k for k, v in PHONE_KEYPAD.items()}

# æ åé¶æ²³å­æ¯ (SGA) â Minecraft éé­å°
SGA_CHARS = {
    'A': 'á', 'B': 'Ê', 'C': 'áµ', 'D': 'â¸', 'E': 'á·',
    'F': 'â', 'G': 'â£', 'H': 'â', 'I': 'â', 'J': 'â®',
    'K': 'ê', 'L': 'ê', 'M': 'á²', 'N': 'ãª', 'O': 'ð¹',
    'P': '!',  'Q': 'á', 'R': 'â·', 'S': 'á­', 'T': 'â¸',
    'U': 'â', 'V': 'â', 'W': 'â´', 'X': '/', 'Y': 'â',
    'Z': 'â',
}
SGA_DECODE = {v: k for k, v in SGA_CHARS.items() if len(v) == 1}

# ADFGX å¯ç è¡¨ (5x5)
ADFGX_TABLE = {
    'A': 'AA', 'B': 'AF', 'C': 'AD', 'D': 'AD', 'E': 'FG',
    'F': 'AX', 'G': 'AG', 'H': 'FV', 'I': 'FX', 'J': 'FX',
    'K': 'GA', 'L': 'GD', 'M': 'GG', 'N': 'GX', 'O': 'GF',
    'P': 'GV', 'Q': 'XA', 'R': 'XD', 'S': 'XG', 'T': 'XF',
    'U': 'XV', 'V': 'VA', 'W': 'VG', 'X': 'VF', 'Y': 'VD',
    'Z': 'VX',
}

# å½éºå¯ç  â ä¸­æç¬ç»æ°æ å°æ°å­
PAWNSHOP_MAP = {
    'å£': 0, 'ç±': 1, 'ä¸­': 2, 'äºº': 3, 'å·¥': 4,
    'å¤§': 5, 'ç': 6, 'å¤«': 7, 'äº': 8, 'ç¾': 9,
}
PAWNSHOP_REV = {v: k for k, v in PAWNSHOP_MAP.items()}

# æé©¬æ¯Â·æ°æéè½¬è½®å¯ç ï¼é»è®¤è½®å­ï¼
JEFFERSON_ROTORS = [
    "ZWAXJGDLUBVIQHKYPNTCRMOSFE", "KPBELNACZDTRXMJQOYHGVSFUWI",
    "BDMAIZVRNSJUWFHTEQGYXPLOCK", "RPLNDVHGFCUKTEBSXQYIZMJWAO",
    "IHFRLABEUOTSGJVDKCPMNZQWXY", "AMKGHIWPNYCJBFZDRUSLOQXVET",
    "GWTHSPYBXIZULVKMRAFDCEONJQ", "NOZUTWDCVRJLXKISEFAPMYGHBQ",
    "QWATDSRFHENYVUBMCOIKZGJXPL", "WABMCXPLTDSRJQZGOIKFHENYVU",
    "XPLTDAOIKFZGHENYSRUBMCQWVJ", "TDSWAYXPLVUBOIKZGJRFHENMCQ",
    "BMCSRFHLTDENQWAOXPYVUIKZGJ", "XPHKZGJTDSENYVUBMLAOIRFCQW",
]

# âââââââââââââââââââââââââââââââââââââââââââ
# å¯ç ç±»ååæ°æ®
# âââââââââââââââââââââââââââââââââââââââââââ

CIPHER_TYPES = {
    "pigpen": {
        "name": "çªåå¯ç ",
        "aliases": ["pigpen", "çªå", "masonic", "pigpen_cipher"],
        "category": "å¾å½¢æ¿æ¢",
        "encode": True, "decode": True,
        "image": "çªåå¯ç .png",
        "description": "å±æµä¼å¯ç åä½ï¼ç¨äºå­æ ¼+ç¹æ ç¬¦å·è¡¨ç¤ºå­æ¯",
        "features": ["äºå­æ ¼å¾æ¡", "å¸¦ç¹/ä¸å¸¦ç¹", "4å®«æ ¼åä½"],
    },
    "bacon": {
        "name": "å¹æ ¹å¯ç ",
        "aliases": ["bacon", "å¹æ ¹", "baconian"],
        "category": "äºè¿å¶æ¿æ¢",
        "encode": True, "decode": True,
        "image": "å¹æ ¹å¯ç .jpg",
        "description": "ç¨ A/B 5 ä½åºåè¡¨ç¤ºå­æ¯ï¼å¯éèå¨å¤§å°åä¸­",
        "features": ["AAAAA-ZZZZZ", "å¯éèå¨å¤§å°å/ç²ä½ä¸­", "24/26å­æ¯çæ¬"],
    },
    "polybius": {
        "name": "æ³¢å©æ¯å¥¥æ¯æ£ç",
        "aliases": ["polybius", "æ³¢å©æ¯å¥¥æ¯", "polybius_square"],
        "category": "åæ æ¿æ¢",
        "encode": True, "decode": True,
        "image": "æ³¢å©æ¯å¥¥æ¯æ£ç.png",
        "description": "5Ã5 æ¹éµè¡ååæ è¡¨ç¤ºå­æ¯ï¼I=Jï¼",
        "features": ["11-55è¡ååæ ", "I/Jåå¹¶", "å¯æ©å±6x6å«æ°å­"],
    },
    "vigenere": {
        "name": "ç»´åå°¼äºå¯ç ",
        "aliases": ["vigenere", "ç»´åå°¼äº", "vig"],
        "category": "å¤è¡¨æ¿æ¢",
        "encode": True, "decode": True,
        "image": "ç»´åå°¼äºå¯ç .png", "image2": "ç»´åå°¼äºå¯.png",
        "description": "ä½¿ç¨å¯é¥è¯çå¯æå¯ç åä½ï¼å¤è¡¨æ¿æ¢",
        "features": ["å¯é¥å¾ªç¯", "ç»´åå°¼äºæ¹éµ", "26Ã26è¡¨æ ¼"],
    },
    "caesar": {
        "name": "å¯æå¯ç ",
        "aliases": ["caesar", "å¯æ", "caesar_shift"],
        "category": "åè¡¨æ¿æ¢",
        "encode": True, "decode": True,
        "image": "å¯æå¯ç å å¯.jpg",
        "description": "åºå®åç§»å­æ¯è¡¨ï¼æå¤èçå å¯æ¹å¼",
        "features": ["ROT13æ¯å¶ç¹ä¾", "åç§»é1-25", "å¯æ´åæä¸¾"],
    },
    "adfgx": {
        "name": "ADFGX å å¯æ³",
        "aliases": ["adfgx", "adfgvx"],
        "category": "WWI åäºå¯ç ",
        "encode": True, "decode": True,
        "image": "ADFGXå å¯æ³.png",
        "description": "ä¸æå¾·åä½¿ç¨çåæ­¥å å¯ï¼Polybius + åç½®æ¢",
        "features": ["ä»ç¨ADFGXå­æ¯", "5Ã5 Polybius", "éè¦å¯é¥è¯"],
    },
    "qwe_keyboard": {
        "name": "QWE é®çå å¯æ³",
        "aliases": ["qwe", "é®çQWE"],
        "category": "é®çæ å°",
        "encode": True, "decode": True,
        "image": "çµèé®çQWEå å¯æ³.jpg",
        "description": "QWERTYé®çé¡ºåºæ å°ABCD...",
        "features": ["Q=A, W=B, E=C...", "é®çå¸å±", "ç®åæ¿æ¢"],
    },
    "keyboard_chessboard": {
        "name": "çµèé®çæ£çå¯ç ",
        "aliases": ["é®çæ£ç", "keyboard_chess"],
        "category": "é®çæ å°",
        "encode": True, "decode": True,
        "image": "çµèé®çæ£çå å¯.jpg",
        "description": "é®ç3è¡å¸å±ï¼è¡å·+åå·è¡¨ç¤ºæ¯ä¸ªé®",
        "features": ["Q=11, W=12...", "æ°å­åæ ", "3è¡é®çæ å°"],
    },
    "keyboard_coordinate": {
        "name": "çµèé®çåæ å å¯",
        "aliases": ["é®çåæ ", "keyboard_coord"],
        "category": "é®çæ å°",
        "encode": True, "decode": True,
        "image": "çµèé®çåæ å å¯.jpg",
        "description": "ç¨é®çç©éµè¡ååæ è¡¨ç¤ºå­æ¯",
        "features": ["è¡å·+åå·", "åæ°å­åæ ", "åèå¾"],
    },
    "phone_keypad": {
        "name": "ææºé®çå¯ç ",
        "aliases": ["phone", "ææºé®ç", "T9", "nokia"],
        "category": "æ°å­æ å°",
        "encode": True, "decode": True,
        "image": "ææºé®çå å¯è§£å¯.jpg",
        "description": "ä¼ ç»ææºä¹å®«æ ¼é®çï¼æ°å­é®+æé®æ¬¡æ°",
        "features": ["A=21, B=22...", "ä¹å®«æ ¼æ°å­", "åä½æ°å­"],
    },
    "atbash": {
        "name": "åç¹å·´ä»ç ",
        "aliases": ["atbash", "åç¹å·´ä»"],
        "category": "åè¡¨æ¿æ¢",
        "encode": True, "decode": True,
        "image": None,
        "description": "å­æ¯è¡¨åè½¬ï¼AâZ, BâY...ï¼ï¼èªåå¯ç ",
        "features": ["èªåæ§", "A=Z, B=Y...", "æç®åæ¿æ¢"],
    },
    "rail_fence": {
        "name": "æ æ å¯ç ",
        "aliases": ["rail_fence", "æ æ ", "railfence"],
        "category": "ç½®æ¢",
        "encode": True, "decode": True,
        "image": None,
        "description": "ä¹å­å½¢æååæè¡è¯»å",
        "features": ["ä¹å­å½¢", "å¤å±æ æ ", "Wååä½"],
    },
    "rot13": {
        "name": "ROT13",
        "aliases": ["rot13", "rot"],
        "category": "åè¡¨æ¿æ¢",
        "encode": True, "decode": True,
        "image": None,
        "description": "å¯æå¯ç åç§»13ä½ç¹ä¾ï¼å å¯=è§£å¯",
        "features": ["èªåæ§", "ROT5(æ°å­)", "ROT47(ASCII)"],
    },
    "morse": {
        "name": "æ©å°å¯ç ",
        "aliases": ["morse", "æ©å°", "æ©å°æ¯"],
        "category": "ä¿¡å·ç¼ç ",
        "encode": True, "decode": True,
        "image": "æ©å°å¯ç å å¯ä¸è§£å¯.jpg",
        "description": "ç¹åä¿¡å·ç¼ç ï¼å¯è¡¨ç°ä¸ºé³é¢/ç¯å/æå­",
        "features": [".- é¿ç­ä¿¡å·", "å¯éèä¸ºé³é¢", "ç©ºæ ¼/ææ åé"],
    },
    "pawnshat": {
        "name": "å½éºå¯ç ",
        "aliases": ["å½éº", "pawnshop", "pawn"],
        "category": "ä¸­æç¼ç ",
        "encode": True, "decode": True,
        "image": "å½éºå¯ç .jpg",
        "description": "æ±å­åºå¤´é¡¶é¨ç¬ç»æ°æ å°æ°å­0-9",
        "features": ["ç¬ç»å¤´æ°", "å£=0 ç±=1", "åæ°å­ç¼ç "],
    },
    "number_coordinate": {
        "name": "æ°å­åæ å å¯å­æ¯",
        "aliases": ["æ°å­åæ ", "number_coord"],
        "category": "åæ æ¿æ¢",
        "encode": True, "decode": True,
        "image": "æ°å­åæ å å¯å­æ¯.png",
        "description": "å­æ¯ç½æ ¼åæ è¡¨ç¤ºæ³ï¼è¡å·+åå·",
        "features": ["XYåæ ", "æ°å­å¯¹", "åèå¾"],
    },
    "alphabet_order": {
        "name": "å­æ¯è¡¨é¡ºåºå å¯",
        "aliases": ["å­æ¯é¡ºåº", "alphabet_order"],
        "category": "æ°å­æ å°",
        "encode": True, "decode": True,
        "image": "å­æ¯è¡¨é¡ºåºå å¯æ³ååå­æ¯è¡¨å å¯æ³åå°é®çå å¯æ³.jpg",
        "description": "A=1, B=2...çç®åæ°å­å¯¹åº",
        "features": ["A=1 B=2...", "åå­æ¯A=26", "å°é®çæ å°"],
    },
    "standard_galactic": {
        "name": "æ åé¶æ²³å­æ¯",
        "aliases": ["SGA", "æ åé¶æ²³", "galactic", "enchanting_table"],
        "category": "ç¬¦å·æ¿æ¢",
        "encode": True, "decode": True,
        "image": "æ åé¶æ²³å­æ¯.png",
        "description": "Minecraft éé­å°æå­ï¼é£æ ¼åå­æ¯æ¿æ¢",
        "features": ["Minecrafté£æ ¼", "ç¹æ®ç¬¦å·å­ç¬¦", "Unicode"],
    },
    "binary": {
        "name": "äºè¿å¶å å¯",
        "aliases": ["binary", "äºè¿å¶", "2è¿å¶"],
        "category": "è¿å¶ç¼ç ",
        "encode": True, "decode": True,
        "image": "äºè¿å¶å å¯è§£å¯.png",
        "description": "ASCII/Unicode å­ç¬¦çäºè¿å¶è¡¨ç¤º",
        "features": ["7ä½/8ä½", "ç©ºæ ¼åé", "å¯éåå¶ä»ç¼ç "],
    },
    "reverse": {
        "name": "ååºå å¯",
        "aliases": ["reverse", "ååº", "åå", "åè½¬"],
        "category": "ç½®æ¢",
        "encode": True, "decode": True,
        "image": "ååå å¯è§£å¯.png",
        "description": "å­ç¬¦ä¸²ç´æ¥åè½¬ï¼æç®åçç½®æ¢æä½",
        "features": ["ABCâCBA", "å¯åè¯/å¥å­", "éå¨åè½¬æ³¨æ"],
    },
    "jefferson_wheel": {
        "name": "æé©¬æ¯Â·æ°æéè½¬è½®å¯ç ",
        "aliases": ["jefferson", "è½¬è½®", "rotor", "è½®è½¬"],
        "category": "å¤è¡¨æ¿æ¢",
        "encode": True, "decode": True,
        "image": None,
        "description": "å¤è½®çå¯ç æºï¼å¯é¥æ¯è½®çä½¿ç¨é¡ºåº",
        "features": ["14ä¸ªè½®ç", "å¯é¥æ§å¶é¡ºåº", "ç ´è§£ééå"],
    },
    "fes_hieroglyph": {
        "name": "è²æ¯è±¡å½¢æå­",
        "aliases": ["è²æ¯", "fes", "hieroglyph"],
        "category": "ç¬¦å·æ¿æ¢",
        "encode": False, "decode": False,
        "image": "éæ¯çè±¡å½¢æå­ç¿»è¯å¾.png",
        "description": "å¾å½¢ç¬¦å·å¯¹åºå­æ¯çæ¿æ¢å¯ç ï¼ä»åèå¾ï¼",
        "features": ["è±¡å½¢å¾âå­æ¯", "è§è§åè", "éæå¨å¯¹ç§"],
    },
    "blue_punch_card": {
        "name": "èè²æå­å¡",
        "aliases": ["punchcard", "æå­å¡", "blue_punch"],
        "category": "ç¼ç åè",
        "encode": False, "decode": False,
        "image": "Blue-punch-card-front-horiz.png",
        "description": "IBM æå­å¡ç¼ç åèå¾ï¼äºè¿å¶å­å¨çæ©æå½¢å¼",
        "features": ["IBMæ ¼å¼", "80å", "ç©å½¢å­"],
    },
    # ââ åºç¡ç¼ç  ââ
    "base64": {
        "name": "Base64 ç¼ç ",
        "aliases": ["base64", "b64"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "æå¸¸è§çäºè¿å¶âææ¬ç¼ç ï¼ç»å°¾å¸¸æ=å¡«å",
        "features": ["A-Za-z0-9+/", "= å¡«å", "CTF åºåºçæé«"],
    },
    "base32": {
        "name": "Base32 ç¼ç ",
        "aliases": ["base32", "b32"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "A-Z2-7 å­ç¬¦éï¼æ¯5bitä¸ç»",
        "features": ["A-Z2-7", "= å¡«åå°8çåæ°", "å¨å¤§åå­æ¯"],
    },
    "base16": {
        "name": "Base16 / Hex ç¼ç ",
        "aliases": ["hex", "base16", "åå­è¿å¶"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "æ¯å­èâä¸¤ä½åå­è¿å¶æ°ï¼00-FFï¼",
        "features": ["0-9A-F", "å¶æ°é¿åº¦", "å¯0xåç¼"],
    },
    "base58": {
        "name": "Base58 ç¼ç ",
        "aliases": ["base58", "b58", "bitcoin"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "å»é¤äºææ··æ·å­ç¬¦çç¼ç ï¼æ 0OIlï¼ï¼Bitcoinå°åä½¿ç¨",
        "features": ["æ 0OIl", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"],
    },
    "base85": {
        "name": "Base85 / ASCII85",
        "aliases": ["base85", "b85", "ascii85"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "Adobe PostScript/PDF ä½¿ç¨çç¼ç ï¼~>ç»å°¾",
        "features": ["~> ç»å°¾", "å«ç¹æ®å­ç¬¦", "PDF/PostScript"],
    },
    "url_encode": {
        "name": "URL ç¼ç ",
        "aliases": ["url", "urlencode", "percent"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "%xx æ ¼å¼ï¼å¸¸ç¨äºWebä¼ å",
        "features": ["% ç¾åå·", "%xx åå­è¿å¶", "ç©ºæ ¼â%20æ+"],
    },
    "html_entity": {
        "name": "HTML å®ä½ç¼ç ",
        "aliases": ["html", "entity", "htmlentity"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "&amp; &lt; &#x27; ç­å½¢å¼ï¼ç¨äºHTML/XSS",
        "features": ["& å¼å¤´ ; ç»å°¾", "&#æ°å­;", "&#xåå­è¿å¶;"],
    },
    "unicode_escape": {
        "name": "Unicode è½¬ä¹",
        "aliases": ["unicode", "uescape", "\\u"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "\\uXXXX æ \\UXXXXXXXX æ ¼å¼",
        "features": ["\\u åç¼", "4ä½/8ä½åå­è¿å¶", "JSON/JSå¸¸ç¨"],
    },
    "binary_str": {
        "name": "äºè¿å¶å­ç¬¦ä¸²",
        "aliases": ["binary", "bin", "0101"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "æ¯8ä½ä¸ç» 0/1 è¡¨ç¤ºä¸ä¸ªASCIIå­ç¬¦",
        "features": ["0å1", "8ä½ä¸ç»", "ç©ºæ ¼åé"],
    },
    "octal_str": {
        "name": "å«è¿å¶å­ç¬¦ä¸²",
        "aliases": ["octal", "oct", "å«è¿å¶"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "\\ooo æ ¼å¼ï¼æ¯3ä½å«è¿å¶è¡¨ç¤ºä¸ä¸ªå­ç¬¦",
        "features": ["0-7 æ°å­", "\\ åç¼", "3ä½ä¸ç»"],
    },
    "decimal_str": {
        "name": "åè¿å¶ASCIIç ",
        "aliases": ["decimal", "dec", "ascii"],
        "category": "åºç¡ç¼ç ",
        "encode": True, "decode": True,
        "image": None,
        "description": "ç©ºæ ¼åéç10è¿å¶æ°å­ï¼æ¯ä¸ªè¡¨ç¤ºä¸ä¸ªASCIIå­ç¬¦",
        "features": ["æ°å­ 32-126", "ç©ºæ ¼åé", "ASCIIè¡¨"],
    },
}

# âââââââââââââââââââââââââââââââââââââââââââ
# ç¼ç /è§£ç å½æ°
# âââââââââââââââââââââââââââââââââââââââââââ

def _clean_text(text: str) -> str:
    return text.upper().replace(' ', '').replace('\n', '').replace('\r', '')


# ââ çªåå¯ç  ââââââââââââââââââââââââââââââ
def pigpen_encode(text: str) -> str:
    """å°å­æ¯ç¼ç ä¸ºçªåå¯ç ç¬¦å·ï¼ç¨ ASCII è¿ä¼¼è¡¨ç¤ºï¼ã"""
    result = []
    for c in _clean_text(text):
        if c in PIGPEN_ENCODE:
            result.append(PIGPEN_ENCODE[c])
        else:
            result.append(c)
    return ' '.join(result)


def pigpen_decode(symbols: str) -> str:
    """çªåå¯ç ç¬¦å· â å­æ¯ï¼ä»æ¯æé¢å®ä¹å­ç¬¦ï¼ã"""
    rev = {v: k for k, v in PIGPEN_ENCODE.items()}
    # Try splitting by common separators
    for sep in [' ', '|', '/']:
        if sep in symbols:
            parts = symbols.split(sep)
            return ''.join(rev.get(p.strip(), p.strip()) for p in parts if p.strip())
    return symbols  # can't auto-parse


# ââ å¹æ ¹å¯ç  ââââââââââââââââââââââââââââââ
def bacon_encode(text: str) -> str:
    return ' '.join(BACON_24.get(c, c) for c in _clean_text(text))


def bacon_decode(cipher_text: str) -> str:
    rev = {v: k for k, v in BACON_24.items()}
    result = []
    parts = cipher_text.replace(' ', '').lower()
    for i in range(0, len(parts) - 4, 5):
        chunk = parts[i:i+5].upper()
        result.append(rev.get(chunk, '?'))
    return ''.join(result)


# ââ Polybius æ£ç âââââââââââââââââââââââââ
def polybius_encode(text: str) -> str:
    result = []
    for c in _clean_text(text):
        if c == 'J': c = 'I'
        for row in range(5):
            for col in range(5):
                if POLYBIUS_GRID[row][col] == c:
                    result.append(f"{row+1}{col+1}")
                    break
    return ' '.join(result)


def polybius_decode(cipher_text: str) -> str:
    result = []
    nums = [n for n in cipher_text.replace(' ', '') if n.isdigit()]
    for i in range(0, len(nums) - 1, 2):
        row = int(nums[i]) - 1
        col = int(nums[i+1]) - 1
        if 0 <= row < 5 and 0 <= col < 5:
            result.append(POLYBIUS_GRID[row][col])
    return ''.join(result)


# ââ ç»´åå°¼äºå¯ç  âââââââââââââââââââââââââ
def vigenere_encode(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def vigenere_decode(cipher_text: str, key: str) -> str:
    text, key = cipher_text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


# ââ QWE é®ç ââââââââââââââââââââââââââââââ
def qwe_encode(text: str) -> str:
    return ''.join(QWE_ENCODE.get(c, c) for c in _clean_text(text))


def qwe_decode(cipher_text: str) -> str:
    return ''.join(QWE_DECODE.get(c, c) for c in _clean_text(cipher_text))


# ââ é®çæ£ç ââââââââââââââââââââââââââââââ
def keyboard_chess_encode(text: str) -> str:
    return ' '.join(KEYBOARD_CHESSBOARD.get(c, '??') for c in _clean_text(text))


def keyboard_chess_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(CHESSBOARD_DECODE.get(p, '?') for p in parts)


# ââ ææºé®ç ââââââââââââââââââââââââââââââ
def phone_encode(text: str) -> str:
    return ' '.join(PHONE_KEYPAD.get(c, '??') for c in _clean_text(text))


def phone_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(PHONE_DECODE.get(p, '?') for p in parts)


# ââ å½éºå¯ç  âââââââââââââââââââââââââââââ
def pawnshat_encode(text: str) -> str:
    result = []
    for c in text:
        if c.isdigit() and int(c) in PAWNSHOP_REV:
            result.append(PAWNSHOP_REV[int(c)])
        else:
            result.append(c)
    return ' '.join(result)


def pawnshat_decode(cipher_text: str) -> str:
    result = []
    for c in cipher_text.replace(' ', ''):
        result.append(str(PAWNSHOP_MAP.get(c, c)))
    return ''.join(result)


# ââ å­æ¯è¡¨é¡ºåº ââââââââââââââââââââââââââââ
def alphabet_order_encode(text: str) -> str:
    return ' '.join(str(ord(c) - 64) for c in _clean_text(text) if c.isalpha())


def alphabet_order_decode(cipher_text: str) -> str:
    result = []
    for n in cipher_text.split():
        try:
            result.append(chr(int(n) + 64))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ââ æ åé¶æ²³å­æ¯ âââââââââââââââââââââââââ
def sga_encode(text: str) -> str:
    return ''.join(SGA_CHARS.get(c, c) for c in _clean_text(text))


def sga_decode(cipher_text: str) -> str:
    return ''.join(SGA_DECODE.get(c, c) for c in cipher_text)


# ââ äºè¿å¶ ââââââââââââââââââââââââââââââââ
def binary_encode(text: str) -> str:
    return ' '.join(f"{ord(c):08b}" for c in text)


def binary_decode(cipher_text: str) -> str:
    clean = cipher_text.replace(' ', '').replace('\n', '').replace('\r', '').strip()
    if not clean:
        return ''
    result = []
    # Try space-separated first
    parts = cipher_text.strip().split()
    if len(parts) > 1:
        for b in parts:
            try:
                val = int(b, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    # Try 8-bit or 7-bit chunks
    for width in [8, 7]:
        result = []
        for i in range(0, len(clean), width):
            chunk = clean[i:i+width]
            if len(chunk) < width:
                continue
            try:
                val = int(chunk, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    return cipher_text


# ââ ååº ââââââââââââââââââââââââââââââââââ
def reverse_encode(text: str) -> str:
    return text[::-1]


def reverse_decode(cipher_text: str) -> str:
    return cipher_text[::-1]  # self-inverse


# ââ Caesar å¯æ ââââââââââââââââââââââââââââ
def caesar_encode(text: str, key: str = "3") -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        elif 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)


def caesar_decode(cipher_text: str, key: str = "3") -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    return caesar_encode(cipher_text, str(26 - shift))


# ââ ROT13 ââââââââââââââââââââââââââââââââââ
def rot13_encode(text: str) -> str:
    return caesar_encode(text, "13")


def rot13_decode(cipher_text: str) -> str:
    return caesar_encode(cipher_text, "13")


# ââ Atbash åç¹å·´ä» âââââââââââââââââââââââââ
def atbash_encode(text: str) -> str:
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif 'a' <= c <= 'z':
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)


def atbash_decode(cipher_text: str) -> str:
    return atbash_encode(cipher_text)  # self-inverse


# ââ Rail Fence æ æ  ââââââââââââââââââââââââ
def rail_fence_encode(text: str, key: str = "3") -> str:
    try:
        rails = max(2, int(key))
    except ValueError:
        rails = 3
    if rails >= len(text):
        return text
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for c in text:
        fence[rail].append(c)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    return ''.join(''.join(row) for row in fence)


def rail_fence_decode(cipher_text: str, key: str = "3") -> str:
    try:
        rails = max(2, int(key))
    except ValueError:
        rails = 3
    if rails >= len(cipher_text):
        return cipher_text
    n = len(cipher_text)
    # Build fence pattern
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    # Count chars per rail
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    # Slice cipher text by rail
    rails_text = []
    idx = 0
    for cnt in counts:
        rails_text.append(cipher_text[idx:idx+cnt])
        idx += cnt
    # Reconstruct
    pointers = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_text[r][pointers[r]])
        pointers[r] += 1
    return ''.join(result)


# ââ Morse æ©æ¯å¯ç  âââââââââââââââââââââââââ
MORSE_ENCODE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.',
    '@': '.--.-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', '=': '-...-', '-': '-....-', '+': '.-.-.',
    '"': '.-..-.', '\'': '.----.', '_': '..--.-', '!': '-.-.--',
}
MORSE_DECODE_MAP = {v: k for k, v in MORSE_ENCODE_MAP.items()}


def morse_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c == ' ':
            result.append('/')
        elif c in MORSE_ENCODE_MAP:
            result.append(MORSE_ENCODE_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def morse_decode(cipher_text: str) -> str:
    result = []
    for token in cipher_text.strip().split():
        if token == '/':
            result.append(' ')
        elif token in MORSE_DECODE_MAP:
            result.append(MORSE_DECODE_MAP[token])
        else:
            result.append('?')
    return ''.join(result)


# âââââââââââââââââââââââââââââââââââââââââââ
#  åºç¡ç¼ç  encode/decode (Base64/32/16/58/85/URL/HTML/Unicode/Binary/Octal)
# âââââââââââââââââââââââââââââââââââââââââââ

# ââ Base64 ââââââââââââââââââââââââââââââââ
def base64_encode(text: str) -> str:
    return b64.b64encode(text.encode('utf-8')).decode('ascii')

def base64_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    missing = len(t) % 4
    if missing:
        t += '=' * (4 - missing)
    try:
        return b64.b64decode(t, validate=True).decode('utf-8', errors='replace')
    except Exception:
        return b64.b64decode(t).decode('utf-8', errors='replace')


# ââ Base32 ââââââââââââââââââââââââââââââââ
def base32_encode(text: str) -> str:
    return b64.b32encode(text.encode('utf-8')).decode('ascii')

def base32_decode(cipher_text: str) -> str:
    t = cipher_text.strip().rstrip('=').upper()
    missing = len(t) % 8
    if missing:
        t += '=' * (8 - missing)
    try:
        return b64.b32decode(t).decode('utf-8', errors='replace')
    except Exception:
        return ''


# ââ Base16 / Hex ââââââââââââââââââââââââââ
def base16_encode(text: str) -> str:
    return text.encode('utf-8').hex()

def base16_decode(cipher_text: str) -> str:
    t = cipher_text.strip().replace(' ', '').replace('\n', '')
    if t.lower().startswith('0x'):
        t = t[2:]
    try:
        return bytes.fromhex(t).decode('utf-8', errors='replace')
    except Exception:
        return ''


# ââ Base58 ââââââââââââââââââââââââââââââââ
_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(text: str) -> str:
    data = text.encode('utf-8')
    n = int.from_bytes(data, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58_ALPHABET[r])
    # Add leading zeros
    for byte in data:
        if byte == 0:
            res.append(_B58_ALPHABET[0])
        else:
            break
    return ''.join(reversed(res))

def base58_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    n = 0
    for c in t:
        if c not in _B58_ALPHABET:
            continue
        n = n * 58 + _B58_ALPHABET.index(c)
    # Leading zeros from alphabet[0]
    leading_zeros = 0
    for c in t:
        if c == _B58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break
    try:
        result = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return (b'\x00' * leading_zeros + result).decode('utf-8', errors='replace')
    except Exception:
        return ''


# ââ Base85 ââââââââââââââââââââââââââââââââ
def base85_encode(text: str) -> str:
    try:
        return b64.a85encode(text.encode('utf-8')).decode('ascii')
    except Exception:
        return b64.b85encode(text.encode('utf-8')).decode('ascii')

def base85_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    try:
        return b64.a85decode(t.encode('ascii'), adobe=True).decode('utf-8', errors='replace')
    except Exception:
        try:
            return b64.a85decode(t.encode('ascii')).decode('utf-8', errors='replace')
        except Exception:
            try:
                return b64.b85decode(t.encode('ascii')).decode('utf-8', errors='replace')
            except Exception:
                return ''


# ââ URL Encode ââââââââââââââââââââââââââââ
def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe='')

def url_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    # Handle + â space
    t = t.replace('+', '%20')
    try:
        return urllib.parse.unquote(t, encoding='utf-8')
    except Exception:
        return ''


# ââ HTML Entity âââââââââââââââââââââââââââ
def html_encode(text: str) -> str:
    return html_mod.escape(text)

def html_decode(cipher_text: str) -> str:
    try:
        return html_mod.unescape(cipher_text)
    except Exception:
        return cipher_text


# ââ Unicode Escape ââââââââââââââââââââââââ
def unicode_encode(text: str) -> str:
    result = []
    for c in text:
        cp = ord(c)
        if cp > 127:
            result.append(f'\\u{cp:04x}')
        else:
            result.append(c)
    return ''.join(result)

def unicode_decode(cipher_text: str) -> str:
    try:
        return codecs.decode(cipher_text, 'unicode_escape')
    except Exception:
        return cipher_text


# ââ Binary String âââââââââââââââââââââââââ
def binary_str_encode(text: str) -> str:
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_str_decode(cipher_text: str) -> str:
    cleaned = cipher_text.replace(' ', '').replace('\n', '')
    result = []
    for i in range(0, len(cleaned) - 7, 8):
        try:
            result.append(chr(int(cleaned[i:i+8], 2)))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ââ Octal String ââââââââââââââââââââââââââ
def octal_str_encode(text: str) -> str:
    return ' '.join(f'\\{oct(ord(c))[2:].zfill(3)}' for c in text)

def octal_str_decode(cipher_text: str) -> str:
    parts = cipher_text.strip().split()
    result = []
    for p in parts:
        p = p.strip('\\')
        try:
            result.append(chr(int(p, 8)))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ââ Decimal ASCII âââââââââââââââââââââââââ
def decimal_str_encode(text: str) -> str:
    return ' '.join(str(ord(c)) for c in text)

def decimal_str_decode(cipher_text: str) -> str:
    parts = cipher_text.strip().split()
    result = []
    for p in parts:
        try:
            n = int(p)
            if 0 <= n <= 0x10FFFF:
                result.append(chr(n))
            else:
                result.append('?')
        except ValueError:
            result.append('?')
    return ''.join(result)


# ââ Keyboard Coordinate é®çåæ  ââââââââââââ
KEYBOARD_COORD_MAP = {
    'Q': '11', 'W': '12', 'E': '13', 'R': '14', 'T': '15',
    'Y': '16', 'U': '17', 'I': '18', 'O': '19', 'P': '10',
    'A': '21', 'S': '22', 'D': '23', 'F': '24', 'G': '25',
    'H': '26', 'J': '27', 'K': '28', 'L': '29',
    'Z': '31', 'X': '32', 'C': '33', 'V': '34', 'B': '35',
    'N': '36', 'M': '37',
}
KEYBOARD_COORD_REV = {v: k for k, v in KEYBOARD_COORD_MAP.items()}


def keyboard_coordinate_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c in KEYBOARD_COORD_MAP:
            result.append(KEYBOARD_COORD_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def keyboard_coordinate_decode(cipher_text: str) -> str:
    result = []
    tokens = ''.join(cipher_text.split())
    for i in range(0, len(tokens) - 1, 2):
        pair = tokens[i:i+2]
        if pair in KEYBOARD_COORD_REV:
            result.append(KEYBOARD_COORD_REV[pair])
        else:
            result.append('?')
    return ''.join(result)


# ââ Number Coordinate æ°å­åæ  ââââââââââââââ
NUMBER_COORD_MAP = {c: f"{i}" for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}
NUMBER_COORD_REV = {v: k for k, v in NUMBER_COORD_MAP.items()}


def number_coordinate_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c in NUMBER_COORD_MAP:
            result.append(NUMBER_COORD_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def number_coordinate_decode(cipher_text: str) -> str:
    result = []
    tokens = cipher_text.split()
    for t in tokens:
        if t in NUMBER_COORD_REV:
            result.append(NUMBER_COORD_REV[t])
        else:
            result.append('?')
    return ''.join(result)


# ââ ADFGX âââââââââââââââââââââââââââââââââ
def _adfgx_polybius(text: str, keyword: str = "") -> str:
    """ADFGX Polybius substitution phase."""
    letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # J â I
    result = []
    for c in text.upper().replace('J', 'I'):
        if c in letters:
            idx = letters.index(c)
            row, col = idx // 5, idx % 5
            result.append("ADFGX"[row] + "ADFGX"[col])
        elif c.isdigit():
            result.append(c)
    return ''.join(result)


def adfgx_encode(text: str, keyword: str) -> str:
    sub = _adfgx_polybius(text)
    if not keyword:
        return ' '.join(sub[i:i+2] for i in range(0, len(sub), 2))
    # Columnar transposition
    kw = keyword.upper()
    cols = {c: [] for c in kw}
    for i, ch in enumerate(sub):
        cols[kw[i % len(kw)]].append(ch)
    sorted_cols = sorted(cols.keys())
    return ''.join(''.join(cols[k]) for k in sorted_cols)


def adfgx_decode(cipher_text: str, keyword: str) -> str:
    if not keyword:
        letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        result = []
        for i in range(0, len(cipher_text) - 1, 2):
            r, c = cipher_text[i], cipher_text[i+1]
            if r in 'ADFGX' and c in 'ADFGX':
                idx = 'ADFGX'.index(r) * 5 + 'ADFGX'.index(c)
                result.append(letters[idx])
        return ''.join(result)
    # With keyword: reverse columnar transposition
    kw = keyword.upper()
    kw_sorted = sorted(kw)
    col_len = len(cipher_text) // len(kw)
    remainder = len(cipher_text) % len(kw)
    col_lengths = {k: col_len + (1 if i < remainder else 0) for i, k in enumerate(kw_sorted)}
    pos = 0
    cols = {}
    for k in kw_sorted:
        cols[k] = cipher_text[pos:pos + col_lengths[k]]
        pos += col_lengths[k]
    # Reconstruct pre-transposition text
    result = []
    for i in range(col_len + 1):
        for k in kw:
            if i < col_lengths.get(k, 0):
                result.append(cols[k][i])
    sub = ''.join(result)
    letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    plain = []
    for i in range(0, len(sub) - 1, 2):
        r, c = sub[i], sub[i+1]
        if r in 'ADFGX' and c in 'ADFGX':
            idx = 'ADFGX'.index(r) * 5 + 'ADFGX'.index(c)
            plain.append(letters[idx])
    return ''.join(plain)


# ââ æ°æéè½¬è½® âââââââââââââââââââââââââââ
def jefferson_decode(cipher_text: str, key: list, rotors: list = None) -> list:
    """æé©¬æ¯Â·æ°æéè½¬è½®å¯ç è§£ç ï¼è¿åææå¯è½çææã"""
    if rotors is None:
        rotors = JEFFERSON_ROTORS
    tmp_list = []
    for i in range(len(rotors)):
        k = key[i] - 1
        rotor = rotors[k]
        target = cipher_text[i] if i < len(cipher_text) else cipher_text[-1]
        for j in range(len(rotor)):
            if target.upper() == rotor[j]:
                tmp = rotor[j:] + rotor[:j] if j > 0 else rotor
                tmp_list.append(tmp)
                break
    # Build column strings
    messages = []
    col_len = min(len(t) for t in tmp_list)
    for i in range(col_len):
        col = ''.join(t[i] for t in tmp_list)
        messages.append(col)
    return messages


# âââââââââââââââââââââââââââââââââââââââââââ
# æ¥è¯¢ & å·¥å·å½æ°
# âââââââââââââââââââââââââââââââââââââââââââ

def list_ciphers(category: str = None) -> list:
    """ååºææå·²æ³¨åçå¯ç ç±»åã"""
    result = []
    for cid, info in CIPHER_TYPES.items():
        if category and info.get("category") != category:
            continue
        result.append({
            "id": cid,
            **info,
        })
    return result


def get_cipher(cipher_id: str) -> dict:
    """è¿åæå®å¯ç ç±»åçå®æ´ä¿¡æ¯ã"""
    return CIPHER_TYPES.get(cipher_id.lower())


def search_ciphers(query: str) -> list:
    """æåç§°/å«åæç´¢å¯ç ç±»åã"""
    q = query.lower()
    results = []
    for cid, info in CIPHER_TYPES.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            results.append({"id": cid, **info})
    return results


def get_image_path(cipher_id: str) -> str:
    """è¿åå¯ç ç±»åå¯¹åºçåèå¾ä¸»å¾è·¯å¾ã"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if info and info.get("image"):
        img_path = DATA_DIR / info["image"]
        if img_path.exists():
            return str(img_path)
    return ""


def get_image2_path(cipher_id: str) -> str:
    """è¿åå¯ç ç±»åå¯¹åºçåèå¾è¾å¾è·¯å¾ï¼å¦æï¼ã"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if info and info.get("image2"):
        img_path = DATA_DIR / info["image2"]
        if img_path.exists():
            return str(img_path)
    return ""


def get_categories() -> list:
    """è¿åææç±»å«ã"""
    cats = set()
    for info in CIPHER_TYPES.values():
        cats.add(info["category"])
    return sorted(cats)


def encode(cipher_id: str, text: str, **kwargs) -> str:
    """éç¨ç¼ç å¥å£ã"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        # åºç¡ç¼ç 
        "base64": base64_encode,
        "base32": base32_encode,
        "base16": base16_encode, "hex": base16_encode,
        "base58": base58_encode,
        "base85": base85_encode,
        "url_encode": url_encode, "url": url_encode, "urlencode": url_encode,
        "html_entity": html_encode, "html": html_encode, "entity": html_encode,
        "unicode_escape": unicode_encode, "unicode": unicode_encode, "uescape": unicode_encode,
        "binary_str": binary_str_encode,
        "octal_str": octal_str_encode, "octal": octal_str_encode, "oct": octal_str_encode,
        "decimal_str": decimal_str_encode, "decimal": decimal_str_encode, "dec": decimal_str_encode,
        # ç»å¸å¯ç 
        "pigpen": pigpen_encode,
        "bacon": bacon_encode, "baconian": bacon_encode,
        "polybius": polybius_encode, "polybius_square": polybius_encode,
        "vigenere": lambda t: vigenere_encode(t, kwargs.get("key", "A")),
        "caesar": lambda t: caesar_encode(t, kwargs.get("key", "3")),
        "rot13": rot13_encode,
        "atbash": atbash_encode,
        "rail_fence": lambda t: rail_fence_encode(t, kwargs.get("key", "3")),
        "morse": morse_encode,
        "qwe": qwe_encode, "qwe_keyboard": qwe_encode,
        "keyboard_chessboard": keyboard_chess_encode,
        "keyboard_coordinate": keyboard_coordinate_encode,
        "number_coordinate": number_coordinate_encode,
        "phone": phone_encode, "phone_keypad": phone_encode,
        "alphabet_order": alphabet_order_encode,
        "sga": sga_encode, "standard_galactic": sga_encode,
        "binary": binary_encode,
        "reverse": reverse_encode,
        "pawnshat": pawnshat_encode,
        "adfgx": lambda t: adfgx_encode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](text)
    return f"[!] ä¸æ¯æç¼ç : {cipher_id}"


def decode(cipher_id: str, cipher_text: str, **kwargs) -> str:
    """éç¨è§£ç å¥å£ã"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        # åºç¡ç¼ç 
        "base64": base64_decode,
        "base32": base32_decode,
        "base16": base16_decode, "hex": base16_decode,
        "base58": base58_decode,
        "base85": base85_decode,
        "url_encode": url_decode, "url": url_decode, "urlencode": url_decode,
        "html_entity": html_decode, "html": html_decode, "entity": html_decode,
        "unicode_escape": unicode_decode, "unicode": unicode_decode, "uescape": unicode_decode,
        "binary_str": binary_str_decode,
        "octal_str": octal_str_decode, "octal": octal_str_decode, "oct": octal_str_decode,
        "decimal_str": decimal_str_decode, "decimal": decimal_str_decode, "dec": decimal_str_decode,
        # ç»å¸å¯ç 
        "pigpen": pigpen_decode,
        "bacon": bacon_decode, "baconian": bacon_decode,
        "polybius": polybius_decode, "polybius_square": polybius_decode,
        "vigenere": lambda t: vigenere_decode(t, kwargs.get("key", "A")),
        "caesar": lambda t: caesar_decode(t, kwargs.get("key", "3")),
        "rot13": rot13_decode,
        "atbash": atbash_decode,
        "rail_fence": lambda t: rail_fence_decode(t, kwargs.get("key", "3")),
        "morse": morse_decode,
        "qwe": qwe_decode, "qwe_keyboard": qwe_decode,
        "keyboard_chessboard": keyboard_chess_decode,
        "keyboard_coordinate": keyboard_coordinate_decode,
        "number_coordinate": number_coordinate_decode,
        "phone": phone_decode, "phone_keypad": phone_decode,
        "alphabet_order": alphabet_order_decode,
        "sga": sga_decode, "standard_galactic": sga_decode,
        "binary": binary_decode,
        "reverse": reverse_decode,
        "pawnshat": pawnshat_decode,
        "adfgx": lambda t: adfgx_decode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](cipher_text)
    return f"[!] ä¸æ¯æè§£ç : {cipher_id}"


def get_text_path(cipher_id: str) -> str:
    """è¿åå¯ç ç±»åå¯¹åºçè¯´æææ¬æä»¶è·¯å¾ï¼å¦æï¼ã"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if not info:
        return ""
    name = info["name"]
    # Try common text file patterns
    candidates = [
        name + ".txt",
        name + "å å¯è§£å¯.txt",
        name + "å å¯è§£å¯æ³.txt",
        name + "ç¼ç .txt",
        name + ".txt",
    ]
    # Also try: binary -> äºè¿å¶, reverse -> åå, etc.
    txt_map = {
        "jefferson_wheel": "æé©¬æ¯æ°æé è½¬è½®å¯ç .txt",
        "vigenere": "ç»´åå°¼äº.txt",
        "morse": "æ©å°å¯ç å å¯ä¸è§£å¯.jpg",  # no txt, just image
    }
    if cipher_id.lower() in txt_map:
        target = DATA_DIR / txt_map[cipher_id.lower()]
        if target.exists():
            return str(target)
    for c in candidates:
        target = DATA_DIR / c
        if target.exists():
            return str(target)
    return ""


def get_text_content(cipher_id: str) -> str:
    """è¯»åå¯ç ç±»åçè¯´æææ¬åå®¹ã"""
    path = get_text_path(cipher_id)
    if path and path.endswith('.txt'):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception:
            try:
                with open(path, 'r', encoding='gbk', errors='replace') as f:
                    return f.read()
            except Exception:
                return ""
    return ""
