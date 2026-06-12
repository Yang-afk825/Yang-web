"""Morse code & other classic ciphers — encode / decode / auto-detect."""

MORSE_ENCODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.', ' ': '/',
}

MORSE_DECODE = {v: k for k, v in MORSE_ENCODE.items()}

# Common cipher alphabets
ROT13 = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
)

ATBASH = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'ZYXWVUTSRQPONMLKJIHGFEDCBA',
)

CAESAR_SHIFTS = {i: str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    ''.join(chr((j + i) % 26 + 65) for j in range(26)),
) for i in range(1, 26)}


def morse_encode(text: str) -> str:
    return ' '.join(MORSE_ENCODE.get(c.upper(), c) for c in text)


def morse_decode(code: str) -> str:
    result = []
    for w in code.split('/'):
        chars = [MORSE_DECODE.get(c, '?') for c in w.split()]
        result.append(''.join(chars))
    return ' '.join(result)


def is_morse(text: str) -> bool:
    return all(c in '.- /' for c in text.replace(' ', ''))


def rot_n(text: str, n: int = 13) -> str:
    table = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        ''.join(chr((i + n) % 26 + 65) for i in range(26)) +
        ''.join(chr((i + n) % 26 + 97) for i in range(26)),
    )
    return text.translate(table)


def atbash(text: str) -> str:
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif 'a' <= c <= 'z':
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)


def caesar_brute(text: str) -> list:
    results = []
    for shift in range(1, 26):
        result = text.translate(CAESAR_SHIFTS[shift])
        results.append((shift, result))
    return results


def rail_fence_encode(text: str, rails: int = 3) -> str:
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for c in text:
        fence[rail].append(c)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    return ''.join(''.join(r) for r in fence)


def baconian_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            n = ord(c) - ord('A')
            result.append(format(n, '05b').replace('0', 'A').replace('1', 'B'))
        else:
            result.append(c)
    return ' '.join(result)


def baconian_decode(code: str) -> str:
    result = []
    for chunk in code.split():
        chunk = chunk.strip().upper().replace('A', '0').replace('B', '1')
        try:
            n = int(chunk, 2)
            if 0 <= n < 26:
                result.append(chr(n + ord('A')))
            else:
                result.append('?')
        except ValueError:
            result.append('?')
    return ''.join(result)


def auto_classical(text: str) -> dict:
    results = {}
    if is_morse(text):
        results['morse'] = morse_decode(text)

    # Try ROT variants
    for n in [13, 5, 1, 25]:
        decoded = rot_n(text, n)
        if _score_english(decoded) > 0.6:
            results[f'rot{n}'] = decoded

    atb = atbash(text)
    if _score_english(atb) > 0.6:
        results['atbash'] = atb

    # Try caesar
    caesar_attempts = caesar_brute(text)
    for shift, result in caesar_attempts:
        if _score_english(result) > 0.7:
            results[f'caesar{shift}'] = result

    return results


def _score_english(text: str) -> float:
    common = set('ETAOINSHRDLUetaoinshrdlu')
    if not text:
        return 0.0
    text_chars = [c for c in text if c.isalpha()]
    if not text_chars:
        return 0.0
    return sum(1 for c in text_chars if c in common) / len(text_chars)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python morse_code.py <text> [--auto]")
        sys.exit(0)

    text = " ".join(sys.argv[1:])
    if text.startswith("--auto"):
        text = sys.argv[2] if len(sys.argv) > 2 else input("text: ")

    if text.startswith(".-") or text.startswith("-."):
        print("morse:", morse_decode(text))
    else:
        print("morse:", morse_encode(text))
        print("rot13:", rot_n(text))
        print("atbash:", atbash(text))
        auto = auto_classical(text)
        if auto:
            print("auto:", auto)
