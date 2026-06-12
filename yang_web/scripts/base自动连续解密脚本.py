import binascii
import base64


def get_continuous_asciis(ranges: list):
    """
    取连续的ASCII文本
    :param ranges: 范围数组, 例[['A', 'B']]
    :return: 
    """
    return ''.join([''.join(map(chr, range(ord(r[0]), ord(r[1]) + 1))) for r in ranges])


with open('aa.txt') as f:
    enc = f.read()

while True:
    b16 = b32 = b64 = False
    if all([i.upper() in '0123456789ABCDEF' for i in enc]):
        b16 = True
    elif all([i.upper() in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ2345678=' for i in enc]):
        b32 = True
    elif all([i.upper() in get_continuous_asciis([['a', 'z'], ['A', 'Z'], ['0', '9']]) + '+/=' for i in enc]):
        b64 = True
    else:
        print('End')
        break
    if b16:
        print('Base16')
        enc = binascii.a2b_hex(enc).decode('utf-8')
    elif b32:
        print('Base32')
        enc = base64.b32decode(enc).decode('utf-8')
    elif b64:
        print('Base64')
        enc = base64.b64decode(enc).decode('utf-8')
    print('-' * 30)
    print(enc)
    print('-' * 30)
