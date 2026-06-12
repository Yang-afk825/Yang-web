import base36
import base58
import base62
import base64
import base91
import py3base92 #ç±äºpython3ä¸å¼å®¹base92ï¼æ­¤ä¸ºgithubä¸çä¸ä¸ªé¡¹ç®



def encode(txt):
    print("[+]input is ", end="")
    print(txt)

    print("==============================================================================")
    #base16
    print("[æå]base16 encode: ", end="")
    print(base64.b16encode(txt))

    #base32
    print("[æå]base32 encode: ", end="")
    print(base64.b32encode(txt))


    #base36
    try:
        base36_m_str = bytes.decode(txt)
        base36_m_int = int(base36_m_str)

        base36_cipher = base36.dumps(base36_m_int)
        print("[æå]base36 encode: ", end="")
        print(base36_cipher)
    except Exception as e:
        print("[å¤±è´¥]base36 encode: ", end="")
        print("base36å å¯åªæ¯ææ´æ°æ°å­")

    #base58
    print("[æå]base58 encode: ", end="")
    print(base58.b58encode(txt))

    #base62
    print("[æå]base62 encode: ", end="")
    print(base62.encodebytes(txt))

    #base64
    print("[æå]base64 encode: ", end="")
    print(base64.b64encode(txt))

    #base85
    print("[æå]base85 encode: ", end="")
    print(base64.b85encode(txt))

    #base91
    print("[æå]base91 encode: ", end="")
    print(base91.encode(txt))

    #base92
    print("[æå]base92 encode: ", end="")
    print(py3base92.encode(txt))


def decode(txt):
    print("[+]input is ", end="")
    print(txt)
    print("==============================================================================")

    #base16
    try:
        base16_decode = base64.b16decode(txt)
        print("[æå]base16 decode: ", end="")
        print(base16_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base16 decode: ", end="")
        print(e)


    #base32
    try:
        base32_decode = base64.b32decode(txt)
        print("[æå]base32 decode: ", end="")
        print(base32_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base32 decode: ", end="")
        print(e)


    #base36
    try:
        base36_decode = base36.loads(txt)
        print("[æå]base36 decode: ", end="")
        print(base36_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base36 decode: ", end="")
        print(e)


    #base58
    try:
        base58_decode = base58.b58decode(txt)
        print("[æå]base58 decode: ", end="")
        print(base58_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base58 decode: ", end="")
        print(e)


    #base62
    try:
        base62_c_string = bytes.decode(txt)
        base62_decode = base62.decodebytes(base62_c_string)
        print("[æå]base62 decode: ", end="")
        print(base62_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base62 decode: ", end="")
        print(e)


    #base64
    try:
        base64_decode = base64.b64decode(txt)
        print("[æå]base64 decode: ", end="")
        print(base64_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base64 decode: ", end="")
        print(e)


    #base85
    try:
        base85_decode = base64.a85decode(txt).decode()
        print("[æå]base85 decode: ", end="")
        print(base85_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base85 decode: ", end="")
        print(e)


    #base91
    try:
        base91_decode = base91.decode(str(txt, encoding="utf-8")).decode()
        print("[æå]base91 decode: ", end="")
        print(base91_decode)
        print()
    except Exception as e:
        print("[å¤±è´¥]base91 decode: ", end="")
        print(e)



    #base92
    try:
        base92_decode = py3base92.decode(str(txt, encoding="utf-8"))
        print("[æå]base92 decode: ", end="")
        print(base92_decode)
        print()
    except Exception as e:
        print("[-]base92 decode: ", end="")
        print(e)
    



if __name__ == '__main__':
    print("Welcome to base series encode and decode")
    txt = input("Please input your string ::: ")


    txt = str.encode(txt)
    flag = input("Please input encode(1) or decode(åè½¦) ::: ")

    if(flag == "1"):
        encode(txt)
    else:
        decode(txt)
