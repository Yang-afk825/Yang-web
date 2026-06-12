import argparse
from colorama import init, Fore
init(autoreset=True)


parser = argparse.ArgumentParser()
parser.add_argument('-t', type=str, default=None, required=True,
                    help='è¾å¥äºè¿å¶ææ¬')
args  = parser.parse_args()

bin_str = args.t

def BintoAsc(bin_str, bit, reverse=False):
    ascii_str = ""
    for i in range(0, len(bin_str), bit):
        bin_ = bin_str[i:i + bit][::-1] if reverse else bin_str[i:i + bit]
        # å¦æ127 >= num >= 32,é£å°±æ¯å¯è§å­ç¬¦,ä¸å¯è§å­ç¬¦ç»ç»è½¬æ¢ä¸º`~`(æ³¢æµªçº¿)
        ascii_str += chr(num) if 127 >= (num := int(bin_, 2)) >= 32 else chr(126)
    return ascii_str

input_ = input(f"{Fore.GREEN}æ¯å¦å°è¯0å1äºæ¢åè½¬æ¢Asciiç ? (N/y):")
if input_ not in ["N", "n", ""]:
    bin_str = "".join("1" if i == "0" else "0" for i in bin_str)

# æ­£å¸¸æåµ
print(f"{Fore.RED}[7Bit]: {Fore.BLUE}{BintoAsc(bin_str, 7)}")
print(f"{Fore.RED}[8Bit]: {Fore.BLUE}{BintoAsc(bin_str, 8)}")
print()

# ç¹æ®æåµ1
print(f"{Fore.YELLOW} [1].å°è¯å¨é¨å­èååºåè½¬æ¢Asciiç :")
reverse_bin_str = bin_str[::-1]
print(f"{Fore.RED}  [7Bit]: {Fore.BLUE}{BintoAsc(reverse_bin_str, 7)}")
print(f"{Fore.RED}  [8Bit]: {Fore.BLUE}{BintoAsc(reverse_bin_str, 8)}")
print()

# ç¹æ®æåµ2
print(f"{Fore.YELLOW} [2].å°è¯æ¯ä¸ªå­èä¾æ¬¡ååºåè½¬æ¢Asciiç :")
print(f"{Fore.RED}  [7Bit]: {Fore.BLUE}{BintoAsc(bin_str, 7, reverse=True)}")
print(f"{Fore.RED}  [8Bit]: {Fore.BLUE}{BintoAsc(bin_str, 8, reverse=True)}")