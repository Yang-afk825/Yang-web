import string
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-f', type=str, default=None, required=True,
                    help='输入文件名称')
args  = parser.parse_args()

# ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
key = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"

# 1.获取密文
with open(args.f, "r") as f:
    data = f.readlines()
data = [i.replace("\n", "") for i in data]

'''
1.依次读取每行，从中提取出隐写位。
2.如果最后没有‘=’，说明没有隐写位，跳过。
3.如果最后是一个‘=’，说明有两位隐写位，将倒数第二个字符转化为对应的二进制索引，然后取后两位。
4.如果最后是两个‘=’，说明有四位隐写位，将倒数第三个字符转化为对应的二进制索引，然后取后四位。
5.记住要补齐8位后取后2位和后4位，如果不补齐的话比如说遇到了B --> "1"，补齐后能得到"01"，不补齐就是"1"，那就错了
6.将每行提取出的隐写位依次连接起来，每8位为一组转换为ASCII字符，最后不足8位的丢弃。
'''

bin_str = ""
for cipher in data:
    flag = 0
    if cipher[-1:] == "=":
        flag = 1
        if cipher[-2:] == "==":
            flag = 2
    
    if flag == 1:
        bin_str += bin(key.index(cipher[-2]))[2:].zfill(8)[-2:]
    elif flag == 2:
        bin_str += bin(key.index(cipher[-3]))[2:].zfill(8)[-4:]

print("".join(chr(int(bin_str[i*8:i*8+8], 2)) for i in range(len(bin_str) // 8)))