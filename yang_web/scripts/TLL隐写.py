import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-f', type=str, default=None, required=True,
                    help='è¾å¥æä»¶åç§°')
args  = parser.parse_args()


file_name = args.f

with open(file_name) as f:
    data = f.read()
    data = data.splitlines()

dic = {"63": "00", "127": "01", "191": "10", "255": "11"}
text = ""
for i in data:
    if i := (dic.get(i, None)):
        text += i

with open("binary.txt", "w") as f:
    f.write(text)