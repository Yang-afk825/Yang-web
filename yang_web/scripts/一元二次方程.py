print("ax^2-bx+c=0的值："+"\n")
a=float(input("a= "))
b=float(input("b= "))
c=float(input("c= "))
delt=b**2-4*a*c
if delt<0:
    print("无解")
elif delt==0:
    print("x的值为："+str(-b/2*a))
else:
    x1 = (-b + delt ** 0.5) / 2*a
    x2 = (-b - delt ** 0.5) / 2*a
    print("x1的值： "+str(x1))
    print("x2的值： "+str(x2))