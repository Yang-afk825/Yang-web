# -*- coding: utf-8 -*-
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+- =\\{\\}[]"

strings = open('./flag.txt').read()



result = {}

for i in alphabet:

	counts = strings.count(i)

	i = '{0}'.format(i)

	result[i] = counts



res = sorted(result.items(),key=lambda item:item[1],reverse=True)

for data in res:

	print(data)



for i in res:

	flag = str(i[0])

	print(flag[0],end="")

