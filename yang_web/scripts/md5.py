import hashlib   
for i in range(33,127):
    for j in range(33,127):
        for k in range(33,127):
            for l in range(33,127):
                for m in range(33,127):
                    x=hashlib.md5()
                    x.update(chr(i)+'1_1001_10_600_600_'+chr(j)+chr(k)+'00'+chr(l)+chr(m)+'7_202103301539')
                    des=x.hexdigest()
                    if 'b9fd' in des and '9d5' in des and 'c1' in des and 'f6c' in des and 'abd' in des and '5ac' in des and '7' in des:
                        print i,j,k,l,m
