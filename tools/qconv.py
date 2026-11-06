# qconv.py <in> <out>: compact lines "ADDR name comment..." -> "0xADDR func name hand provisional comment"
import sys,re
o=[]
for l in open(sys.argv[1],encoding='utf-8'):
    p=l.rstrip().split(None,2)
    if len(p)<2 or not re.fullmatch(r'(0x)?[0-9a-fA-F]{8}',p[0]): continue
    a=p[0][2:] if p[0].startswith('0x') else p[0]
    o.append('0x%s func %s hand provisional %s'%(a.lower(),p[1],p[2] if len(p)>2 else ''))
open(sys.argv[2],'w',encoding='utf-8',newline='\n').write('\n'.join(o)+'\n')
print(len(o))
