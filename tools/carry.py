# carry.py <st_dir> <ghidra>: put GG1-carried names (st/hand_<prog>.txt) into hand_<prog>.txt, carried names win; tag -> [from GG1 <prog> 0x..]
import sys,re,os
st,g=sys.argv[1],sys.argv[2]
for p in ['PROG1','PROG2','PROG3','PROG4','ROBSYS','LOGO2','LOADER0']:
    f=os.path.join(st,'hand_%s.txt'%p)
    if not os.path.exists(f): continue
    car={}
    for l in open(f,encoding='utf-8'):
        m=re.match(r'(0x[0-9a-f]{8}) func (\S+) hand(.*)$',l.rstrip())
        if not m: continue
        r=m.group(3); r=re.sub(r'\[x (\w+) (0x[0-9a-f]+)\]',r'[from GG1 \1 \2]',r)
        car[int(m.group(1),16)]=(m.group(2),r)
    hp=os.path.join(g,'hand_%s.txt'%p); cur={}
    if os.path.exists(hp):
        for l in open(hp,encoding='utf-8'):
            m=re.match(r'(0x[0-9a-f]{8}) func (\S+) hand(.*)$',l.rstrip())
            if m: cur[int(m.group(1),16)]=(m.group(2),m.group(3))
    cur.update(car)
    open(hp,'w',encoding='utf-8',newline='\n').write(''.join('0x%08x func %s hand%s\n'%(a,n,r) for a,(n,r) in sorted(cur.items())))
    print(p,len(car))
