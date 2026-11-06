# squeeze.py <ghidra> <prog> <base hex> [addr-list file|-] [maxlines]: compact decomp view (literal-pool values inlined, locals/blank lines dropped)
import sys,os,re,struct
g,prog,base=sys.argv[1],sys.argv[2],int(sys.argv[3],16)
want=None
if len(sys.argv)>4 and sys.argv[4]!='-': want=set(int(x,16) for x in open(sys.argv[4]).read().split())
mx=int(sys.argv[5]) if len(sys.argv)>5 else 10**9
b=open(os.path.join(g,'bin',prog+'.BIN'),'rb').read()
def rd(a):
    o=a-base
    return struct.unpack('>I',b[o:o+4])[0] if 0<=o<=len(b)-4 else None
names={}
hp=os.path.join(g,'hand_%s.txt'%prog)
if os.path.exists(hp):
    for l in open(hp,encoding='utf-8'):
        f=l.split(None,4)
        if len(f)>=3 and f[1]=='func': names[int(f[0],16)]=f[2]
fe=set()
for l in open(os.path.join(g,'funcinfo_%s.tsv'%prog)):
    if l.startswith('F '): fe.add(int(l.split()[1],16))
def sub(m):
    a=int(m.group(1),16); v=rd(a) if a>=base else None
    if v is None: return m.group(0)
    if v in fe: return names.get(v,'F%05x'%(v&0xfffff))
    return '@%x'%v if v>0xfff else '%d'%v
t=open(os.path.join(g,'decomp_%s.c'%prog),encoding='utf-8',errors='replace').read()
for p in re.split(r'(?m)^// ==== ',t)[1:]:
    m=re.match(r'(\S+) @ ([0-9a-f]+) size=(\d+)',p)
    a=int(m.group(2),16)
    if want is not None and a not in want: continue
    body=p[m.end():]
    body=re.sub(r'\b(?:DAT|PTR_\w+?|PTR)_([0-9a-f]{8})\b',sub,body)
    body=re.sub(r'\b(?:FUN|thunk_FUN)_([0-9a-f]{8})\b',lambda x:names.get(int(x.group(1),16),'F'+x.group(1)[3:]),body)
    ls=[]
    for l in body.split('\n'):
        s=l.strip()
        if not s or s=='{' or re.match(r'^(undefined\d?|int|uint|short|ushort|char|byte|code|bool|float|longlong|ulonglong)\s*\*{0,2}\s*[\w]+(\s*\[\d+\])?;$',s): continue
        ls.append(re.sub(r'\s+',' ',s))
    print('## %08x %s size=%s'%(a,m.group(1),m.group(3)))
    print('\n'.join(ls[:mx]))
