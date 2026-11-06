# digest.py <ghidra dir> <prog> <base hex> [level]: one-line feature digest per function (for hand naming).
# Resolves SH-2 literal-pool refs (DAT_/PTR_ names) to their 32-bit value, maps values that are function entries to callee names,
# classifies hardware regions. Names come from hand_<prog>.txt when present.
import sys,os,re,struct,collections
g,prog,base=sys.argv[1],sys.argv[2],int(sys.argv[3],16)
binf=os.path.join(g,'bin',prog+'.BIN' if not prog.endswith('.BIN') else prog)
if not os.path.exists(binf): binf=os.path.join(g,'bin',prog+'.BIN')
b=open(binf,'rb').read()
def rd(a):
    o=a-base
    return struct.unpack('>I',b[o:o+4])[0] if 0<=o<=len(b)-4 else None
funcs=[]; info={}
cur=None
for l in open(os.path.join(g,'funcinfo_%s.tsv'%prog),encoding='utf-8',errors='replace'):
    f=l.rstrip('\n').split(' ',4)
    if f[0]=='F': cur=int(f[1],16); funcs.append(cur); info[cur]={'sz':int(f[4]) if len(f)>4 else 0,'S':[]}
    elif f[0]=='S' and cur is not None: info[cur]['S'].append(l[2:].strip())
names={}
hp=os.path.join(g,'hand_%s.txt'%prog)
if os.path.exists(hp):
    for l in open(hp,encoding='utf-8'):
        f=l.split(None,4)
        if len(f)>=3 and f[1]=='func': names[int(f[0],16)]=f[2]
def nm(a): return names.get(a,'%05x'%(a&0xfffff))
def region(v):
    if v is None: return None
    t=v&0x1fffffff
    R=[(0x05C00000,0x05D00000,'vdp1ram'),(0x05D00000,0x05D80000,'vdp1reg'),(0x05E00000,0x05F00000,'vdp2ram'),(0x05F00000,0x05F80000,'cram'),(0x05F80000,0x05FE0000,'vdp2reg'),(0x05FE0000,0x05FF0000,'scu'),(0x05A00000,0x05B00000,'sndram'),(0x05B00000,0x05C00000,'scsp'),(0x00100000,0x00180000,'smpc'),(0x05890000,0x058A0000,'cdblock'),(0x05800000,0x05890000,'a-bus')]
    if v>=0xfffffe00: return 'sh2reg'
    if 0x20000000<=v<0x20100000: return None
    if 0x20100000<=v<0x20180000: return 'smpc'
    if 0x25000000<=v<0x25800000: return None
    for lo,hi,n in R:
        if lo<=t<hi and v>=0x20000000: return n
    return None
def run():
    t=open(os.path.join(g,'decomp_%s.c'%prog),encoding='utf-8',errors='replace').read()
    parts=re.split(r'(?m)^// ==== ',t)[1:]
    for p in parts:
        m=re.match(r'(\S+) @ ([0-9a-f]+) size=(\d+)',p)
        if not m: continue
        a=int(m.group(2),16); body=p[m.end():]
        sig=re.search(r'\n\n(.*?)\n\{',body,re.S)
        npar=len(re.findall(r'param_\d',sig.group(1))) if sig else 0
        hw=collections.Counter(); calls=[]; glob=collections.Counter(); consts=[]
        for r in re.finditer(r'(?:DAT|PTR_\w+?|PTR)_([0-9a-f]{8})\b',body):
            v=rd(int(r.group(1),16)) if int(r.group(1),16)>=base else None
            if v is None: continue
            if v in names or v in info: 
                if v!=a: calls.append(v)
            else:
                h=region(v)
                if h: hw[h]+=1
                elif 0x06000000<=v<0x06100000 or 0x00200000<=v<0x00300000: glob[v]+=1
                else: consts.append(v)
        for r in re.finditer(r'\b(?:FUN|thunk_FUN)_([0-9a-f]{8})\b',body):
            x=int(r.group(1),16)
            if x!=a: calls.append(x)
        for r in re.finditer(r'\b([A-Za-z]\w*)\(',body):
            pass
        seen=[];[seen.append(c) for c in calls if c not in seen]
        loops=len(re.findall(r'\b(?:do|while|for)\b',body))
        feat=[]
        if len(re.findall(r'>> 0x10|>> 16',body)): feat.append('sh16')
        mul=len(re.findall(r'\*\s*\(?(?:\w+|\))',body))
        sw=len(re.findall(r'\bswitch\b',body))
        if sw: feat.append('sw%d'%sw)
        if '/' in re.sub(r'/\*.*?\*/|//.*','',body): feat.append('div')
        gl=','.join('%x'%(v&0xfffff)+('x%d'%n if n>1 else '') for v,n in glob.most_common(4))
        big=[ '%x'%c for c in consts if c>0xffff][:3]
        print('%08x sz=%d p=%d L=%d %s%s%s%s%s%s'%(a,info.get(a,{}).get('sz',0),npar,loops,
          (' HW:'+','.join('%s%d'%(k,n) for k,n in hw.items())) if hw else '',
          (' C:'+','.join(nm(c) for c in seen[:7])+('+%d'%(len(seen)-7) if len(seen)>7 else '')) if seen else '',
          (' S:'+'|'.join(s[:30] for s in info.get(a,{}).get('S',[])[:2])) if info.get(a,{}).get('S') else '',
          (' G:'+gl) if gl else '', (' K:'+','.join(big)) if big else '', (' '+' '.join(feat)) if feat else ''))
run()
