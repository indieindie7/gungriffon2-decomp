# xstage.py: carry hand names from a named stage program to another stage program by normalized decompile body.
# Stage programs "1".."10" share most code at the same base (0x0600E800) but shifted addresses.
# usage: py -3.13 -I xstage.py <ghidra dir> <src prog> <dst prog>   -> writes hand_<dst>.txt (keeps existing lines)
# match = identical body after stripping comments, own name, addresses, PTR_/FUN_/DAT_/LAB_ symbols; unique on both sides.
# second round: unmatched functions whose (callee-name multiset via PTR_) equals a unique src one after round 1 names.
import sys, os, re, collections
g, src, dst = sys.argv[1:4]
def bodies(prog):
    d = {}; cur = None; buf = []
    for l in open(os.path.join(g, 'decomp_%s.c' % prog), encoding='utf-8', errors='replace'):
        m = re.match(r'// ==== (\S+) @ ([0-9a-fA-F]+)', l)
        if m:
            if cur: d[cur] = (nm, ''.join(buf))
            cur = m.group(2).lower().zfill(8); nm = m.group(1); buf = []; continue
        buf.append(l)
    if cur: d[cur] = (nm, ''.join(buf))
    return d
def norm(nm, t):
    t = re.sub(r'/\*.*?\*/', '', t, flags=re.S)
    t = t.replace(nm, 'SELF')
    t = re.sub(r'PTR_\w+?_[0-9a-f]{8}\b', 'PTR', t)
    t = re.sub(r'\b(FUN|DAT|LAB|PTR|s|u|switchD|caseD)_[0-9a-fA-F_]+\w*', 'SYM', t)
    t = re.sub(r'0x060[0-9a-f]{5}', 'ADDR', t)
    t = re.sub(r'\b\w+_[0-9a-f]{8}\b', 'SYM', t)
    return re.sub(r'\s+', ' ', t).strip()
def hand(prog):
    d = {}; fn = os.path.join(g, 'hand_%s.txt' % prog)
    if os.path.exists(fn):
        for l in open(fn, encoding='utf-8'):
            f = l.split(None, 4)
            if len(f) >= 3: d[f[0].lower().replace('0x', '').zfill(8)] = l.rstrip('\n')
    return d
S, D = bodies(src), bodies(dst); H = hand(src); out = hand(dst)
def keyed(B):
    k = collections.defaultdict(list)
    for a, (nm, t) in B.items(): k[norm(nm, t)].append(a)
    return k
ks, kd = keyed(S), keyed(D); got = 0
for k, al in kd.items():
    sl = ks.get(k, [])
    if len(al) == 1 and len(sl) == 1 and sl[0] in H and al[0] not in out:
        f = H[sl[0]].split(None, 4)
        rest = f[4] if len(f) > 4 else ''
        out[al[0]] = '0x%s func %s hand %s' % (al[0], f[2], (rest + ' [x %s 0x%s]' % (src, sl[0])).strip())
        got += 1
with open(os.path.join(g, 'hand_%s.txt' % dst), 'w', encoding='utf-8') as fo:
    for a in sorted(out): fo.write(out[a] + '\n')
print('%s: %d funcs, matched %d, hand lines %d, unmatched %d' % (dst, len(D), got, len(out), len(D) - len(out)))
