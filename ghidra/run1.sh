#!/bin/bash
# usage: run1.sh <prog>: merge naming/q<prog>_*.txt into hand, apply names, re-export
cd /c/Users/john/Documents/Gungriffon2/ghidra
p=$1; G='C:\Users\john\Documents\Gungriffon2\ghidra'; L=/c/Users/john/Documents/Gungriffon2/ghidra/logs
py -3.13 -I ../tools/decmerge.py . $p
bash run.sh $L/apply_$p.log -process $p.BIN -noanalysis -postScript ApplyNames.java "$G\hand_$p.txt" >/dev/null 2>&1
bash run.sh $L/export_$p.log -process $p.BIN -noanalysis -readOnly -postScript ExportFuncInfo.java "$G\funcinfo_$p.tsv" >/dev/null 2>&1
bash run.sh $L/dump_$p.log -process $p.BIN -noanalysis -readOnly -postScript CsDumpAll.java "$G\decomp_$p.c" >/dev/null 2>&1
echo "$p FUN_ left: $(awk '$1=="F" && $3 ~ /^FUN_/' funcinfo_$p.tsv | wc -l)"
