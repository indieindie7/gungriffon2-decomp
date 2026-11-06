#!/bin/bash
# headless Ghidra on the Gungriffon project. usage: ckrun.sh <abs log> <args...> (e.g. -process X -noanalysis -postScript Y)
log="$1"; shift
cd /c/Users/john/Documents/Gungriffon2/ghidra || exit 1
cmd //c "C:\Users\john\Documents\Tools\ghidra-headless.bat C:\Users\john\Documents\Gungriffon2\ghidra GG2 $* -scriptPath ${SP:-C:\Users\john\Documents\Gungriffon2\ghidra\scripts}" < /dev/null > "$log" 2>&1
tail -2 "$log"
