#!/bin/bash
cd /c/Users/john/Documents/Gungriffon2/ghidra
for p in "PROG1.BIN 0600E800" "PROG2.BIN 0600E800" "PROG3.BIN 0600E800" "ROBSYS.BIN 0600E800" "PROG4.BIN 06010000" "LOGO2.BIN 06010000" "LOADER0.BIN 0600A000"; do bash import.sh $p; done > logs/import_all.txt 2>&1
echo done >> logs/import_all.txt
