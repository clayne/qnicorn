#!/bin/sh

python3 ./sample_x86.py
echo "=========================="
python3 ./shellcode.py
echo "=========================="
python3 ./sample_arm.py
echo "=========================="
python3 ./sample_arm64.py
echo "=========================="
python3 ./sample_mips.py
echo "=========================="
python3 ./sample_sparc.py
echo "=========================="
python3 ./sample_m68k.py
