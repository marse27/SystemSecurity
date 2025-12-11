#!/bin/bash
echo "[1/5] Building tracer..."
gcc -o tracer tracer.c

echo "[2/5] Building hello..."
gcc -o hello hello.c

echo "[3/5] Running tracer on hello 3 times..."
./tracer ./hello

echo "[4/5] Building sandbox shared library..."
gcc -shared -fPIC -o sandbox.so sandbox.c

echo "[5/5] Building hello_malicious..."
gcc -o hello_malicious hello_malicious.c

echo "[RUN] Executing hello_malicious with LD_PRELOAD and policy file..."
POLICY="policy.txt" LD_PRELOAD=./sandbox.so ./hello_malicious
