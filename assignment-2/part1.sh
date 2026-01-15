#!/bin/bash
echo "[1/5] Building tracer..."
gcc -o tracer tracer.c

echo "[2/5] Building sandbox shared library..."
gcc -shared -fPIC -o sandbox.so sandbox.c

echo "[3/5] Building tests..."
g++ test1.cpp -o test1
g++ test2.cpp -o test2

echo "[4/5] Generating policy for test1..."
./tracer ./test1 >/dev/null
mv policy.txt policy_test1.txt
echo 231 >> policy_test1.txt

echo "[RUN] Executing test1 with LD_PRELOAD and policy file..."
POLICY="policy_test1.txt" LD_PRELOAD=./sandbox.so ./test1 || true

echo
echo "[5/5] Generating policy for test2..."
./tracer ./test2 >/dev/null
mv policy.txt policy_test2.txt
echo 231 >> policy_test2.txt

echo "[RUN] Executing test2 with LD_PRELOAD and policy file..."
POLICY="policy_test2.txt" LD_PRELOAD=./sandbox.so ./test2 || true
