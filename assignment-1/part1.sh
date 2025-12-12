#!/bin/bash
echo "[1/5] Building tracer..."
gcc -o tracer tracer.c

echo "[2/5] Building hello..."
gcc -o hello hello.c

echo "[3/5] Running tracer on /bin/ls 3 times..."
./tracer /bin/ls

echo "[DONE] Policy file created."