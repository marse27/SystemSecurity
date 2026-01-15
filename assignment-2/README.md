# Assignment 2

## Part 1 – Block (some) attacks that bypass the W^X policy

Extend the Syscall User Dispatch (SUD) sandbox from Assignment 1 to block dangerous syscall argument combinations that can bypass a W^X policy.

### What it does
- Builds the tracer, sandbox, and the two attacker test programs
- Runs the tracer on `test1` 3 times to generate a syscall allowlist policy (`policy_test1.txt`)
- Runs `test1` under the sandbox (`LD_PRELOAD`) and blocks the W^X bypass by denying `mprotect()` when it requests `PROT_WRITE | PROT_EXEC`
- Runs the tracer on `test2` 3 times to generate a syscall allowlist policy (`policy_test2.txt`)
- Runs `test2` under the sandbox (`LD_PRELOAD`) and blocks the `/proc/self/mem` abuse by denying `open/openat()` when opening `/proc/self/mem` with writable access

### Files
- `test1.cpp` - Simulates an attacker that bypasses W^X using mprotect(PROT_EXEC | PROT_WRITE)
- `test2.cpp` - Simulates an attacker that abuses `/proc/self/mem` by opening it with O_RDWR

### How to run
```bash
cd assignment-2
chmod +x part1.sh
./part1.sh
```

For WSL / Windows users:
```bash
cd assignment-2
sed -i 's/\r$//' part1.sh
chmod +x part1.sh
./part1.sh
```

### Expected output

#### test1
The sandbox denies mprotect() when it tries to create writable + executable memory and the program prints:
`Succeeded to mitigate the attacker`

#### test2
The sandbox denies opening `/proc/self/mem` with write permissions and the program prints:
`Failed to open /proc/self/mem ... attacker blocked :) !!!`

---

## Part 2 – Code Scanner

