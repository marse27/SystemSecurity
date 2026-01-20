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

Built a code scanner that identifies all syscall instructions in executable memory regions of a running program. 

### What it does
- Scans executable memory regions by parsing `/proc/self/maps`
- Identifies all syscall instructions (`0x0F 0x05` opcode) in x86-64 binaries
- Reports the virtual address and memory region of each syscall found
- Loads as a shared library using `LD_PRELOAD` and runs before the target program starts
- Works with any Linux x86-64 application (tested with `/bin/ls`, `/bin/echo`, `/bin/cat`)

### Files
- `syscall_scanner.c` - Main scanner implementation with constructor function
- `pmparser.c` - Library to parse `/proc/self/maps` (from https://github.com/ouadev/proc_maps_parser)
- `pmparser.h` - Header file for the proc maps parser
- `Makefile` - Build configuration for the shared library
- `REPORT.md` - Detailed report with implementation details, screenshots, and analysis

### How to build
```bash
cd assignment-2/part2-code-scanner

# Download the proc_maps_parser library
wget https://raw.githubusercontent.com/ouadev/proc_maps_parser/master/pmparser.c
wget https://raw.githubusercontent.com/ouadev/proc_maps_parser/master/include/pmparser.h

# Build the scanner
make
