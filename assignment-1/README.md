# Assignment 1

## Part 1: Identify Required System Calls

Trace system calls of `/bin/ls` using ptrace and record the union of syscalls across multiple runs.

### What it does
- Runs the tracer on `/bin/ls` 3 times
- Records all unique system calls made
- Outputs the union of syscalls to `policy.txt`

### Files
- `tracer.c` - ptrace-based syscall tracer
- `policy.txt` - Generated syscall policy file

### How to run
```bash
cd assignment-1
chmod +x part1.sh
./part1.sh
```

---

## Part 2: Enforce a System Call Policy

Sandbox implementation using Syscall User Dispatch (SUD). The sandbox is initialized via `prctl()`, compiled as a shared library, and loaded into the target application using `LD_PRELOAD`.

### What it does
1. Runs tracer on a simple program that prints "Hello World" to get its allowed syscalls
2. Creates a malicious version that calls `getpid()` (which it shouldn't need)
3. Loads the sandbox and blocks the unauthorized syscall

### Files
- `hello.c` - Print "Hello World"
- `hello_malicious.c` - Print "Hello World" + `getpid()`
- `sandbox.c` - Sandbox with Syscall User Dispatch

### How to run
```bash
cd assignment-1
chmod +x part2.sh
./part2.sh
```

### Expected output
The sandbox will intercept the `getpid()` syscall and terminate the malicious program:
```
SYSCALL: 1
Hello World!
SYSCALL: 39
BLOCKED SYSCALL: 39 - TERMINATING!
```
