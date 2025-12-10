// hello.c - test multiple syscalls with raw syscalls
long raw_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;
    asm volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

void _start() {
    // Syscall 1: write
    const char msg1[] = "Hello World!\n";
    raw_syscall(1, 1, (long)msg1, sizeof(msg1) - 1, 0, 0, 0);
    
    // Syscall 9: mmap
    raw_syscall(9, 0, 4096, 3, 34, -1, 0);  // PROT_READ|WRITE, MAP_PRIVATE|ANON
    
    // Syscall 39: getpid
    raw_syscall(39, 0, 0, 0, 0, 0, 0);
    
    // Syscall 2: open (will fail but that's ok)
    const char file[] = "/tmp/test";
    raw_syscall(2, (long)file, 0, 0, 0, 0, 0);
    
    const char msg2[] = "Done!\n";
    raw_syscall(1, 1, (long)msg2, sizeof(msg2) - 1, 0, 0, 0);
    
    // Syscall 60: exit
    raw_syscall(60, 0, 0, 0, 0, 0, 0);
}