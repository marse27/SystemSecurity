// hello.c - test with unauthorized syscall
long raw_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;
    asm volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

void _start() {
    // Syscall 1: write (ALLOWED - in policy)
    const char msg1[] = "Hello World!\n";
    raw_syscall(1, 1, (long)msg1, sizeof(msg1) - 1, 0, 0, 0);
    
    // ⚠️ ATTACKER CODE: Syscall 102 (getuid) - NOT IN POLICY!
    const char attack_msg[] = "Attempting unauthorized syscall 102 (getuid)...\n";
    raw_syscall(1, 1, (long)attack_msg, sizeof(attack_msg) - 1, 0, 0, 0);
    raw_syscall(102, 0, 0, 0, 0, 0, 0);  // getuid - NOT ALLOWED!
    
    // Should NEVER reach here if sandbox works!
    const char failure_msg[] = "❌ SANDBOX FAILED! This should not print!\n";
    raw_syscall(1, 1, (long)failure_msg, sizeof(failure_msg) - 1, 0, 0, 0);
    
    const char msg2[] = "Done!\n";
    raw_syscall(1, 1, (long)msg2, sizeof(msg2) - 1, 0, 0, 0);
    
    raw_syscall(60, 0, 0, 0, 0, 0, 0);  // exit
}