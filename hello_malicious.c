#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

// // Raw syscall - bypasses libc, directly executes syscall instruction
// static inline long raw_syscall(long n) {
//     long ret;
//     __asm__ volatile (
//         "syscall"
//         : "=a"(ret)
//         : "a"(n)
//         : "rcx", "r11", "memory"
//     );
//     return ret;
// }

int main(void) {
    printf("Hello World!\n");
    
    // // Try unauthorized syscall (getuid = 102)
    // printf("Attempting unauthorized syscall 102 (getuid)...\n");
    // fflush(stdout);
    
    // long uid = raw_syscall(SYS_getuid);
    
    // // Should NOT reach here if sandbox works!
    // printf("Got UID: %ld - SANDBOX FAILED!\n", uid);
    return 0;
}