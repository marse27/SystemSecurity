#define _GNU_SOURCE
#include <signal.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <string.h>
#include <dlfcn.h>

#ifndef PR_SYS_DISPATCH_EXCLUSIVE_ON
#define PR_SYS_DISPATCH_EXCLUSIVE_ON 1
#endif

static volatile char selector = SYSCALL_DISPATCH_FILTER_ALLOW;

static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
    
    selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "SYSCALL: %d\n", info->si_syscall);
    write(STDERR_FILENO, buf, len);
    
    if (info->si_syscall == 59) {
        char msg[] = "🚫 BLOCKED EXECVE!\n";
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
        ctx->uc_mcontext.gregs[REG_RAX] = -1;
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        return;
    }
    
    long result = syscall(
        info->si_syscall,
        ctx->uc_mcontext.gregs[REG_RDI],
        ctx->uc_mcontext.gregs[REG_RSI],
        ctx->uc_mcontext.gregs[REG_RDX],
        ctx->uc_mcontext.gregs[REG_R10],
        ctx->uc_mcontext.gregs[REG_R8],
        ctx->uc_mcontext.gregs[REG_R9]
    );
    
    ctx->uc_mcontext.gregs[REG_RAX] = result;
    selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

// Find libc text region
static int get_libc_range(void **start, void **end) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;
    
    char line[256];
    *start = (void*)~0UL;
    *end = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start_addr, end_addr;
        char perms[5], path[128] = {0};
        
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %127s", 
                   &start_addr, &end_addr, perms, path) >= 3) {
            // Find libc executable regions
            if (perms[2] == 'x' && (strstr(path, "/libc-") || strstr(path, "/libc.so"))) {
                if ((void*)start_addr < *start) *start = (void*)start_addr;
                if ((void*)end_addr > *end) *end = (void*)end_addr;
            }
        }
    }
    
    fclose(maps);
    return (*start == (void*)~0UL) ? -1 : 0;
}

__attribute__((constructor))
static void setup_syscall_dispatch(void) {
    printf("🔒 Setting up...\n");
    
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsys_handler;
    sigfillset(&sa.sa_mask);
    sigdelset(&sa.sa_mask, SIGSYS);
    sigaction(SIGSYS, &sa, NULL);
    
    void *start, *end;
    if (get_libc_range(&start, &end) < 0) {
        printf("Failed to find libc\n");
        return;
    }
    
    printf("Allowed region (libc): %p to %p\n", start, end);
    
    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_EXCLUSIVE_ON,
              start, (size_t)end - (size_t)start, &selector) < 0) {
        perror("prctl");
        return;
    }
    
    selector = SYSCALL_DISPATCH_FILTER_BLOCK;
    printf("✅ Monitoring active!\n");
}