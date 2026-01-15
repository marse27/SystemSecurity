#define _GNU_SOURCE
#include <signal.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define MAX_SYSCALL 512

static volatile char sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
static int allowed_syscalls[MAX_SYSCALL] = {0};

extern const char syscall_dispatcher_start[];
extern const char syscall_dispatcher_end[];

static void load_policy(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return;
    
    int sc, count = 0;
    while (fscanf(f, "%d", &sc) == 1) {
        if (sc >= 0 && sc < MAX_SYSCALL) {
            allowed_syscalls[sc] = 1;
            count++;
        }
    }
    fclose(f);
    printf("\nLoaded %d syscalls\n", count);
}

static int prot_is_wx(long prot) {
    return ((prot & PROT_WRITE) && (prot & PROT_EXEC));
}

static int flags_is_writeable(long flags) {
    return ((flags & O_ACCMODE) != O_RDONLY);
}

#define RETURN_FROM_HANDLER()                         \
    do {                                              \
        sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK; \
        __asm__ volatile (                            \
            "movq $15, %%rax\n\t"                     \
            "leaveq\n\t"                              \
            "add $8, %%rsp\n\t"                       \
            "jmp syscall_dispatcher_start\n\t"        \
            ::: "memory"                              \
        );                                            \
    } while (0)


static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;

    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    
    ucontext_t *ctx = (ucontext_t *)ucontext;
    int sc = info->si_syscall;

    long a1 = ctx->uc_mcontext.gregs[REG_RDI];
    long a2 = ctx->uc_mcontext.gregs[REG_RSI];
    long a3 = ctx->uc_mcontext.gregs[REG_RDX];
    long a4 = ctx->uc_mcontext.gregs[REG_R10];
    long a5 = ctx->uc_mcontext.gregs[REG_R8];
    long a6 = ctx->uc_mcontext.gregs[REG_R9];

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "SYSCALL: %d\n", sc);
    write(STDERR_FILENO, buf, len);
    
    if (sc == __NR_mprotect) {
        long prot = a3;
        if (prot_is_wx(prot)) {
            ctx->uc_mcontext.gregs[REG_RAX] = -EPERM;
            RETURN_FROM_HANDLER();
        }
    }

    if (sc == __NR_open) {
        const char *path = (const char *)a1;
        long flags = a2;

        if (path && strcmp(path, "/proc/self/mem") == 0 && flags_is_writeable(flags)) {
            ctx->uc_mcontext.gregs[REG_RAX] = -EACCES;
            RETURN_FROM_HANDLER();
        }
    }

    if (sc == __NR_openat) {
        const char *path = (const char *)a2;
        long flags = a3;

        if (path && strcmp(path, "/proc/self/mem") == 0 && flags_is_writeable(flags)) {
            ctx->uc_mcontext.gregs[REG_RAX] = -EACCES;
            RETURN_FROM_HANDLER();
        }
    }

    // Policy check
    if (!allowed_syscalls[sc]) {
        char msg[64];
        len = snprintf(msg, sizeof(msg), "BLOCKED SYSCALL: %d - TERMINATING!\n\n", sc);
        write(STDERR_FILENO, msg, len);
        _exit(1);
    }
    
    // Execute the syscall
    long result = syscall(sc, a1, a2, a3, a4, a5, a6);
    
    ctx->uc_mcontext.gregs[REG_RAX] = result;
    
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
    
    // Manually do rt_sigreturn inside the exclusive region instead of normal return with vDSO
    __asm__ volatile (
        "movq $15, %%rax\n\t"           // rt_sigreturn = 15
        "leaveq\n\t"                    
        "add $8, %%rsp\n\t"              
        "jmp syscall_dispatcher_start\n\t"  // Jump to exclusive region
        ::: "memory"
    );     
}

// The exclusive region for rt_sigreturn
__asm__ (
    ".global syscall_dispatcher_start\n\t"
    ".global syscall_dispatcher_end\n\t"
    "syscall_dispatcher_start:\n\t"
    "syscall\n\t"
    "nop\n\t"
    "syscall_dispatcher_end:\n\t"
    "nop\n\t"
);

static void sud_setup() {
    load_policy(getenv("POLICY"));
    
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsys_handler;
    sigfillset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
    
    // The exclusive region for our sandbox to execute rt_sigreturn instead of vDSO
    const char *start = syscall_dispatcher_start;
    const char *end = syscall_dispatcher_end;
    
    printf("Dispatcher: %p - %p (%ld bytes)\n", 
           start, end, (long)((char*)end - (char*)start));
    
    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
              start, (size_t)((char*)end - (char*)start + 1), 
              &sud_selector) < 0) {
        perror("prctl");
        return;
    }
    
    printf("SUD active!\n\n");
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

__attribute__((constructor))
static void __sud_init(void) {
    sud_setup();
}