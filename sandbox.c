// #define _GNU_SOURCE
// #include <signal.h>
// #include <sys/prctl.h>
// #include <linux/prctl.h>
// #include <unistd.h>
// #include <stdio.h>
// #include <sys/syscall.h>
// #include <ucontext.h>
// #include <string.h>
// #include <dlfcn.h>
// #include <stdlib.h>

// static volatile char sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;

// static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
//     sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    
//     ucontext_t *ctx = (ucontext_t *)ucontext;
    
//     char buf[128];
//     int len = snprintf(buf, sizeof(buf), "SYSCALL: %d\n", info->si_syscall);
//     write(STDERR_FILENO, buf, len);
    
//     // instead of if syscall = 102, check if si_syscall in poluicy.txt, if not say blocked and exit to kill hello program
//     if (info->si_syscall == 102) {
//         char msg[] = "🚫 BLOCKED EXECVE!\n";
//         write(STDERR_FILENO, msg, sizeof(msg) - 1);
//         ctx->uc_mcontext.gregs[REG_RAX] = -1;
//         sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
//         exit(1);
//     }
    
//     // Manual syscall
//     long result = syscall(
//         info->si_syscall,
//         ctx->uc_mcontext.gregs[REG_RDI],
//         ctx->uc_mcontext.gregs[REG_RSI],
//         ctx->uc_mcontext.gregs[REG_RDX],
//         ctx->uc_mcontext.gregs[REG_R10],
//         ctx->uc_mcontext.gregs[REG_R8],
//         ctx->uc_mcontext.gregs[REG_R9]
//     );
    
//     ctx->uc_mcontext.gregs[REG_RAX] = result;
//     sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
// }

// // Find program's text region
// static int get_program_range(void **start, void **end) {
//     FILE *maps = fopen("/proc/self/maps", "r");
//     if (!maps) return -1;
    
//     char line[256];
//     int found = 0;
    
//     while (fgets(line, sizeof(line), maps)) {
//         unsigned long start_addr, end_addr;
//         char perms[5], path[128] = {0};
        
//         if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %127s", 
//                    &start_addr, &end_addr, perms, path) >= 3) {
//             // Find hello executable region (adjust "hello" to your binary name)
//             if (perms[2] == 'x' && strstr(path, "/hello") != NULL) {
//                 *start = (void *)start_addr;
//                 *end = (void *)end_addr;
//                 found = 1;
//                 break;
//             }
//         }
//     }
    
//     fclose(maps);
//     return found ? 0 : -1;
// }

// __attribute__((constructor))
// static void setup_syscall_dispatch(void) {
//     printf("Setting up SUD...\n");
    
//     struct sigaction sa = {0};
//     sa.sa_flags = SA_SIGINFO;
//     sa.sa_sigaction = sigsys_handler;
//     sigfillset(&sa.sa_mask);
//     sigdelset(&sa.sa_mask, SIGSYS);
//     sigaction(SIGSYS, &sa, NULL);
    
//     void *start, *end;
//     if (get_program_range(&start, &end) < 0) {
//         printf("Failed to find program's range\n");
//         return;
//     }
    
//     printf("Monitored region: %p to %p\n", start, end);
    
//     // INCLUSIVE mode - monitor only program's code
//     if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_INCLUSIVE_ON,
//               start, (size_t)end - (size_t)start, &sud_selector) < 0) {
//         perror("prctl");
//         return;
//     }
    
//     printf("SUD active!\n");
//     sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
// }
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
#include <stdlib.h>

#define MAX_SYSCALL 512

static volatile char sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
static int allowed_syscalls[MAX_SYSCALL] = {0};

// Load policy from file
static void load_policy(const char *filename) {
    if (!filename) {
        printf("⚠️  No POLICY environment variable set, blocking all syscalls!\n");
        return;
    }
    
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("⚠️  Failed to open policy file: %s\n", filename);
        perror("fopen");
        return;
    }
    
    int syscall_num;
    int count = 0;
    while (fscanf(f, "%d", &syscall_num) == 1) {
        if (syscall_num >= 0 && syscall_num < MAX_SYSCALL) {
            allowed_syscalls[syscall_num] = 1;
            count++;
        }
    }
    fclose(f);
    printf("✅ Loaded %d allowed syscalls from %s\n", count, filename);
}

static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    ucontext_t *ctx = (ucontext_t *)ucontext;
    
    int sc = info->si_syscall;
    
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "SYSCALL: %d\n", sc);
    write(STDERR_FILENO, buf, len);
    
    // Check if syscall is in policy
    if (sc < 0 || sc >= MAX_SYSCALL || !allowed_syscalls[sc]) {
        char msg[256];
        len = snprintf(msg, sizeof(msg), 
                      "🚫 BLOCKED: Syscall %d is NOT in policy!\n"
                      "🛑 Terminating program.\n", sc);
        write(STDERR_FILENO, msg, len);
        
        // Kill the program
        syscall(SYS_exit_group, 1);  // Ensure entire process dies
    }
    
    // Syscall is allowed - execute it
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
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

// Find program's text region
static int get_program_range(void **start, void **end) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;
    
    char line[256];
    int found = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start_addr, end_addr;
        char perms[5], path[128] = {0};
        
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %127s", 
                   &start_addr, &end_addr, perms, path) >= 3) {
            // Find hello executable region
            if (perms[2] == 'x' && strstr(path, "/hello") != NULL) {
                *start = (void *)start_addr;
                *end = (void *)end_addr;
                found = 1;
                break;
            }
        }
    }
    
    fclose(maps);
    return found ? 0 : -1;
}

__attribute__((constructor))
static void setup_syscall_dispatch(void) {
    printf("🔒 Setting up Syscall User Dispatch Sandbox...\n");
    
    // Load policy from environment variable
    const char *policy_file = getenv("POLICY");
    load_policy(policy_file);
    
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsys_handler;
    sigfillset(&sa.sa_mask);
    sigdelset(&sa.sa_mask, SIGSYS);
    sigaction(SIGSYS, &sa, NULL);
    
    void *start, *end;
    if (get_program_range(&start, &end) < 0) {
        printf("Failed to find program's range\n");
        return;
    }
    
    printf("Monitored region: %p to %p\n", start, end);
    
    // INCLUSIVE mode - monitor only program's code
    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_INCLUSIVE_ON,
              start, (size_t)end - (size_t)start, &sud_selector) < 0) {
        perror("prctl");
        return;
    }
    
    printf("✅ SUD active!\n\n");
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}