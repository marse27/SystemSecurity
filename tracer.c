#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h> 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_SYSCALL 1024
#define RUNS 1

static void end_program(const char *msg) {
    perror(msg);
    exit(1);
}

static void trace_once(char *prog, char **args, int *seen, FILE *policy) {
    pid_t child = fork();
    if (child == -1) {
        end_program("fork");
    }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            end_program("ptrace(TRACEME)");
        }
        raise(SIGSTOP);

        execvp(prog, args);
        end_program("execvp");
    }

    int status;
    int syscall = 0;

    if (waitpid(child, &status, 0) == -1) {
        end_program("waitpid");
    }

    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == -1) {
        end_program("ptrace(SETOPTIONS)");
    }

    while (1) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1) {
            end_program("ptrace(SYSCALL)");
        }

        if (waitpid(child, &status, 0) == -1) {
            end_program("waitpid");
        }

        if (WIFEXITED(status)) {
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) {
            end_program("ptrace(GETREGS)");
        }

        if (!syscall) {
            long sc = regs.orig_rax;

            if (sc >= 0 && sc < MAX_SYSCALL) {
                if (!seen[sc]) {
                    seen[sc] = 1;
                    fflush(policy);
                }
            }
            syscall = 1;
        } else {
            syscall = 0;
        }
    }
}

int main(int argc, char *argv[]) {
    (void)argc;

    FILE *policy = fopen("policy.txt", "w");
    if (!policy) {
        end_program("fopen(policy.txt)");
    }

    int seen[MAX_SYSCALL] = {0};

    for (int i = 0; i < RUNS; i++) {
        trace_once(argv[1], &argv[1], seen, policy);
    }

    fprintf(policy, "Unique syscalls across %d runs (also in policy.txt):\n", RUNS);
    for (int i = 0; i < MAX_SYSCALL; i++) {
        if (seen[i]) {
            fprintf(policy, "%d\n", i);
        }
    }

    fclose(policy);

    return 0;
}
