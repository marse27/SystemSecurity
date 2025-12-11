#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    printf("Hello World!\n");
    
    // Not in policy.txt
    getpid();
    printf("SANDBOX DOESN'T WORK!!\n");
    return 0;
}