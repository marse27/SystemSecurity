#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pmparser.h"

#define SYSCALL_BYTE1 0x0F
#define SYSCALL_BYTE2 0x05

void scan_region(procmaps_struct* map) {
    unsigned char* start = (unsigned char*)map->addr_start;
    unsigned char* end = (unsigned char*)map->addr_end;
    size_t region_size = map->length;
    const char* pathname = map->pathname ? map->pathname : "[anonymous]";
    
    printf("\n[*] Scanning region:  %s\n", pathname);
    printf("    Address range: %p - %p\n", start, end);
    printf("    Size: %zu bytes\n", region_size);
    printf("    Permissions: %c%c%c%c\n", 
           map->is_r ?  'r' : '-',
           map->is_w ? 'w' : '-',
           map->is_x ? 'x' :  '-',
           map->is_p ? 'p' : 's');
    
    int syscall_count = 0;
    
    for (unsigned char* ptr = start; ptr < end - 1; ptr++) {
        if (ptr[0] == SYSCALL_BYTE1 && ptr[1] == SYSCALL_BYTE2) {
            printf("syscall found at address: %p\n", ptr);
            syscall_count++;
        }
    }
    
    printf("total syscalls found in this region: %d\n", syscall_count);
}

__attribute__((constructor))
void init_scanner(void) {
    printf("scanning for syscall instr");
    
    procmaps_iterator maps_it;
    procmaps_error_t result = pmparser_parse(-1, &maps_it);
    
    if (result != PROCMAPS_SUCCESS) {
        fprintf(stderr, "Error %d\n", result);
        return;
    }
    
    procmaps_struct* map = NULL;
    int regions_scanned = 0;
    
    while ((map = pmparser_next(&maps_it)) != NULL) {
        if (map->is_x) {
            scan_region(map);
            regions_scanned++;
        }
    }
    
    pmparser_free(&maps_it);
    printf("scan complete\n");
    printf("total regions scanned: %d\n", regions_scanned);
}
