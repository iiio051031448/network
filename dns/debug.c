#include <stdio.h>
#include <string.h>

void dump_data(unsigned char*buff, int count, const char *func, int line)
{       
    int i = 0;
    if (NULL != func) {
        printf("\n================================================\n");
        printf("[%s][%d]\n", func, line);
    }
    for(i = 0; i < count; i++){
        printf("%02X ", buff[i]);
        if ((i + 1) != 1 && (i + 1) % 8 == 0) {
            printf(" ");
            if ((i + 1) != 1 && (i + 1) % 16 == 0) {
                printf("\n");
            }
        }
    }   
    if (NULL != func) {
        printf("\n");
        printf("================================================\n");
    }
    return;
}   
