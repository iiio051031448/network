#include <linux/in.h>         
#include <linux/ctype.h>
#include <linux/stat.h>
#include <linux/kobject.h>
#include <linux/list.h>

void dump_data(unsigned char*buff, int count, const char *func, int line)
{       
    int i = 0;
    if (NULL != func) {
        printk("\n================================================\n");
        printk("[%s][%d]\n", func, line);
    }
    for(i = 0; i < count; i++){
        printk("%02X ", buff[i]);
        if ((i + 1) != 1 && (i + 1) % 8 == 0) {
            printk(" ");
            if ((i + 1) != 1 && (i + 1) % 16 == 0) {
                printk("\n");
            }
        }
    }   
    if (NULL != func) {
        printk("\n");
        printk("================================================\n");
    }
    return;
}   

char *ip2str(unsigned int ipv4, char *str_ip, unsigned int str_len)
{
    if (str_ip == NULL || str_len < 16) {
        return NULL;
    }

    sprintf(str_ip, "%d.%d.%d.%d", (ipv4>>24)&0xff, (ipv4>>16)&0xff,
            (ipv4>>8)&0xff, ipv4&0xff);

    return str_ip;
}

unsigned int str2ip(const char *ipstr)
{
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    //inet_pton(AF_INET, ipstr, &addr.sin_addr);

    //return addr.sin_addr.s_addr;
    return 0x0A020A2E;
}

//EXPORT_SYMBOL(dump_data);
//EXPORT_SYMBOL(str2ip);
