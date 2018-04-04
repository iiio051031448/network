#ifndef __UP_H__
#define __UP_H__

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]

char *ip2str(unsigned int ipv4, char *str_ip, unsigned int str_len);
unsigned int str2ip(const char *ipstr);

#include <asm/io.h>                             
#define UP_MSG_PRINTF(fmt, ...) \
    printk("[%s][%d]", __func__, __LINE__); \
    printk(fmt, ##__VA_ARGS__); \
    printk("\n");

#endif //__UP_H__
