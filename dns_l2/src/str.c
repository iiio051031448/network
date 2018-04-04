#include <linux/in.h>         
#include <linux/ctype.h>
#include <linux/stat.h>
#include <linux/kobject.h>
#include <linux/list.h>


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
