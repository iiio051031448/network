#ifndef __SDNS_H__
#define __SDNS_H__

#define _LOG(fmt, ...) \
    printf("[%s][%d]" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

void dump_data(unsigned char*buff, int count, const char *func, int line);
#define __DUMP_DATA(d, n) \
    do { \
        dump_data((unsigned char *)d, n, __func__, __LINE__); \
    } while(0)

char *ip2str(unsigned int ipv4, char *str_ip, unsigned int str_len);
unsigned int str2ip(const char *ipstr);

#endif //__SDNS_H__
