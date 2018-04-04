#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>

#include "sdns.h"

#define SERVER_PORT     (8898)
#define BUF_SIZE        (1024)

typedef struct dns_flags {
#if __BYTE_ORDER__ ==__ORDER_LITTLE_ENDIAN__
    unsigned short rcode:4,
                   z:3,
                   ra:1,
                   rd:1,
                   tc:1,
                   aa:1,
                   opcode:4,
                   qr:1;
#elif __BYTE_ORDER__ ==__ORDER_BIG_ENDIAN__
    unsigned short qr:1,
                   opcode:4,
                   aa:1,
                   tc:1,
                   rd:1,
                   ra:1,
                   z:3,
                   rcode:4;
#endif
}__attribute__((packed)) DNS_FLAGS_ST;

union flags_un {
    struct dns_flags bits;
    unsigned short unit;
};

typedef struct s_dns_header
{
    unsigned short id;
    union flags_un flags;
    unsigned short qr_cnt;
    unsigned short an_cnt;
    unsigned short ns_cnt;
    unsigned short ar_cnt;
}__attribute__((packed)) S_DNS_HEADER_ST;

typedef struct dns_rrs_tag
{
    unsigned short name;
    unsigned short type;
    unsigned short class;
    /* unsigned long  ttl; 8 bit for X86_64 */
    unsigned int ttl;
    unsigned short len;
    /* unsigned long  ip; 8 bit for X86_64 */
    unsigned int ip;
}__attribute__((packed)) S_DNS_RRS_ST;

static int g_srv_fd = -1;

static int extract_domain_name(char *str, char *name, int maxlen)
{
    char *p = str;
    char *q = name;
    int len = 0;
    while(*p != 0 && *p < 32) p++;
    while(*p != 0 && len < maxlen){
        if(*p < 32)
            *q = '.';
        else
            *q = *p;
        len ++;
        p ++;
        q ++;
    }
    *q = 0;

    return 0;
}

int send_dns_response(int dst_ip, short dst_port, char *resp, int resp_len)
{
    struct sockaddr_in dst_addr;

    __DUMP_DATA(resp, resp_len);

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = dst_ip;
    dst_addr.sin_port = dst_port;

    sendto(g_srv_fd, resp, resp_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

    return 0;
}

static int do_dns_intercept(const char *msg, int msg_len, struct sockaddr_in *clt_addr)
{
    S_DNS_HEADER_ST *dh = NULL;
    union flags_un flags;
    char resp[1024] = {0};
    int resp_len = 0;
    S_DNS_HEADER_ST *resp_dh;
    S_DNS_RRS_ST *answer = NULL;

    dh = (S_DNS_HEADER_ST *)msg;
    flags.unit = ntohs(dh->flags.unit);

    memcpy(resp, msg, msg_len);
    resp_dh = (S_DNS_HEADER_ST *)resp;
    flags.bits.qr = 1;
    flags.bits.aa = 1;
    flags.bits.ra = 1;
    resp_dh->flags.unit = htons(flags.unit);
    resp_len = msg_len;

    /* answers count */
    resp_dh->an_cnt = htons(1); 

    answer = (S_DNS_RRS_ST *)((char *)resp_dh + msg_len);
    answer->name = htons(0xC00C);
    answer->type = htons(0x1);
    answer->class = htons(0x1);
    answer->ttl = htonl(0x0);
    answer->len = htons(0x4);
    answer->ip = str2ip("10.2.10.46");
    resp_len += sizeof(S_DNS_RRS_ST);

    _LOG("answer size : %ld", sizeof(int));

    send_dns_response(clt_addr->sin_addr.s_addr, clt_addr->sin_port, resp, resp_len);

    return 0;
}

static int handle_msg(const char *msg, int msg_len, struct sockaddr_in *clt_addr)
{
    S_DNS_HEADER_ST *dh = NULL;
    union flags_un flags;
    char ip_buf[16] = {0};
    int qr_cnt = 0;

    dh = (S_DNS_HEADER_ST *)msg;
    flags.unit = ntohs(dh->flags.unit);
    qr_cnt = dh->qr_cnt;

    ip2str(clt_addr->sin_addr.s_addr, ip_buf, sizeof(ip_buf));
    _LOG("recv data. from %s:%d", ip_buf, clt_addr->sin_port);
    __DUMP_DATA(msg, msg_len);
    __DUMP_DATA(dh, sizeof(*dh));
    _LOG("Questions:%d", qr_cnt);
    _LOG("RD:%d", flags.bits.rd);

    if (0 == qr_cnt) {
        _LOG("qr cnt is 0");
        return 0;
    }

    char qr_domain[256] = {0};
    extract_domain_name((char *)(dh + 1), qr_domain, sizeof(qr_domain));
    _LOG("qr domain : [%s]", qr_domain);

    do_dns_intercept(msg, msg_len, clt_addr);

    return 0;
}

int wait_msg(int srv_fd)
{
    int cnt = -1;
    char buf[BUF_SIZE];
    socklen_t len;
    struct sockaddr_in clt_addr;

    len = sizeof(clt_addr);

    while(1) {
        memset(buf, 0, sizeof(buf));
        cnt = recvfrom(srv_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&clt_addr, &len);
        if (cnt < 0) {
            _LOG("recv failed.");
            return -1;
        }

        handle_msg(buf, cnt, &clt_addr);
    }
    
    return 0;
}

int main(void)
{
    int ret = -1;
    int srv_fd = -1;    
    struct sockaddr_in srv_addr;

    srv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_fd < 0) {
        _LOG("create socket failed.");
        return -1;
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(SERVER_PORT);

    ret = bind(srv_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if (ret < 0) {
        _LOG("bind socket failed."); 
        goto error;
    }

    _LOG("smart dns start. listen on port:%d", SERVER_PORT);

    g_srv_fd = srv_fd;

    wait_msg(srv_fd);

    close(srv_fd);
    srv_fd = -1;
    g_srv_fd = -1;

    return 0;

error:
    if (srv_fd > 0) {
        close(srv_fd);
        srv_fd = -1;
    }

    return -1;
}

