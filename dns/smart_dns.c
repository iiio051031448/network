#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>

#define _LOG(fmt, ...) \
    printf("[%s][%d]" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)


#define SERVER_PORT     (8898)
#define BUF_SIZE        (1024)

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
        _LOG("recv data.");
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

    wait_msg(srv_fd);

    close(srv_fd);
    srv_fd = -1;

    return 0;

error:
    if (srv_fd > 0) {
        close(srv_fd);
        srv_fd = -1;
    }

    return -1;
}

