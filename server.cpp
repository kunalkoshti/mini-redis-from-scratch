#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "utils.h"

#define PORT "1234"

using namespace std;

const size_t k_max_msg_size = 4096;

static int32_t one_request(int connfd)
{
    char rbuf[4 + k_max_msg_size];
    errno = 0;
    int32_t err = read_full(connfd, rbuf, 4);
    if (err == -1)
    {
        msg(errno == 0 ? "unexpected EOF error" : "recv() error");
        return -1;
    }
    uint32_t len = 0;
    memcpy(&len, rbuf, 4);
    len = ntohl(len);
    if (len > k_max_msg_size)
    {
        msg("message too big");
        return -1;
    }
    err = read_full(connfd, &rbuf[4], len);
    if (err == -1)
    {
        msg(errno == 0 ? "unexpected EOF error" : "recv() error");
        return -1;
    }
    printf("client says: %.*s\n", len, &rbuf[4]);
    const char *response = "Hello from server!\n";
    char wbuf[4 + strlen(response)];
    uint32_t wlen = (uint32_t)strlen(response);
    uint32_t net_wlen = htonl(wlen);
    memcpy(wbuf, &net_wlen, 4);
    memcpy(&wbuf[4], response, wlen);
    err = write_full(connfd, wbuf, 4 + wlen);
    if (err == -1)
    {
        msg("send() error");
        return -1;
    }
    return 0;
}

void do_something(int fd)
{
    char buf[100];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    if (n == -1)
    {
        msg("recv() error");
        return;
    }
    fprintf(stdout, "Received: %.*s\n", (int)n, buf);
    const char *response = "Hello from server!\n";
    if (send(fd, response, strlen(response), 0) == -1)
    {
        msg("send() error");
        return;
    }
}

int main()
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int s = getaddrinfo(NULL, PORT, &hints, &res);
    if (s != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        abort();
    }
    int listen_fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd == -1)
        {
            die("socket() error");
        }
        int yes = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            die("setsockopt() error");
        }
        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
            msg("bind() error");
            close(listen_fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (listen_fd == -1)
    {
        die("Failed to bind");
    }
    if (listen(listen_fd, 10) == -1)
    {
        die("listen() error");
    }
    fprintf(stdout, "Server is listening on port %s\n", PORT);
    fprintf(stdout, "Waiting for connections...\n");
    while (true)
    {
        struct sockaddr_storage client_addr;
        socklen_t addr_size = sizeof client_addr;
        int new_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_size);
        if (new_fd == -1)
        {
            msg("accept() error");
            continue;
        }
        fprintf(stdout, "server: got connection\n");
        while (true)
        {
            int32_t err = one_request(new_fd);
            if (err == -1)
            {
                break;
            }
        }
        close(new_fd);
    }
    return 0;
}