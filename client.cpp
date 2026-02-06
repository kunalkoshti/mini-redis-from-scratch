#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include "utils.h"

#define PORT "1234"

using namespace std;

int main()
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int s = getaddrinfo("localhost", PORT, &hints, &res);
    if (s != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        abort();
    }
    int sock_fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
        sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd == -1)
        {
            die("socket() error");
        }
        if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
            msg("connect() error");
            close(sock_fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (sock_fd == -1)
    {
        die("Failed to connect");
    }
    const char *request = "Hello from client!\n";
    if (send(sock_fd, request, strlen(request), 0) == -1)
    {
        die("send() error");
    }
    char buf[100];
    ssize_t n = recv(sock_fd, buf, sizeof buf, 0);
    if (n == -1)
    {
        die("recv() error");
    }
    fprintf(stdout, "Received: %.*s\n", (int)n, buf);
    close(sock_fd);
    return 0;
}