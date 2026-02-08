#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include "utils.h"

#define PORT "1234"
const size_t k_max_msg = 4096;
const int msg_ct = 10;

using namespace std;

static int32_t query(int fd, const char *text)
{
    uint32_t len = (uint32_t)strlen(text);
    if (len > k_max_msg)
    {
        msg("message too big");
        return -1;
    }
    char wbuf[4 + k_max_msg];
    uint32_t netlen = htonl(len);
    memcpy(wbuf, &netlen, 4);
    memcpy(&wbuf[4], text, len);
    int32_t err = write_full(fd, wbuf, 4 + len);
    if (err == -1)
    {
        msg("send() error");
        return -1;
    }
    char rbuf[4 + k_max_msg];
    errno = 0;
    err = read_full(fd, rbuf, 4);
    if (err == -1)
    {
        msg(errno == 0 ? "unexpected EOF error" : "recv() error");
        return -1;
    }
    uint32_t rlen = 0;
    memcpy(&rlen, rbuf, 4);
    rlen = ntohl(rlen);
    if (rlen > k_max_msg)
    {
        msg("message too big");
        return -1;
    }
    err = read_full(fd, &rbuf[4], rlen);
    if (err == -1)
    {
        msg(errno == 0 ? "unexpected EOF error" : "recv() error");
        return -1;
    }
    printf("server says: %.*s\n", rlen, &rbuf[4]);
    return 0;
}

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
    for (int i = 0; i < msg_ct; i++)
    {
        string s = "client says: Hello " + to_string(i) + "!";
        if (query(sock_fd, s.c_str()) == -1)
        {
            break;
        }
    }
    close(sock_fd);
    return 0;
}