#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <arpa/inet.h>
#include "utils.h"

void msg(const char *m)
{
    fprintf(stderr, "%s\n", m);
}

void msg_errno(const char *msg)
{
    fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

void die(const char *m)
{
    int err = errno;
    fprintf(stderr, "[%d] %s: %s\n", err, m, strerror(err));
    abort();
}

int32_t read_full(int fd, char *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = recv(fd, buf, n, 0);
        if (rv < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (rv == 0)
        {
            return -1;
        }
        assert((size_t)rv <= n);
        buf += rv;
        n -= (size_t)rv;
    }
    return 0;
}

int32_t write_full(int fd, const char *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = send(fd, buf, n, 0);
        if (rv < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (rv == 0)
        {
            return -1;
        }
        assert((size_t)rv <= n);
        buf += rv;
        n -= (size_t)rv;
    }
    return 0;
}

const char *inet_ntop2(sockaddr_storage *addr, char *buf, size_t size)
{
    struct sockaddr_storage *sas = addr;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    void *src;

    switch (sas->ss_family)
    {
    case AF_INET:
        sa4 = (struct sockaddr_in *)addr;
        src = &(sa4->sin_addr);
        break;
    case AF_INET6:
        sa6 = (struct sockaddr_in6 *)addr;
        src = &(sa6->sin6_addr);
        break;
    default:
        return NULL;
    }

    return inet_ntop(sas->ss_family, src, buf, size);
}