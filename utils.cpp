#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include "utils.h"

void msg(const char *m)
{
    fprintf(stderr, "%s\n", m);
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