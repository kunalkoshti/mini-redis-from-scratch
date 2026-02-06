#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
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