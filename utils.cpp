#include "utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <cmath>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

// FNV hash
uint64_t str_hash(const uint8_t *data, size_t len) {
  uint32_t h = 0x811C9DC5;
  for (size_t i = 0; i < len; i++) {
    h = (h + data[i]) * 0x01000193;
  }
  return h;
}

void msg(const char *m) { fprintf(stderr, "%s\n", m); }

void msg_errno(const char *msg) {
  fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

void die(const char *m) {
  int err = errno;
  fprintf(stderr, "[%d] %s: %s\n", err, m, strerror(err));
  abort();
}

int32_t read_full(int fd, char *buf, size_t n) {
  while (n > 0) {
    ssize_t rv = recv(fd, buf, n, 0);
    if (rv < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (rv == 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    buf += rv;
    n -= (size_t)rv;
  }
  return 0;
}

int32_t write_full(int fd, const char *buf, size_t n) {
  while (n > 0) {
    ssize_t rv = send(fd, buf, n, 0);
    if (rv < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (rv == 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    buf += rv;
    n -= (size_t)rv;
  }
  return 0;
}

const char *inet_ntop2(sockaddr_storage *addr, char *buf, size_t size) {
  struct sockaddr_storage *sas = addr;
  struct sockaddr_in *sa4;
  struct sockaddr_in6 *sa6;
  void *src;

  switch (sas->ss_family) {
  case AF_INET:
    sa4 = (struct sockaddr_in *)addr;
    src = &(sa4->sin_addr);
    break;
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *)addr;
    src = &(sa6->sin6_addr);
    break;
  default:
    return nullptr;
  }

  return inet_ntop(sas->ss_family, src, buf, size);
}

bool str2int(const std::string &s, int64_t &out) {
  char *end = nullptr;
  errno = 0;
  out = strtoll(s.c_str(), &end, 10);
  return !(end == s.c_str() || *end != '\0' || errno == ERANGE);
}

bool str2dbl(const std::string &s, double &out) {
  char *end = nullptr;
  errno = 0;
  out = strtod(s.c_str(), &end);
  return !(end == s.c_str() || *end != '\0' || errno == ERANGE ||
           !std::isfinite(out));
}