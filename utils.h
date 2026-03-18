#pragma once

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sys/socket.h>

template <typename T, typename M>
inline T *container_of_cpp(M *ptr, size_t offset) {
  return reinterpret_cast<T *>(reinterpret_cast<char *>(ptr) - offset);
}

#define container_of(ptr, type, member)                                        \
  container_of_cpp<type>(ptr, offsetof(type, member))

uint64_t str_hash(const uint8_t *data, size_t len);

void msg(const char *m);
void msg_errno(const char *msg);
void die(const char *m);
int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);
const char *inet_ntop2(sockaddr_storage *addr, char *buf, size_t size);
bool str2int(const std::string &s, int64_t &out);
bool str2dbl(const std::string &s, double &out);
