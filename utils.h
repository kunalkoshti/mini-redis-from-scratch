#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
#include <sys/socket.h>

void msg(const char *m);
void msg_errno(const char *msg);
void die(const char *m);
int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);
const char *inet_ntop2(sockaddr_storage *addr, char *buf, size_t size);

#endif