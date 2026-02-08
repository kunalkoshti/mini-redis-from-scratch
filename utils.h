#ifndef UTILS_H
#define UTILS_H

void msg(const char *m);
void die(const char *m);
int32_t read_full(int fd, char *buf, size_t n);
int32_t write_full(int fd, const char *buf, size_t n);

#endif