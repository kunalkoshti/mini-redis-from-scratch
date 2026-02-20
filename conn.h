#ifndef CONN_H
#define CONN_H

#include "buffer.h"
#include <memory>
#include <vector>

struct Conn {
  int fd = -1;
  bool is_closed = false;
  Buffer incoming; // Buffer for data received from client
  Buffer outgoing; // Buffer for data to be sent to client
};

// Map FDs to Connection objects; unique_ptr handles automatic memory cleanup
extern std::vector<std::unique_ptr<Conn>> fd2conn;

void connection_destroy(int fd, int epfd);
void connection_destroy_multiple(std::vector<int> &to_close, int epfd);

#endif
