#pragma once

#include "buffer.h"
#include "list.h"
#include <memory>
#include <vector>

struct PartialReadTimer {
  bool in_list = false;
  uint64_t last_read_ms = 0;
};

struct PartialWriteTimer {
  bool in_list = false;
  uint64_t last_write_ms = 0;
};

struct Conn {
  int fd = -1;
  bool is_closed = false;
  Buffer incoming; // Buffer for data received from client
  Buffer outgoing; // Buffer for data to be sent to client
  uint64_t last_active_ms = 0;
  DList idle_node;
  PartialReadTimer partial_read;
  PartialWriteTimer partial_write;
  DList read_pending_node;
  DList write_pending_node;
};

// Map FDs to Connection objects; unique_ptr handles automatic memory cleanup
extern std::vector<std::unique_ptr<Conn>> fd2conn;
extern DList g_idle_list;
extern DList g_read_pending_list;
extern DList g_write_pending_list;

void init_conn_state();
void connection_destroy(int fd, int epfd);
void connection_destroy_multiple(std::vector<int> &to_close, int epfd);
