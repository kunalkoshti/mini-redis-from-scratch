#include "conn.h"
#include <sys/epoll.h>
#include <unistd.h>

// Global connection table definition
std::vector<std::unique_ptr<Conn>> fd2conn;
DList g_idle_list;
DList g_read_pending_list;
DList g_write_pending_list;

void init_conn_state() {
  dlist_init(&g_idle_list);
  dlist_init(&g_read_pending_list);
  dlist_init(&g_write_pending_list);
}

void connection_destroy(int fd, int epfd) {
  if (fd < 0 || (size_t)fd >= fd2conn.size() || !fd2conn[fd])
    return;

  Conn *conn = fd2conn[fd].get();
  dlist_detach(&conn->idle_node);
  if (conn->partial_read.in_list) {
    dlist_detach(&conn->read_pending_node);
  }
  if (conn->partial_write.in_list) {
    dlist_detach(&conn->write_pending_node);
  }
  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
  close(fd);
  fd2conn[fd].reset();
}

void connection_destroy_multiple(std::vector<int> &to_close, int epfd) {
  for (auto &fd : to_close) {
    connection_destroy(fd, epfd);
  }
}
