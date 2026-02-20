#include "conn.h"
#include <sys/epoll.h>
#include <unistd.h>

// Global connection table definition
std::vector<std::unique_ptr<Conn>> fd2conn;

void connection_destroy(int fd, int epfd) {
  if (fd < 0 || (size_t)fd >= fd2conn.size() || !fd2conn[fd])
    return;

  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
  close(fd);
  fd2conn[fd].reset();
}

void connection_destroy_multiple(std::vector<int> &to_close, int epfd) {
  for (auto &fd : to_close) {
    connection_destroy(fd, epfd);
  }
}
