#include "conn.h"
#include "io_handlers.h"
#include "utils.h"
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define PORT "1234"
#define MAX_EVENTS 64

int main() {
  // Setup listening socket
  struct addrinfo hints = {}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(NULL, PORT, &hints, &res) != 0)
    die("getaddrinfo");

  int listen_fd = -1;
  for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (listen_fd == -1)
      continue;

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == 0)
      break;
    close(listen_fd);
    listen_fd = -1;
  }
  freeaddrinfo(res);
  if (listen_fd == -1)
    die("Failed to bind");

  fd_set_nb(listen_fd);
  if (listen(listen_fd, 128) == -1)
    die("listen() error");

  printf("Server listening on port %s\n", PORT);

  int epfd = epoll_create1(0);
  if (epfd == -1)
    die("epoll_create1");

  // Listen FD exists on the stack; no need for unique_ptr ownership
  Conn listen_conn;
  listen_conn.fd = listen_fd;
  struct epoll_event ev = {};
  ev.data.ptr = &listen_conn;
  ev.events = EPOLLIN;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) == -1)
    die("epoll_ctl() add");

  struct epoll_event events[MAX_EVENTS];
  while (true) {
    int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
    if (n == -1) {
      if (errno == EINTR)
        continue;
      die("epoll_wait");
    }

    std::vector<int> to_close;

    for (int i = 0; i < n; i++) {
      Conn *conn = (Conn *)events[i].data.ptr;
      if (conn->fd == listen_fd) {
        // Accept all pending connections in loop (ET mode)
        while (true) {
          auto client_conn = handle_accept(listen_fd);
          if (!client_conn)
            break;

          int fd = client_conn->fd;
          if ((size_t)fd >= fd2conn.size())
            fd2conn.resize(fd + 1);

          struct epoll_event cev = {};
          cev.data.ptr = client_conn.get(); // Epoll stores raw pointer
          cev.events = EPOLLIN | EPOLLET;

          if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &cev) == -1) {
            msg_errno("epoll_ctl add");
            close(fd);
          } else {
            // Transfer ownership to global table
            fd2conn[fd] = std::move(client_conn);
          }
        }
      } else {
        if (!conn->is_closed && (events[i].events & EPOLLIN))
          handle_read(conn, epfd);

        if (!conn->is_closed && (events[i].events & EPOLLOUT))
          handle_write(conn, epfd);

        if (!conn->is_closed && (events[i].events & (EPOLLERR | EPOLLHUP)))
          conn->is_closed = true;

        if (conn->is_closed) {
          to_close.push_back(conn->fd);
        }
      }
    }
    connection_destroy_multiple(to_close, epfd);
  }
  return 0;
}