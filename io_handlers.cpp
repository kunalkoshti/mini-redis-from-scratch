#include "io_handlers.h"
#include "protocol.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static const size_t read_buffer_size = 64 * 1024;

// Set socket to non-blocking mode for use with epoll edge-trigger
void fd_set_nb(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    die("fcntl F_GETFL error");
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    die("fcntl F_SETFL error");
}

// Accept new client and initialize connection state
std::unique_ptr<Conn> handle_accept(int listen_fd) {
  struct sockaddr_storage ss;
  socklen_t slen = sizeof ss;
  int connfd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
  if (connfd < 0) {
    // EAGAIN means no more pending connections in the queue
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      msg_errno("accept() error");
    return nullptr;
  }

  fprintf(stdout, "Accepted connection from %s\n",
          inet_ntop2(&ss, (char[INET6_ADDRSTRLEN]){}, INET6_ADDRSTRLEN));

  fd_set_nb(connfd);

  int val = 1;
  setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  auto conn = std::make_unique<Conn>();
  conn->fd = connfd;
  return conn;
}

// Flush outgoing buffer to socket until empty or blocked
void handle_write(Conn *conn, int epfd) {
  while (!conn->outgoing.empty()) {
    ssize_t rv = write(conn->fd, conn->outgoing.data(), conn->outgoing.size());
    if (rv < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return; // Kernel buffer full, wait for next EPOLLOUT
      if (errno == EINTR)
        continue;
      msg_errno("write() error");
      conn->is_closed = true;
      return;
    }
    if (rv > 0)
      conn->outgoing.consume((size_t)rv);
  }

  // Done writing, stop listening for EPOLLOUT to avoid busy-wait
  struct epoll_event event = {};
  event.data.ptr = conn;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &event) == -1) {
    msg_errno("epoll_ctl() MOD error");
    conn->is_closed = true;
  }
}

// Read all available data from socket and process requests
void handle_read(Conn *conn, int epfd) {
  // Drain the socket buffer (required for Edge-Triggered mode)
  while (true) {
    // Always ensure we have at least 64KB free space before reading
    if (!conn->incoming.ensure_capacity(read_buffer_size)) {
      msg("out of memory");
      conn->is_closed = true;
      return;
    }

    uint8_t *ptr = conn->incoming.back();
    // We can now safely read up to read_buffer_size
    ssize_t rv = read(conn->fd, ptr, read_buffer_size);
    if (rv < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break; // Socket drained
      if (errno == EINTR)
        continue;
      msg_errno("read() error");
      conn->is_closed = true;
      return;
    }
    if (rv == 0) {
      msg(conn->incoming.empty() ? "client closed" : "unexpected EOF");
      conn->is_closed = true;
      return;
    }

    conn->incoming.advance((size_t)rv);
  }

  // Process all requests in the incoming buffer (pipelining)
  while (true) {
    int result = try_one_request(conn);
    if (result == 1)
      continue;
    if (result == 0)
      break;
    conn->is_closed = true;
    return;
  }

  // If we have responses to send, switch epoll to listen for write-readiness
  if (!conn->outgoing.empty()) {
    struct epoll_event event = {};
    event.data.ptr = conn;
    event.events = EPOLLOUT | EPOLLET | EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &event) == -1) {
      msg_errno("epoll_ctl() MOD error");
      conn->is_closed = true;
      return;
    }
    handle_write(conn, epfd);
  }
}
