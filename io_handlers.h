#ifndef IO_HANDLERS_H
#define IO_HANDLERS_H

#include "conn.h"
#include <memory>

void fd_set_nb(int fd);
std::unique_ptr<Conn> handle_accept(int listen_fd);
void handle_read(Conn *conn, int epfd);
void handle_write(Conn *conn, int epfd);

#endif
