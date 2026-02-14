#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include "utils.h"
#include <assert.h>

#define PORT "1234"

using namespace std;

const size_t k_max_msg_size = 32 << 20;

const size_t read_buffer_size = 64 * 1024;

struct Conn
{
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
    bool want_close = false;
    vector<uint8_t> incoming;
    vector<uint8_t> outgoing;
};

static void fd_set_nb(int fd)
{
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno)
    {
        die("fcntl error");
        return;
    }

    flags |= O_NONBLOCK;

    errno = 0;
    (void)fcntl(fd, F_SETFL, flags);
    if (errno)
    {
        die("fcntl error");
    }
}

static Conn *handle_accept(int listen_fd)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    int connfd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (connfd < 0)
    {
        msg_errno("accept() error");
        return NULL;
    }
    fprintf(stdout, "Accepted connection from %s\n",
            inet_ntop2(&ss, (char[INET6_ADDRSTRLEN]){}, INET6_ADDRSTRLEN));
    fd_set_nb(connfd);
    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

static void buff_append(vector<uint8_t> &buff, const uint8_t *data, size_t len)
{
    buff.insert(buff.end(), data, data + len);
}

static void buff_consume(vector<uint8_t> &buff, size_t len)
{
    buff.erase(buff.begin(), buff.begin() + len);
}

static bool try_one_request(Conn *conn)
{
    if (conn->incoming.size() < 4)
    {
        return false;
    }
    uint32_t msg_len = 0;
    memcpy(&msg_len, conn->incoming.data(), 4);
    msg_len = ntohl(msg_len);
    if (msg_len > k_max_msg_size)
    {
        conn->want_close = true;
        return false;
    }
    if (4 + msg_len > conn->incoming.size())
    {
        return false;
    }
    const uint8_t *msg = &conn->incoming[4];
    printf("client says: len:%d data:%.*s\n",
           msg_len, msg_len < 100 ? msg_len : 100, msg);
    uint32_t net_len = htonl(msg_len);
    buff_append(conn->outgoing, (const uint8_t *)&net_len, 4);
    buff_append(conn->outgoing, msg, msg_len);
    buff_consume(conn->incoming, 4 + msg_len);
    return true;
}

void handle_write(Conn *conn)
{
    assert(!conn->outgoing.empty());
    ssize_t rv = write(conn->fd, &conn->outgoing[0], conn->outgoing.size());
    if (rv < 0 && errno == EAGAIN)
    {
        return; // actually not ready
    }
    if (rv < 0)
    {
        msg_errno("write() error");
        conn->want_close = true; // error handling
        return;
    }
    buff_consume(conn->outgoing, (size_t)rv);
    if (conn->outgoing.empty())
    {
        conn->want_write = false;
        conn->want_read = true;
    }
}

static void handle_read(Conn *conn)
{
    uint8_t buff[read_buffer_size];
    ssize_t rv = read(conn->fd, buff, read_buffer_size);
    if (rv < 0 && errno == EAGAIN)
    {
        return;
    }
    if (rv < 0)
    {
        msg_errno("read() error");
        conn->want_close = true;
        return;
    }
    if (rv == 0)
    {
        if (conn->incoming.size() == 0)
        {
            msg("client closed");
        }
        else
        {
            msg("unexpected EOF");
        }
        conn->want_close = true;
        return;
    }
    buff_append(conn->incoming, buff, (size_t)rv);
    while (try_one_request(conn))
    {
    }
    if (!conn->outgoing.empty())
    {
        conn->want_write = true;
        conn->want_read = false;
        return handle_write(conn);
    }
}

int main()
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int s = getaddrinfo(NULL, PORT, &hints, &res);
    if (s != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        abort();
    }
    int listen_fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd == -1)
        {
            die("socket() error");
        }
        int yes = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            die("setsockopt() error");
        }
        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
            msg("bind() error");
            close(listen_fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (listen_fd == -1)
    {
        die("Failed to bind");
    }

    fd_set_nb(listen_fd);

    if (listen(listen_fd, 10) == -1)
    {
        die("listen() error");
    }
    fprintf(stdout, "Server is listening on port %s\n", PORT);
    fprintf(stdout, "Waiting for connections...\n");

    vector<Conn *> fd2conn;
    vector<struct pollfd> poll_args;

    while (true)
    {
        poll_args.clear();
        struct pollfd pfd = {listen_fd, POLLIN, 0};
        poll_args.push_back(pfd);
        for (Conn *conn : fd2conn)
        {
            if (!conn)
                continue;
            struct pollfd pfd = {conn->fd, POLLERR, 0};
            if (conn->want_read)
                pfd.events |= POLLIN;
            if (conn->want_write)
                pfd.events |= POLLOUT;
            poll_args.push_back(pfd);
        }
        int rv = poll(poll_args.data(), poll_args.size(), -1);
        if (rv < 0 && errno == EINTR)
        {
            continue;
        }
        if (rv < 0)
        {
            die("poll() error");
        }
        if (poll_args[0].revents)
        {
            if (Conn *conn = handle_accept(listen_fd))
            {
                if ((size_t)conn->fd >= fd2conn.size())
                {
                    fd2conn.resize(conn->fd + 1);
                }
                assert(!fd2conn[conn->fd]);
                fd2conn[conn->fd] = conn;
            }
        }
        for (size_t i = 1; i < poll_args.size(); i++)
        {
            uint32_t ready = poll_args[i].revents;
            Conn *conn = fd2conn[poll_args[i].fd];
            if (ready & POLLIN)
            {
                assert(conn->want_read);
                handle_read(conn);
            }
            if (ready & POLLOUT)
            {
                assert(conn->want_write);
                handle_write(conn);
            }
            if ((ready & POLLERR) || conn->want_close)
            {
                (void)close(conn->fd);
                fd2conn[conn->fd] = NULL;
                delete conn;
            }
        }
    }
    return 0;
}