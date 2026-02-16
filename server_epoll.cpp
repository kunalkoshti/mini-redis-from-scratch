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
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <memory>

#define PORT "1234"
#define MAX_EVENTS 64

using namespace std;

const size_t k_max_msg_size = 32 << 20; // 32MB limit
const size_t read_buffer_size = 64 * 1024;

struct Conn
{
    int fd = -1;
    vector<uint8_t> incoming; // Buffer for data received from client
    vector<uint8_t> outgoing; // Buffer for data to be sent to client
};

// Map FDs to Connection objects; unique_ptr handles automatic memory cleanup
vector<unique_ptr<Conn>> fd2conn;

// Set socket to non-blocking mode for use with epoll edge-trigger
static void fd_set_nb(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        die("fcntl F_GETFL error");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        die("fcntl F_SETFL error");
}

// Clean up epoll registration and free connection memory
void connection_destroy(int fd, int epfd)
{
    if (fd < 0 || (size_t)fd >= fd2conn.size() || !fd2conn[fd])
        return;

    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    fd2conn[fd].reset(); // Destroys the unique_ptr and the Conn object
}

// Accept new client and initialize connection state
static unique_ptr<Conn> handle_accept(int listen_fd)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    int connfd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (connfd < 0)
    {
        // EAGAIN means no more pending connections in the queue
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            msg_errno("accept() error");
        return nullptr;
    }

    fprintf(stdout, "Accepted connection from %s\n",
            inet_ntop2(&ss, (char[INET6_ADDRSTRLEN]){}, INET6_ADDRSTRLEN));

    fd_set_nb(connfd);
    auto conn = make_unique<Conn>();
    conn->fd = connfd;
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

// Parse protocol: 4-byte header for length followed by body
static int try_one_request(Conn *conn)
{
    if (conn->incoming.size() < 4)
        return 0; // Need more data for header

    uint32_t msg_len = 0;
    memcpy(&msg_len, conn->incoming.data(), 4);
    msg_len = ntohl(msg_len);

    if (msg_len > k_max_msg_size)
        return -1; // Protect against OOM/malicious size
    if (4 + msg_len > conn->incoming.size())
        return 0; // Body not fully received yet

    const uint8_t *msg = &conn->incoming[4];
    printf("client says: len:%d data:%.*s\n",
           msg_len, msg_len < 100 ? msg_len : 100, msg);

    // Echo back protocol: length + body
    uint32_t net_len = htonl(msg_len);
    buff_append(conn->outgoing, (const uint8_t *)&net_len, 4);
    buff_append(conn->outgoing, msg, msg_len);
    buff_consume(conn->incoming, 4 + msg_len);
    return 1;
}

// Flush outgoing buffer to socket until empty or blocked
void handle_write(Conn *conn, int epfd)
{
    while (!conn->outgoing.empty())
    {
        ssize_t rv = write(conn->fd, conn->outgoing.data(), conn->outgoing.size());
        if (rv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return; // Kernel buffer full, wait for next EPOLLOUT
            if (errno == EINTR)
                continue;
            msg_errno("write() error");
            connection_destroy(conn->fd, epfd);
            return;
        }
        if (rv > 0)
            buff_consume(conn->outgoing, (size_t)rv);
    }

    // Done writing, stop listening for EPOLLOUT to avoid busy-wait
    struct epoll_event event = {};
    event.data.ptr = conn;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &event) == -1)
    {
        msg_errno("epoll_ctl() MOD error");
        connection_destroy(conn->fd, epfd);
    }
}

// Read all available data from socket and process requests
static void handle_read(Conn *conn, int epfd)
{
    // Drain the socket buffer (required for Edge-Triggered mode)
    while (true)
    {
        uint8_t buff[read_buffer_size];
        ssize_t rv = read(conn->fd, buff, read_buffer_size);
        if (rv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break; // Socket drained
            if (errno == EINTR)
                continue;
            msg_errno("read() error");
            connection_destroy(conn->fd, epfd);
            return;
        }
        if (rv == 0)
        {
            msg(conn->incoming.empty() ? "client closed" : "unexpected EOF");
            connection_destroy(conn->fd, epfd);
            return;
        }
        buff_append(conn->incoming, buff, (size_t)rv);
    }

    // Process all requests in the incoming buffer (pipelining)
    while (true)
    {
        int result = try_one_request(conn);
        if (result == 1)
            continue;
        if (result == 0)
            break;
        connection_destroy(conn->fd, epfd);
        return;
    }

    // If we have responses to send, switch epoll to listen for write-readiness
    if (!conn->outgoing.empty())
    {
        struct epoll_event event = {};
        event.data.ptr = conn;
        event.events = EPOLLOUT | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &event) == -1)
        {
            msg_errno("epoll_ctl() MOD error");
            connection_destroy(conn->fd, epfd);
            return;
        }
        handle_write(conn, epfd);
    }
}

int main()
{
    // Setup listening socket
    struct addrinfo hints = {}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, PORT, &hints, &res) != 0)
        die("getaddrinfo");

    int listen_fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    {
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
    if (listen(listen_fd, SOMAXCONN) == -1)
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
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

    struct epoll_event events[MAX_EVENTS];
    while (true)
    {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n == -1)
        {
            if (errno == EINTR)
                continue;
            die("epoll_wait");
        }

        for (int i = 0; i < n; i++)
        {
            Conn *conn = (Conn *)events[i].data.ptr;
            if (conn->fd == listen_fd)
            {
                // Accept all pending connections in loop (ET mode)
                while (true)
                {
                    auto client_conn = handle_accept(listen_fd);
                    if (!client_conn)
                        break;

                    int fd = client_conn->fd;
                    if ((size_t)fd >= fd2conn.size())
                        fd2conn.resize(fd + 1);

                    struct epoll_event cev = {};
                    cev.data.ptr = client_conn.get(); // Epoll stores raw pointer
                    cev.events = EPOLLIN | EPOLLET;

                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &cev) == -1)
                    {
                        msg_errno("epoll_ctl add");
                        close(fd);
                    }
                    else
                    {
                        // Transfer ownership to global table
                        fd2conn[fd] = std::move(client_conn);
                    }
                }
            }
            else
            {
                // Guard: check if connection was closed by a previous event in this batch
                if (!conn || (size_t)conn->fd >= fd2conn.size() || !fd2conn[conn->fd])
                    continue;

                if (events[i].events & EPOLLIN)
                    handle_read(conn, epfd);

                // Second guard: handle_read might have triggered connection_destroy
                if (!fd2conn[conn->fd])
                    continue;

                if (events[i].events & EPOLLOUT)
                    handle_write(conn, epfd);

                if (events[i].events & (EPOLLERR | EPOLLHUP))
                    connection_destroy(conn->fd, epfd);
            }
        }
    }
    return 0;
}