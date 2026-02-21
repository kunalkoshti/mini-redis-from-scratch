#include "utils.h"
#include <errno.h>
#include <iostream>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>

#define PORT "1234"
const size_t k_max_msg = 32 << 20;

using namespace std;

/**
 * Encodes a command into the binary protocol format.
 */
static void encode_cmd(vector<uint8_t> &out, const vector<string> &cmd) {
  uint32_t nstr = htonl(cmd.size());
  out.insert(out.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);

  for (const string &s : cmd) {
    uint32_t len = htonl(s.size());
    out.insert(out.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    out.insert(out.end(), s.data(), s.data() + s.size());
  }
}

static int32_t query(int fd, const vector<string> &cmd) {
  vector<uint8_t> req;
  encode_cmd(req, cmd);

  if (req.size() > k_max_msg) {
    msg("message too big");
    return -1;
  }

  uint32_t netlen = htonl(req.size());
  if (write_full(fd, (char *)&netlen, 4) != 0) {
    msg("send() header error");
    return -1;
  }
  if (write_full(fd, (char *)req.data(), req.size()) != 0) {
    msg("send() body error");
    return -1;
  }

  uint32_t rlen_net = 0;
  if (read_full(fd, (char *)&rlen_net, 4) != 0) {
    msg(errno == 0 ? "unexpected EOF error" : "recv() header error");
    return -1;
  }
  uint32_t rlen = ntohl(rlen_net);
  if (rlen > k_max_msg) {
    msg("response too big");
    return -1;
  }

  vector<uint8_t> rbuf(rlen);
  if (read_full(fd, (char *)rbuf.data(), rlen) != 0) {
    msg(errno == 0 ? "unexpected EOF error" : "recv() body error");
    return -1;
  }

  uint32_t rescode = 0;
  if (rlen >= 4) {
    memcpy(&rescode, rbuf.data(), 4);
    rescode = ntohl(rescode);
  }

  printf("server says: [status:%u] %.*s\n", rescode, rlen > 4 ? rlen - 4 : 0,
         rlen > 4 ? (char *)&rbuf[4] : "");
  return 0;
}

int main() {
  struct addrinfo hints{}, *res{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int s = getaddrinfo("localhost", PORT, &hints, &res);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    abort();
  }
  int sock_fd = -1;
  for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock_fd == -1)
      continue;
    if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      msg("connect() error");
      close(sock_fd);
      sock_fd = -1;
      continue;
    }
    break;
  }
  freeaddrinfo(res);
  if (sock_fd == -1) {
    die("Failed to connect");
  }

  vector<vector<string>> query_list = {{"set", "mykey", "hello world!"},
                                       {"get", "mykey"},
                                       {"del", "mykey"},
                                       {"get", "mykey"},
                                       {"unknown", "cmd"}};

  for (const auto &q : query_list) {
    if (query(sock_fd, q) == -1) {
      break;
    }
  }
  close(sock_fd);
  return 0;
}