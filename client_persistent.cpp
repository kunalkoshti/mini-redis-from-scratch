#include "utils.h"
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>

#define PORT "1234"
const size_t k_max_msg = 32 << 20;

using namespace std;

enum {
  TAG_NIL = 0, // nil
  TAG_ERR = 1, // error code + msg
  TAG_STR = 2, // string
  TAG_INT = 3, // int64
  TAG_DBL = 4, // double
  TAG_ARR = 5, // array
};

static void encode_cmd(vector<uint8_t> &out, const vector<string> &cmd) {
  uint32_t nstr = htonl((uint32_t)cmd.size());
  out.insert(out.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);

  for (const string &s : cmd) {
    uint32_t len = htonl((uint32_t)s.size());
    out.insert(out.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    out.insert(out.end(), s.data(), s.data() + s.size());
  }
}

static int32_t print_response(const uint8_t *data, size_t size) {
  if (size < 1) {
    msg("bad response");
    return -1;
  }
  switch (data[0]) {
  case TAG_NIL:
    printf("(nil)\n");
    return 1;
  case TAG_ERR:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      uint32_t code = 0;
      uint32_t len = 0;
      memcpy(&code, &data[1], 4);
      memcpy(&len, &data[1 + 4], 4);
      code = ntohl(code);
      len = ntohl(len);
      if (size < 1 + 8 + len) {
        msg("bad response");
        return -1;
      }
      printf("(err) %u %.*s\n", code, len, &data[1 + 8]);
      return 1 + 8 + (int32_t)len;
    }
  case TAG_STR:
    if (size < 1 + 4) {
      msg("bad response");
      return -1;
    }
    {
      uint32_t len = 0;
      memcpy(&len, &data[1], 4);
      len = ntohl(len);
      if (size < 1 + 4 + len) {
        msg("bad response");
        return -1;
      }
      printf("(str) %.*s\n", len, &data[1 + 4]);
      return 1 + 4 + (int32_t)len;
    }
  case TAG_INT:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      int64_t val = 0;
      memcpy(&val, &data[1], 8);
      val = (int64_t)be64toh((uint64_t)val);
      printf("(int) %ld\n", val);
      return 1 + 8;
    }
  case TAG_DBL:
    if (size < 1 + 8) {
      msg("bad response");
      return -1;
    }
    {
      uint64_t tmp = 0;
      memcpy(&tmp, &data[1], 8);
      tmp = be64toh(tmp);
      double val = 0;
      memcpy(&val, &tmp, 8);
      printf("(dbl) %g\n", val);
      return 1 + 8;
    }
  case TAG_ARR:
    if (size < 1 + 4) {
      msg("bad response");
      return -1;
    }
    {
      uint32_t len = 0;
      memcpy(&len, &data[1], 4);
      len = ntohl(len);
      printf("(arr) len=%u\n", len);
      size_t arr_bytes = 1 + 4;
      for (uint32_t i = 0; i < len; ++i) {
        int32_t rv = print_response(&data[arr_bytes], size - arr_bytes);
        if (rv < 0) {
          return rv;
        }
        arr_bytes += (size_t)rv;
      }
      printf("(arr) end\n");
      return (int32_t)arr_bytes;
    }
  default:
    msg("bad response");
    return -1;
  }
}

static int32_t send_req(int fd, const vector<string> &cmd) {
  vector<uint8_t> req;
  encode_cmd(req, cmd);

  if (req.size() > k_max_msg) {
    msg("message too big");
    return -1;
  }

  uint32_t netlen = htonl((uint32_t)req.size());
  if (write_full(fd, (char *)&netlen, 4) != 0) {
    msg("send() header error");
    return -1;
  }
  if (write_full(fd, (char *)req.data(), req.size()) != 0) {
    msg("send() body error");
    return -1;
  }
  return 0;
}

static int32_t read_res(int fd) {
  uint32_t rlen_net = 0;
  errno = 0;
  if (read_full(fd, (char *)&rlen_net, 4) != 0) {
    msg(errno == 0 ? "EOF" : "read() error");
    return -1;
  }
  uint32_t rlen = ntohl(rlen_net);
  if (rlen > k_max_msg) {
    msg("response too big");
    return -1;
  }

  vector<uint8_t> rbuf(rlen);
  if (read_full(fd, (char *)rbuf.data(), rlen) != 0) {
    msg("read() error");
    return -1;
  }

  int32_t rv = print_response(rbuf.data(), rlen);
  if (rv > 0 && (uint32_t)rv != rlen) {
    msg("bad response");
    return -1;
  }
  return rv;
}

static int connect_server() {
  struct addrinfo hints{}, *res{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int s = getaddrinfo("localhost", PORT, &hints, &res);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }
  int sock_fd = -1;
  for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
    sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock_fd == -1)
      continue;
    if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock_fd);
      sock_fd = -1;
      continue;
    }
    break;
  }
  freeaddrinfo(res);
  return sock_fd;
}

static vector<string> split_ws(const string &line) {
  vector<string> out;
  string cur;
  for (char c : line) {
    if (c == ' ' || c == '\t') {
      if (!cur.empty()) {
        out.push_back(cur);
        cur.clear();
      }
      continue;
    }
    cur.push_back(c);
  }
  if (!cur.empty()) {
    out.push_back(cur);
  }
  return out;
}

int main() {
  int sock_fd = connect_server();
  if (sock_fd == -1) {
    die("Failed to connect");
  }

  fprintf(stdout,
          "Connected to localhost:%s. Enter commands, 'quit' to exit.\n",
          PORT);

  string line;
  while (true) {
    fprintf(stdout, "mini-redis> ");
    fflush(stdout);
    if (!std::getline(std::cin, line)) {
      break;
    }
    auto cmd = split_ws(line);
    if (cmd.empty()) {
      continue;
    }
    if (cmd[0] == "quit" || cmd[0] == "exit") {
      break;
    }
    if (send_req(sock_fd, cmd) != 0) {
      msg("request failed; server likely closed connection");
      break;
    }
    if (read_res(sock_fd) < 0) {
      msg("response failed; server likely closed connection");
      break;
    }
  }

  close(sock_fd);
  return 0;
}
