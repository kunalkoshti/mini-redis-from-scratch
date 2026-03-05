#include "utils.h"
#include <endian.h>
#include <errno.h>
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

enum {
  TAG_NIL = 0, // nil
  TAG_ERR = 1, // error code + msg
  TAG_STR = 2, // string
  TAG_INT = 3, // int64
  TAG_DBL = 4, // double
  TAG_ARR = 5, // array
};

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

/**
 * Recursively prints a typed response value.
 * Returns number of bytes consumed, or -1 on error.
 */
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
      return 1 + 8 + len;
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
      return 1 + 4 + len;
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

  uint32_t netlen = htonl(req.size());
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
    rv = -1;
  }
  return rv;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
    fprintf(stderr, "  e.g. %s set mykey hello\n", argv[0]);
    fprintf(stderr, "       %s get mykey\n", argv[0]);
    fprintf(stderr, "       %s del mykey\n", argv[0]);
    fprintf(stderr, "       %s keys\n", argv[0]);
    return 1;
  }

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

  vector<string> cmd;
  for (int i = 1; i < argc; ++i) {
    cmd.push_back(argv[i]);
  }
  int32_t err = send_req(sock_fd, cmd);
  if (err) {
    goto L_DONE;
  }
  err = read_res(sock_fd);
  if (err < 0) {
    goto L_DONE;
  }

L_DONE:
  close(sock_fd);
  return 0;
}