/**
 * @file tests_helpers.h
 * @brief Shared helpers for integration tests.
 *
 * Provides encode_cmd(), send_request(), and read_response() used by
 * all integration test files. Include this header in each test file.
 */

#pragma once

#include "../utils.h"
#include <algorithm>
#include <assert.h>
#include <cstring>
#include <endian.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

const size_t k_max_msg = 32 << 20;

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
static void encode_cmd(std::vector<uint8_t> &out,
                       const std::vector<std::string> &cmd) {
  uint32_t nstr = htonl(cmd.size());
  out.insert(out.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);

  for (const std::string &s : cmd) {
    uint32_t len = htonl(s.size());
    out.insert(out.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    out.insert(out.end(), s.data(), s.data() + s.size());
  }
}

/**
 * Sends a command request to the server.
 */
static void send_request(int fd, const std::vector<std::string> &cmd) {
  std::vector<uint8_t> req;
  encode_cmd(req, cmd);

  uint32_t len = htonl(req.size());
  if (write_full(fd, (char *)&len, 4) != 0)
    die("write_full header");
  if (write_full(fd, (char *)req.data(), req.size()) != 0)
    die("write_full body");
}

/**
 * Structured response from the server.
 * Supports nested arrays for commands like ZQUERY.
 */
struct Response {
  uint8_t tag = 0;
  std::string value;
  uint32_t err_code = 0;
  uint32_t arr_len = 0;
  std::vector<Response> arr_items;
};

/**
 * Recursively parse a serialized response from raw bytes.
 * Sets 'consumed' to the number of bytes read.
 */
static Response parse_response(const uint8_t *data, size_t size,
                               size_t &consumed) {
  Response r = {};
  if (size < 1) {
    consumed = 0;
    return r;
  }
  r.tag = data[0];

  switch (r.tag) {
  case TAG_NIL:
    consumed = 1;
    break;
  case TAG_ERR: {
    uint32_t code = 0, mlen = 0;
    memcpy(&code, &data[1], 4);
    memcpy(&mlen, &data[1 + 4], 4);
    code = ntohl(code);
    mlen = ntohl(mlen);
    r.err_code = code;
    r.value = std::string((char *)&data[1 + 8], mlen);
    consumed = 1 + 8 + mlen;
    break;
  }
  case TAG_STR: {
    uint32_t slen = 0;
    memcpy(&slen, &data[1], 4);
    slen = ntohl(slen);
    r.value = std::string((char *)&data[1 + 4], slen);
    consumed = 1 + 4 + slen;
    break;
  }
  case TAG_INT: {
    int64_t val = 0;
    memcpy(&val, &data[1], 8);
    val = (int64_t)be64toh((uint64_t)val);
    r.value = std::to_string(val);
    consumed = 1 + 8;
    break;
  }
  case TAG_DBL: {
    uint64_t tmp = 0;
    memcpy(&tmp, &data[1], 8);
    tmp = be64toh(tmp);
    double val = 0;
    memcpy(&val, &tmp, 8);
    // Use %g format to match client output
    char buf[64];
    snprintf(buf, sizeof(buf), "%g", val);
    r.value = buf;
    consumed = 1 + 8;
    break;
  }
  case TAG_ARR: {
    uint32_t alen = 0;
    memcpy(&alen, &data[1], 4);
    alen = ntohl(alen);
    r.arr_len = alen;
    size_t offset = 1 + 4;
    for (uint32_t i = 0; i < alen; ++i) {
      size_t sub_consumed = 0;
      Response sub = parse_response(&data[offset], size - offset, sub_consumed);
      r.arr_items.push_back(sub);
      offset += sub_consumed;
    }
    consumed = offset;
    break;
  }
  default:
    consumed = 1;
    break;
  }
  return r;
}

/**
 * Read a full structured Response from the server.
 * Use this when you need to inspect array contents or error codes.
 */
static Response read_response_full(int fd) {
  uint32_t len_net = 0;
  if (read_full(fd, (char *)&len_net, 4) != 0)
    die("read_full header");
  uint32_t len = ntohl(len_net);
  if (len > k_max_msg)
    die("response too big");

  std::vector<uint8_t> buf(len);
  if (read_full(fd, (char *)buf.data(), len) != 0)
    die("read_full body");

  size_t consumed = 0;
  return parse_response(buf.data(), len, consumed);
}

/**
 * Read a response and return just the string payload.
 * Convenience wrapper around read_response_full().
 *   TAG_NIL → ""
 *   TAG_STR → the string value
 *   TAG_INT → decimal string of the int64 value
 *   TAG_ERR → the error message
 *   TAG_DBL → decimal string of the double
 *   TAG_ARR → ""  (use read_response_full to inspect array contents)
 */
static std::string read_response(int fd) {
  Response r = read_response_full(fd);
  switch (r.tag) {
  case TAG_NIL:
    return "";
  case TAG_ERR:
    return r.value;
  case TAG_STR:
    return r.value;
  case TAG_INT:
    return r.value;
  case TAG_DBL:
    return r.value;
  case TAG_ARR:
    return "";
  default:
    return "";
  }
}

/**
 * Connect to the server at localhost:1234.
 */
static int connect_to_server() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    die("socket");
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    die("connect");
  return fd;
}
