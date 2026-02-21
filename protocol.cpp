#include "protocol.h"
#include "utils.h"
#include <map>
#include <string.h>

const size_t k_max_msg = 32 << 20;
const size_t k_max_args = 200 * 1000;

static bool read_u32(const uint8_t *&cur, const uint8_t *end, uint32_t &out) {
  if (cur + 4 > end) {
    return false;
  }
  memcpy(&out, cur, 4);
  cur += 4;
  return true;
}

static bool read_str(const uint8_t *&cur, const uint8_t *end, size_t n,
                     std::string &out) {
  if (cur + n > end) {
    return false;
  }
  out.assign((const char *)cur, n);
  cur += n;
  return true;
}

/**
 * Request format: [n_args (4 bytes)] [[len (4 bytes)] [arg (len bytes)]]...
 */
static int32_t parse_req(const uint8_t *data, size_t size,
                         std::vector<std::string> &out) {
  const uint8_t *end = data + size;
  uint32_t nstr = 0;
  if (!read_u32(data, end, nstr)) {
    return -1;
  }
  nstr = ntohl(nstr);
  if (nstr > k_max_args) {
    return -1;
  }

  while (out.size() < nstr) {
    uint32_t len = 0;
    if (!read_u32(data, end, len)) {
      return -1;
    }
    len = ntohl(len);
    out.push_back(std::string());
    if (!read_str(data, end, len, out.back())) {
      return -1;
    }
  }
  if (data != end) {
    return -1;
  }
  return 0;
}

/**
 * Status codes for response headers.
 */
enum {
  RES_OK = 0,
  RES_ERR = 1,
  RES_NX = 2,
};

static std::map<std::string, std::string> g_data;

/**
 * Global application logic for processing commands.
 * Implements GET, SET, and DEL.
 */
static bool do_request(std::vector<std::string> &cmd, Buffer &out) {
  uint32_t status = RES_OK;

  // Direct pointer to avoid unnecessary string copies on GET
  const std::string *val = nullptr;

  if (cmd.size() == 2 && cmd[0] == "get") {
    auto it = g_data.find(cmd[1]);
    if (it == g_data.end()) {
      status = RES_NX;
    } else {
      val = &it->second;
    }
  } else if (cmd.size() == 3 && cmd[0] == "set") {
    g_data[cmd[1]].swap(cmd[2]);
  } else if (cmd.size() == 2 && cmd[0] == "del") {
    g_data.erase(cmd[1]);
  } else {
    status = RES_ERR;
  }

  uint32_t val_size = val ? val->size() : 0;
  uint32_t resp_len = 4 + val_size;
  resp_len = htonl(resp_len);

  if (!out.append((const uint8_t *)&resp_len, 4))
    return false;

  uint32_t status_net = htonl(status);
  if (!out.append((const uint8_t *)&status_net, 4))
    return false;

  if (val && val_size > 0) {
    if (!out.append((const uint8_t *)val->data(), val_size))
      return false;
  }
  return true;
}

/**
 * Attempts to parse and process one request from the connection buffer.
 *
 * @param conn Client connection structure.
 * @return 1 on success, 0 if data is incomplete, -1 on protocol error.
 */
int try_one_request(Conn *conn) {
  if (conn->incoming.size() < 4) {
    return 0;
  }
  uint32_t len = 0;
  memcpy(&len, conn->incoming.data(), 4);
  len = ntohl(len);
  if (len > k_max_msg) {
    msg("too long");
    return -1;
  }
  if (4 + len > conn->incoming.size()) {
    return 0;
  }
  const uint8_t *request = conn->incoming.data() + 4;

  std::vector<std::string> cmd;
  if (parse_req(request, len, cmd) < 0) {
    msg("bad request");
    return -1;
  }

  // Process request and write response to outgoing buffer
  if (!do_request(cmd, conn->outgoing)) {
    msg("failed to process request");
    return -1;
  }

  conn->incoming.consume(4 + len);
  return 1;
}
