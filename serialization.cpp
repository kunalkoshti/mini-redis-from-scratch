#include "serialization.h"
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

const size_t k_max_msg = 32 << 20;
const size_t k_max_args = 200 * 1000;

// Type tags for serialized values

enum {
  TAG_NIL = 0, // nil
  TAG_ERR = 1, // error code + msg
  TAG_STR = 2, // string
  TAG_INT = 3, // int64
  TAG_DBL = 4, // double
  TAG_ARR = 5, // array
};

// Response serialization

bool out_nil(Buffer &out) { return out.append_u8(TAG_NIL); }

bool out_str(Buffer &out, const char *s, size_t size) {
  if (!out.append_u8(TAG_STR))
    return false;
  if (!out.append_u32(htonl((uint32_t)size)))
    return false;
  return out.append((const uint8_t *)s, size);
}

bool out_int(Buffer &out, int64_t val) {
  if (!out.append_u8(TAG_INT))
    return false;
  uint64_t tmp = htobe64((uint64_t)val);
  return out.append((const uint8_t *)&tmp, 8);
}

bool out_dbl(Buffer &out, double val) {
  if (!out.append_u8(TAG_DBL))
    return false;
  uint64_t tmp;
  memcpy(&tmp, &val, 8);
  tmp = htobe64(tmp);
  return out.append((const uint8_t *)&tmp, 8);
}

bool out_err(Buffer &out, uint32_t code, const char *msg, size_t size) {
  if (!out.append_u8(TAG_ERR))
    return false;
  if (!out.append_u32(htonl(code)))
    return false;
  if (!out.append_u32(htonl((uint32_t)size)))
    return false;
  return out.append((const uint8_t *)msg, size);
}

bool out_arr(Buffer &out, size_t n) {
  if (!out.append_u8(TAG_ARR))
    return false;
  return out.append_u32(htonl((uint32_t)n));
}

bool out_begin_arr(Buffer &out, size_t &ctx) {
  if (!out.append_u8(TAG_ARR) || !out.append_u32(htonl(0)))
    return false;
  ctx = out.size() - 4;
  return true;
}

void out_end_arr(Buffer &out, size_t &ctx, uint32_t n) {
  uint32_t nlen = htonl(n);
  memcpy(out.data() + ctx, &nlen, 4);
}

// Request parsing helpers

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
int32_t parse_req(const uint8_t *data, size_t size,
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

// Response framing

bool response_begin(Buffer &out, size_t *header) {
  *header = out.size();     // message header position
  return out.append_u32(0); // reserve space
}

static size_t response_size(Buffer &out, size_t header) {
  return out.size() - header - 4;
}

bool response_end(Buffer &out, size_t header) {
  size_t msg_size = response_size(out, header);
  if (msg_size > k_max_msg) {
    if (!out.resize(header + 4)) {
      return false;
    }
    if (!out_err(out, ERR_TOO_BIG, "response is too big.",
                 strlen("response is too big."))) {
      return false;
    }
    msg_size = response_size(out, header);
  }
  // message header
  uint32_t len = (uint32_t)msg_size;
  uint32_t nlen = htonl(len);
  memcpy(out.data() + header, &nlen, 4);
  return true;
}
