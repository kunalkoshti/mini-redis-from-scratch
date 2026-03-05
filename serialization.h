#pragma once

/**
 * @file serialization.h
 * @brief Wire-format encoding/decoding for the binary protocol.
 *
 * Handles serializing typed response values (nil, string, int, double, error,
 * array) and parsing incoming requests. Also provides response framing helpers
 * to prepend the 4-byte length header.
 */

#include "buffer.h"
#include <stdint.h>
#include <string>
#include <vector>

extern const size_t k_max_msg;
extern const size_t k_max_args;

// Error codes sent with TAG_ERR responses
enum {
  ERR_UNKNOWN = 1,       // unknown command or wrong arg count
  ERR_TOO_BIG = 2,       // response exceeds k_max_msg
  ERR_TYPE_MISMATCH = 3, // e.g. INCR on a string key, or invalid parse
  ERR_OVERFLOW = 4,      // integer overflow on INCR/INCRBY
};

// --- Response serialization (host → network byte order) ---

bool out_nil(Buffer &out);
bool out_str(Buffer &out, const char *s, size_t size);
bool out_int(Buffer &out, int64_t val);
bool out_dbl(Buffer &out, double val);
bool out_err(Buffer &out, uint32_t code, const char *msg, size_t size);
bool out_arr(Buffer &out, size_t n);

// --- Request parsing (network → host byte order) ---

/**
 * Parse a request body into a list of string arguments.
 * Format: [n_args (4B)] [[len (4B)] [arg (len B)]]...
 *
 * @return 0 on success, -1 on parse error.
 */
int32_t parse_req(const uint8_t *data, size_t size,
                  std::vector<std::string> &out);

// --- Response framing ---

/**
 * Reserve 4 bytes in the buffer for the response length header.
 * Records the header position in *header.
 */
bool response_begin(Buffer &out, size_t *header);

/**
 * Finalize the response: compute body size, write it (in network byte order)
 * into the reserved header slot. If the body exceeds k_max_msg, replaces it
 * with an ERR_TOO_BIG error.
 */
bool response_end(Buffer &out, size_t header);
