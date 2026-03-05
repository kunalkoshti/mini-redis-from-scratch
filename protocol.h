#pragma once

/**
 * @file protocol.h
 * @brief Header for the custom binary KV protocol processing.
 */

#include "conn.h"
#include "hashtable.h"
#include <stdint.h>
#include <string>
#include <variant>
#include <vector>

// KV pair stored in the hashtable. val holds one of:
//   std::string  — set via SET
//   int64_t      — set via SETINT, INCR, INCRBY
//   double       — set via SETDBL
struct Entry {
  struct HNode node; // intrusive hashtable node
  std::string key;
  std::variant<std::string, int64_t, double> val;
};

/**
 * Attempts to parse and process one request from the connection buffer.
 * Reads the length-prefixed request, parses commands, dispatches to the
 * appropriate handler, and writes the framed response.
 *
 * @param conn Client connection structure.
 * @return 1 on success, 0 if data is incomplete, -1 on protocol error.
 */
int try_one_request(Conn *conn);
