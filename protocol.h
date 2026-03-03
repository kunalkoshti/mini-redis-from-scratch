#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
 * @file protocol.h
 * @brief Header for the custom binary KV protocol processing.
 */

#include "conn.h"
#include "hashtable.h"
#include <stdint.h>
#include <string>
#include <vector>

// KV pair for the top-level hashtable
struct Entry {
  struct HNode node; // hashtable node
  std::string key;
  std::string val;
};

/**
 * Attempts to parse and process one request from the connection buffer.
 *
 * @param conn Client connection structure.
 * @return 1 on success, 0 if data is incomplete, -1 on protocol error.
 */
int try_one_request(Conn *conn);

#endif
