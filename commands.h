#pragma once

/**
 * @file commands.h
 * @brief Command handler dispatch for the key-value store.
 *
 * Routes parsed commands (GET, SET, SETINT, SETDBL, DEL, KEYS, INCR,
 * INCRBY, TYPE) to their implementations and writes serialized responses
 * into the output buffer.
 */

#include "buffer.h"
#include <string>
#include <vector>

/**
 * Dispatch a parsed command and write the response.
 *
 * @param cmd  The parsed command arguments (e.g. ["set", "key", "val"]).
 * @param out  Buffer to append the serialized response to.
 * @return true on success, false on write failure.
 */
bool do_request(std::vector<std::string> &cmd, Buffer &out);
