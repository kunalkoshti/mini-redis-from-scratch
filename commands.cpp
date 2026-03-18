/**
 * @file commands.cpp
 * @brief Command dispatcher and global state for the key-value store.
 *
 * Defines the global hashmap (g_data) and the do_request() dispatcher
 * that routes parsed commands to their handler implementations in
 * commands_kv.cpp and commands_zset.cpp.
 *
 * Supported commands:
 *   get <key>            → returns the value (string/int/double) or nil
 *   set <key> <val>      → stores a string value
 *   setint <key> <val>   → parses and stores an int64 value
 *   setdbl <key> <val>   → parses and stores a double value
 *   del <key>            → deletes a key, returns 1 or 0
 *   keys                 → returns all keys as an array
 *   incr <key>           → increments an int64 value by 1 (auto-creates)
 *   incrby <key> <inc>   → increments an int64 value by <inc> (auto-creates)
 *   type <key>           → returns the type name ("string"/"int"/"double")
 *   zadd <key> <score> <name> → adds/updates a member in a sorted set
 *   zrem <key> <name>          → removes a member from a sorted set
 *   zscore <key> <name>        → returns the score of a member
 *   zquery <key> <score> <name> <offset> <limit> [asc|desc]
 *                              → range query on a sorted set
 *   zrank <key> <name>         → returns the 0-based rank of a member
 *   zcount <key> <min> <max>   → counts members with score in [min, max)
 */

#include "commands_internal.h"
// Global data
GlobalData g_data;

// Equality comparison for `struct Entry` nodes in the hashmap
bool entry_eq(HNode *lhs, HNode *rhs) {
  struct Entry *le = container_of(lhs, struct Entry, node);
  struct Entry *re = container_of(rhs, struct Entry, node);
  return le->key == re->key;
}

/**
 * Dispatch a parsed command and write the response.
 */
bool do_request(std::vector<std::string> &cmd, Buffer &out) {
  if (cmd.size() == 2 && cmd[0] == "get") {
    return do_get(cmd[1], out);
  } else if (cmd.size() == 3 && cmd[0] == "set") {
    return do_set_str(cmd[1], cmd[2], out);
  } else if (cmd.size() == 3 && cmd[0] == "setint") {
    return do_set_int(cmd[1], cmd[2], out);
  } else if (cmd.size() == 3 && cmd[0] == "setdbl") {
    return do_set_dbl(cmd[1], cmd[2], out);
  } else if (cmd.size() == 2 && cmd[0] == "del") {
    return do_del(cmd[1], out);
  } else if (cmd.size() == 1 && cmd[0] == "keys") {
    return do_keys(cmd, out);
  } else if (cmd.size() == 2 && cmd[0] == "incr") {
    return do_incr(cmd[1], out);
  } else if (cmd.size() == 3 && cmd[0] == "incrby") {
    return do_incrby(cmd[1], cmd[2], out);
  } else if (cmd.size() == 2 && cmd[0] == "type") {
    return do_type(cmd[1], out);
  } else if (cmd.size() == 4 && cmd[0] == "zadd") {
    return do_zadd(cmd[1], cmd[3], cmd[2], out);
  } else if (cmd.size() == 3 && cmd[0] == "zrem") {
    return do_zrem(cmd[1], cmd[2], out);
  } else if (cmd.size() == 3 && cmd[0] == "zscore") {
    return do_zscore(cmd[1], cmd[2], out);
  } else if ((cmd.size() == 6 || cmd.size() == 7) && cmd[0] == "zquery") {
    return do_zquery(cmd, out);
  } else if (cmd.size() == 3 && cmd[0] == "zrank") {
    return do_zrank(cmd[1], cmd[2], out);
  } else if (cmd.size() == 4 && cmd[0] == "zcount") {
    return do_zcount(cmd, out);
  } else {
    return out_err(out, ERR_UNKNOWN, "unknown command.",
                   strlen("unknown command."));
  }
}
