/**
 * @file commands_internal.h
 * @brief Shared declarations for command handler implementations.
 *
 * Provides access to the global key-value store, the Entry equality
 * comparator, and all do_* command handler function declarations.
 * Included by commands.cpp, commands_kv.cpp, and commands_zset.cpp.
 */

#pragma once

#include "buffer.h"
#include "hashtable.h"
#include "protocol.h"
#include "serialization.h"
#include "utils.h"
#include "zset.h"
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <variant>
#include <vector>

// The global key-value store (defined in commands.cpp)
struct GlobalData {
  HMap db;
};
extern GlobalData g_data;

// Equality comparison for Entry nodes in the hashmap (defined in commands.cpp)
bool entry_eq(HNode *lhs, HNode *rhs);

// KV command handlers (defined in commands_kv.cpp)

bool do_get(std::string &str, Buffer &out);
bool do_set_str(std::string &key, std::string &val, Buffer &out);
bool do_set_int(std::string &key, std::string &val_str, Buffer &out);
bool do_set_dbl(std::string &key, std::string &val_str, Buffer &out);
bool do_del(std::string &key, Buffer &out);
bool do_incr(std::string &key, Buffer &out);
bool do_incrby(std::string &key, std::string &inc_str, Buffer &out);
bool do_type(std::string &key, Buffer &out);
bool do_keys(std::vector<std::string> &cmd, Buffer &out);

// ZSet command handlers (defined in commands_zset.cpp)

bool do_zadd(std::string &key, std::string &name, std::string str_score,
             Buffer &out);
bool do_zrem(std::string &key, std::string &name, Buffer &out);
bool do_zscore(std::string &key, std::string &name, Buffer &out);
bool do_zquery(std::vector<std::string> &cmd, Buffer &out);
bool do_zrank(std::string &key, std::string &name, Buffer &out);
bool do_zcount(std::vector<std::string> &cmd, Buffer &out);
