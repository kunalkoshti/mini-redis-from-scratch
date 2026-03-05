/**
 * @file commands.cpp
 * @brief Command handler implementations for the key-value store.
 *
 * Each do_* function performs a hashtable lookup (or insert/delete),
 * then writes a typed response into the output buffer.
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
 */

#include "commands.h"
#include "hashtable.h"
#include "protocol.h"
#include "serialization.h"
#include <climits>
#include <cmath>
#include <errno.h>
#include <string.h>

// global key-value store
static struct {
  HMap db;
} g_data;

// equality comparison for `struct Entry`
static bool entry_eq(HNode *lhs, HNode *rhs) {
  struct Entry *le = container_of(lhs, struct Entry, node);
  struct Entry *re = container_of(rhs, struct Entry, node);
  return le->key == re->key;
}

// FNV hash
static uint64_t str_hash(const uint8_t *data, size_t len) {
  uint32_t h = 0x811C9DC5;
  for (size_t i = 0; i < len; i++) {
    h = (h + data[i]) * 0x01000193;
  }
  return h;
}

// GET <key> → returns the value in its native type, or nil if not found
static bool do_get(std::string &str, Buffer &out) {
  Entry key;
  key.key.swap(str);
  key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }

  auto &val = container_of(node, Entry, node)->val;
  if (auto *s = std::get_if<std::string>(&val)) {
    return out_str(out, s->data(), s->size());
  } else if (auto *i = std::get_if<int64_t>(&val)) {
    return out_int(out, *i);
  }
  return out_dbl(out, std::get<double>(val));
}

// SET <key> <val> → stores a string value, overwrites any existing type
static bool do_set_str(std::string &key, std::string &val, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (node) {
    container_of(node, Entry, node)->val = std::move(val);
  } else {
    Entry *new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = std::move(val);
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// SETINT <key> <val> → parses val as int64, stores it. error if not a valid integer.
static bool do_set_int(std::string &key, std::string &val_str, Buffer &out) {
  char *end = nullptr;
  errno = 0;
  int64_t val = strtoll(val_str.c_str(), &end, 10);
  if (end == val_str.c_str() || *end != '\0' || errno == ERANGE) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid integer value.",
                   strlen("invalid integer value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (node) {
    container_of(node, Entry, node)->val = val;
  } else {
    Entry *new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = val;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// SETDBL <key> <val> → parses val as double, stores it. rejects inf/nan.
static bool do_set_dbl(std::string &key, std::string &val_str, Buffer &out) {
  char *end = nullptr;
  errno = 0;
  double val = strtod(val_str.c_str(), &end);
  if (end == val_str.c_str() || *end != '\0' || errno == ERANGE) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid double value.",
                   strlen("invalid double value."));
  }
  if (!std::isfinite(val)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid double value.",
                   strlen("invalid double value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (node) {
    container_of(node, Entry, node)->val = val;
  } else {
    Entry *new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = val;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// DEL <key> → removes the key, returns 1 if deleted, 0 if not found
static bool do_del(std::string &key, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_delete(&g_data.db, &entry.node, &entry_eq);
  if (node) {
    delete container_of(node, Entry, node);
  }
  return out_int(out, node ? 1 : 0);
}

// INCR <key> → increments int64 value by 1. creates key with value 1 if missing.
// errors on non-integer type or overflow.
static bool do_incr(std::string &key, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    // Create with initial value 1
    Entry *new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = (int64_t)1;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
    return out_int(out, 1);
  }

  auto &val = container_of(node, Entry, node)->val;
  if (auto *i = std::get_if<int64_t>(&val)) {
    if (*i == INT64_MAX) {
      return out_err(out, ERR_OVERFLOW, "integer overflow.",
                     strlen("integer overflow."));
    }
    *i += 1;
    return out_int(out, *i);
  } else {
    return out_err(out, ERR_TYPE_MISMATCH, "value is not an integer.",
                   strlen("value is not an integer."));
  }
}

// INCRBY <key> <inc> → increments int64 value by <inc>. creates key if missing.
// supports negative increments (decrement). overflow-safe.
static bool do_incrby(std::string &key, std::string &inc_str, Buffer &out) {
  char *end = nullptr;
  errno = 0;
  int64_t inc = strtoll(inc_str.c_str(), &end, 10);
  if (end == inc_str.c_str() || *end != '\0' || errno == ERANGE) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid integer increment value.",
                   strlen("invalid integer increment value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    // Create with initial value `inc`
    Entry *new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = inc;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
    return out_int(out, inc);
  }

  auto &val = container_of(node, Entry, node)->val;
  if (auto *i = std::get_if<int64_t>(&val)) {
    if ((inc > 0 && *i > INT64_MAX - inc) ||
        (inc < 0 && *i < INT64_MIN - inc)) {
      return out_err(out, ERR_OVERFLOW, "integer overflow.",
                     strlen("integer overflow."));
    }
    *i += inc;
    return out_int(out, *i);
  } else {
    return out_err(out, ERR_TYPE_MISMATCH, "value is not an integer.",
                   strlen("value is not an integer."));
  }
}

// TYPE <key> → returns "string", "int", or "double". nil if key doesn't exist.
static bool do_type(std::string &key, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }

  auto &val = container_of(node, Entry, node)->val;
  if (std::holds_alternative<std::string>(val)) {
    return out_str(out, "string", strlen("string"));
  } else if (std::holds_alternative<int64_t>(val)) {
    return out_str(out, "int", strlen("int"));
  } else if (std::holds_alternative<double>(val)) {
    return out_str(out, "double", strlen("double"));
  } else {
    return out_err(out, ERR_UNKNOWN, "unknown type.", strlen("unknown type."));
  }
}

// callback for hm_foreach: serialize each key as a TAG_STR element
static bool cb_keys(HNode *node, void *arg) {
  Buffer &out = *(Buffer *)arg;
  const std::string &key = container_of(node, Entry, node)->key;
  return out_str(out, key.data(), key.size());
}

// KEYS → returns all keys as a TAG_ARR of TAG_STR
static bool do_keys(std::vector<std::string> &, Buffer &out) {
  if (!out_arr(out, (uint32_t)hm_size(&g_data.db))) {
    return false;
  }
  return hm_foreach(&g_data.db, &cb_keys, (void *)&out);
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
  } else {
    return out_err(out, ERR_UNKNOWN, "unknown command.",
                   strlen("unknown command."));
  }
}
