/**
 * @file commands_kv.cpp
 * @brief KV command handler implementations.
 *
 * Implements GET, SET, SETINT, SETDBL, DEL, INCR, INCRBY, TYPE, KEYS.
 */

#include "commands_internal.h"

// GET <key> → returns the value in its native type, or nil if not found
bool do_get(std::string &str, Buffer &out) {
  Entry key;
  key.key.swap(str);
  key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }

  auto &val = container_of(node, Entry, node)->val;
  if (std::holds_alternative<ZSet *>(val)) {
    return out_err(out, ERR_TYPE_MISMATCH, "not a valid type",
                   strlen("not a valid type"));
  }
  if (auto *s = std::get_if<std::string>(&val)) {
    return out_str(out, s->data(), s->size());
  } else if (auto *i = std::get_if<int64_t>(&val)) {
    return out_int(out, *i);
  }
  return out_dbl(out, std::get<double>(val));
}

// SET <key> <val> → stores a string value, overwrites any existing type
bool do_set_str(std::string &key, std::string &val, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  Entry *new_entry;
  if (node) {
    new_entry = container_of(node, Entry, node);
    if (std::holds_alternative<ZSet *>(new_entry->val)) {
      return out_err(out, ERR_TYPE_MISMATCH, "not a string type",
                     strlen("not a string type"));
    }
    new_entry->val = std::move(val);
  } else {
    new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = std::move(val);
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// SETINT <key> <val> → parses val as int64, stores it. error if not a valid
// integer.
bool do_set_int(std::string &key, std::string &val_str, Buffer &out) {
  int64_t val;
  if (!str2int(val_str, val)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid integer value.",
                   strlen("invalid integer value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  Entry *new_entry;
  if (node) {
    new_entry = container_of(node, Entry, node);
    if (std::holds_alternative<ZSet *>(new_entry->val)) {
      return out_err(out, ERR_TYPE_MISMATCH, "not a int type",
                     strlen("not a int type"));
    }
    new_entry->val = val;
  } else {
    new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = val;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// SETDBL <key> <val> → parses val as double, stores it. rejects inf/nan.
bool do_set_dbl(std::string &key, std::string &val_str, Buffer &out) {
  double val;
  if (!str2dbl(val_str, val)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid double value.",
                   strlen("invalid double value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  Entry *new_entry;
  if (node) {
    new_entry = container_of(node, Entry, node);
    if (std::holds_alternative<ZSet *>(new_entry->val)) {
      return out_err(out, ERR_TYPE_MISMATCH, "not a double type",
                     strlen("not a double type"));
    }
    new_entry->val = val;
  } else {
    new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->val = val;
    new_entry->node.hcode = entry.node.hcode;
    hm_insert(&g_data.db, &new_entry->node);
  }
  return out_nil(out);
}

// DEL <key> → removes the key, returns 1 if deleted, 0 if not found
bool do_del(std::string &key, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_delete(&g_data.db, &entry.node, &entry_eq);
  if (node) {
    Entry *e = container_of(node, Entry, node);
    if (std::holds_alternative<ZSet *>(e->val)) {
      ZSet *zset = std::get<ZSet *>(e->val);
      zset_clear(zset);
      delete zset;
    }
    delete e;
  }
  return out_int(out, node ? 1 : 0);
}

// INCR <key> → increments int64 value by 1. creates key with value 1 if
// missing. errors on non-integer type or overflow.
bool do_incr(std::string &key, Buffer &out) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
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
bool do_incrby(std::string &key, std::string &inc_str, Buffer &out) {
  int64_t inc;
  if (!str2int(inc_str, inc)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid integer increment value.",
                   strlen("invalid integer increment value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
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

// TYPE <key> → returns "string", "int", "double", "zset". nil if not found.
bool do_type(std::string &key, Buffer &out) {
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
  } else if (std::holds_alternative<ZSet *>(val)) {
    return out_str(out, "zset", strlen("zset"));
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
bool do_keys(std::vector<std::string> &, Buffer &out) {
  if (!out_arr(out, (uint32_t)hm_size(&g_data.db))) {
    return false;
  }
  return hm_foreach(&g_data.db, &cb_keys, (void *)&out);
}
