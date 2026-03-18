/**
 * @file commands_zset.cpp
 * @brief ZSet (Sorted Set) command handler implementations.
 *
 * Implements ZADD, ZREM, ZSCORE, ZQUERY, ZRANK, ZCOUNT.
 */

#include "commands_internal.h"

static const ZSet k_empty_zset; // dummy empty ZSet for read-only lookups

// Helper: look up a ZSet by key. Returns &k_empty_zset if key doesn't exist
// (safe for read-only operations), nullptr if key exists but is wrong type.
static ZSet *expect_zset(std::string &key) {
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    entry.key.swap(key);
    return (ZSet *)&k_empty_zset;
  }
  Entry *new_entry = container_of(node, Entry, node);
  entry.key.swap(key);
  return std::holds_alternative<ZSet *>(new_entry->val)
             ? std::get<ZSet *>(new_entry->val)
             : nullptr;
}

// ZADD <key> <score> <name> → inserts or updates a sorted set member.
// Creates the ZSet if the key doesn't exist. Returns 1 if new, 0 if updated.
bool do_zadd(std::string &key, std::string &name, std::string str_score,
             Buffer &out) {
  double score;
  if (!str2dbl(str_score, score)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid score value.",
                   strlen("invalid score value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  Entry *new_entry;
  if (!node) {
    new_entry = new Entry();
    new_entry->key.swap(entry.key);
    new_entry->node.hcode = entry.node.hcode;
    new_entry->val = new ZSet();
    hm_insert(&g_data.db, &new_entry->node);
  } else {
    new_entry = container_of(node, Entry, node);
    if (!std::holds_alternative<ZSet *>(new_entry->val)) {
      return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                     strlen("expect zset"));
    }
  }
  ZSet *zset = std::get<ZSet *>(new_entry->val);
  bool added = zset_insert(zset, name.data(), name.size(), score);
  return out_int(out, (int64_t)added);
}

// ZREM <key> <name> → removes a member. Returns 1 if removed, 0 if not found.
// Garbage-collects the entire ZSet key if the set becomes empty.
bool do_zrem(std::string &key, std::string &name, Buffer &out) {
  ZSet *zset = expect_zset(key);
  if (!zset) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                   strlen("expect zset"));
  }
  ZNode *znode = zset_lookup(zset, name.data(), name.size());
  if (znode) {
    zset_delete(zset, znode);
  }
  if (zset->root == nullptr) {
    Entry entry;
    entry.key.swap(key);
    entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
    HNode *node = hm_delete(&g_data.db, &entry.node, &entry_eq);
    if (node) {
      Entry *e = container_of(node, Entry, node);
      ZSet *zset = std::get<ZSet *>(e->val);
      zset_clear(zset);
      delete zset;
      delete e;
    }
  }
  return out_int(out, znode ? 1 : 0);
}

// ZSCORE <key> <name> → returns the score of a member, or nil if not found.
bool do_zscore(std::string &key, std::string &name, Buffer &out) {
  ZSet *zset = expect_zset(key);
  if (!zset) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                   strlen("expect zset"));
  }
  ZNode *znode = zset_lookup(zset, name.data(), name.size());
  return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// ZQUERY <key> <score> <name> <offset> <limit> [asc|desc]
// Range query: seek to (score, name), skip `offset` entries, return up to
// `limit` (name, score) pairs as a nested array. Defaults to ascending.
bool do_zquery(std::vector<std::string> &cmd, Buffer &out) {
  std::string &key = cmd[1];
  std::string &name = cmd[3];
  double score;
  if (!str2dbl(cmd[2], score)) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect fp number",
                   strlen("expect fp number"));
  }
  int64_t offset, limit;
  if (!str2int(cmd[4], offset) || !str2int(cmd[5], limit)) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect int", strlen("expect int"));
  }
  ZSet *zset = expect_zset(key);
  if (!zset) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                   strlen("expect zset"));
  }
  if (limit <= 0) {
    return out_arr(out, 0);
  }
  size_t ctx;
  if (!out_begin_arr(out, ctx)) {
    return false;
  }
  int64_t n = 0;
  bool asc = (cmd.size() == 6 || cmd[6] == "asc");
  if (asc) {
    ZNode *znode = zset_seekge(zset, score, name.data(), name.size());
    znode = znode_offset(znode, offset);
    while (znode && n < limit) {
      if (!out_str(out, znode->name, znode->len) ||
          !out_dbl(out, znode->score)) {
        return false;
      }
      znode = znode_offset(znode, +1);
      n += 2;
    }
  } else {
    ZNode *znode = zset_seekle(zset, score, name.data(), name.size());
    znode = znode_offset(znode, -offset);
    while (znode && n < limit) {
      if (!out_str(out, znode->name, znode->len) ||
          !out_dbl(out, znode->score)) {
        return false;
      }
      znode = znode_offset(znode, -1);
      n += 2;
    }
  }
  out_end_arr(out, ctx, (uint32_t)n);
  return true;
}

// ZRANK <key> <name> → returns the 0-based rank of a member, or nil.
bool do_zrank(std::string &key, std::string &name, Buffer &out) {
  ZSet *zset = expect_zset(key);
  if (!zset) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                   strlen("expect zset"));
  }
  ZNode *znode = zset_lookup(zset, name.data(), name.size());
  return znode ? out_int(out, zset_rank(znode)) : out_nil(out);
}

// ZCOUNT <key> <min> <max> → counts members with score in [min, max).
bool do_zcount(std::vector<std::string> &cmd, Buffer &out) {
  ZSet *zset = expect_zset(cmd[1]);
  if (!zset) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect zset",
                   strlen("expect zset"));
  }
  double score1, score2;
  if (!str2dbl(cmd[2], score1) || !str2dbl(cmd[3], score2)) {
    return out_err(out, ERR_TYPE_MISMATCH, "expect fp number",
                   strlen("expect fp number"));
  }
  return out_int(out, zset_count(zset, score1, score2));
}
