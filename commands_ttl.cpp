/**
 * @file commands_ttl.cpp
 * @brief TTL command handlers and internal TTL heap bookkeeping.
 *
 * TTLs are scheduled in a global min-heap (g_data.heap) keyed by absolute
 * monotonic expiration time in milliseconds. Each Entry stores heap_idx; the
 * heap stores a pointer back to that heap_idx so reordering can keep indices
 * in sync.
 */

#include "commands_internal.h"

static void heap_delete(std::vector<HeapItem> &a, size_t pos) {
  if (pos >= a.size())
    return;
  a[pos] = a.back();
  a.pop_back();
  if (pos < a.size()) {
    heap_update(a.data(), pos, a.size());
  }
}

static void heap_upsert(std::vector<HeapItem> &a, size_t &pos, HeapItem t) {
  if (pos < a.size()) {
    a[pos] = t;
  } else {
    pos = a.size();
    a.push_back(t);
  }
  heap_update(a.data(), pos, a.size());
}

void entry_set_ttl(Entry *ent, int64_t ttl_ms) {
  // ttl_ms < 0 removes TTL (persist semantics). ttl_ms >= 0 schedules expiry
  // at now + ttl_ms.
  if (ttl_ms < 0 && ent->heap_idx != SIZE_MAX) {
    heap_delete(g_data.heap, ent->heap_idx);
    ent->heap_idx = SIZE_MAX;
  } else if (ttl_ms >= 0) {
    uint64_t expire_at = get_monotonic_msec() + (uint64_t)ttl_ms;
    HeapItem item = {expire_at, &ent->heap_idx};
    heap_upsert(g_data.heap, ent->heap_idx, item);
  }
}

bool do_ttl(std::string &key, Buffer &out) {
  // PTTL <key> → nil if missing, -1 if present with no TTL, else remaining ms.
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }
  Entry *e = container_of(node, Entry, node);
  if (e->heap_idx == SIZE_MAX) {
    return out_int(out, -1);
  }
  uint64_t expire_at = g_data.heap[e->heap_idx].val;
  uint64_t now_ms = get_monotonic_msec();
  return out_int(out, expire_at > now_ms ? (int64_t)(expire_at - now_ms) : 0);
}

bool do_expire(std::string &key, std::string &ttl_str, Buffer &out) {
  // PEXPIRE <key> <ttl_ms> → nil if missing, 1 if TTL updated.
  int64_t ttl_ms = 0;
  if (!str2int(ttl_str, ttl_ms)) {
    return out_err(out, ERR_TYPE_MISMATCH, "invalid integer TTL value.",
                   strlen("invalid integer TTL value."));
  }
  Entry entry;
  entry.key.swap(key);
  entry.node.hcode = str_hash((uint8_t *)entry.key.data(), entry.key.size());
  HNode *node = hm_lookup(&g_data.db, &entry.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }
  Entry *e = container_of(node, Entry, node);
  entry_set_ttl(e, ttl_ms);
  return out_int(out, 1);
}
