/**
 * @file hashtable.h
 * @brief Intrusive hash table with incremental rehashing.
 *
 * Two-table design: new inserts go into `newer`, and a bounded amount
 * of entries migrate from `older` to `newer` on each mutation, so
 * rehashing never blocks for long.
 */

#pragma once
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

// Intrusive hash node — embed in your data struct via container_of
struct HNode {
  HNode *next = nullptr;
  uint64_t hcode = 0;
};

// Single hash table (power-of-2 sized, chaining)
struct HTab {
  HNode **tab = nullptr;
  size_t mask = 0;
  size_t size = 0;
};

// Two-table map with incremental rehashing
struct HMap {
  HTab newer;
  HTab older;
  size_t migrate_pos = 0;
};

// Lookup a key by hash + equality callback, returns node or nullptr
HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
// Insert a node into the map, triggers rehashing if load factor exceeded
void hm_insert(HMap *hmap, HNode *node);
// Delete a key by hash + equality callback, returns detached node or nullptr
HNode *hm_delete(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
// Free both tables and reset the map
void hm_clear(HMap *hmap);
// Total number of entries across both tables
size_t hm_size(HMap *hmap);
// Iterate all entries, calling f(node, arg); stops early if f returns false
bool hm_foreach(HMap *hmap, bool (*f)(HNode *, void *), void *arg);
