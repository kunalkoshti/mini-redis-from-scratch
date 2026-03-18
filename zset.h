/**
 * @file zset.h
 * @brief Sorted Set (ZSet) backed by an AVL tree + hash map.
 *
 * Each ZSet stores (score, name) pairs sorted by (score, name).
 * The AVL tree provides O(log N) ordered operations (seekge, seekle,
 * offset, rank, count), while the hash map provides O(1) lookup by name.
 *
 * ZNode uses a flexible array member for the name string, so nodes
 * are allocated with malloc(sizeof(ZNode) + len) and freed with free().
 */

#pragma once
#include "avl.h"
#include "hashtable.h"

// Sorted Set container: AVL tree root + hash map for name lookups
struct ZSet {
  AVLNode *root = nullptr;
  HMap hmap;
};

// Sorted Set element node — uses flexible array member for zero-copy name
// Embed both an AVLNode (for tree) and HNode (for hash map) intrusively
struct ZNode {
  AVLNode tree; // intrusive AVL tree node (sorted by score, then name)
  HNode hmap;   // intrusive hash map node (keyed by name)
  double score;
  size_t len = 0;
  char name[]; // flexible array member — name bytes follow the struct
};

// Lookup key for hash map comparisons (stack-allocated, no flexible array)
struct HKey {
  HNode node;
  size_t len = 0;
  const char *name = nullptr;
};

// Public API

// O(1) lookup by name via hash map. Returns nullptr if not found.
ZNode *zset_lookup(ZSet *zset, const char *name, size_t len);

// Insert or update a (name, score) pair. Returns true if newly inserted.
bool zset_insert(ZSet *zset, const char *name, size_t len, double score);

// Delete a node from both the tree and hash map, then free its memory.
void zset_delete(ZSet *zset, ZNode *node);

// Find the first node >= (score, name) in sorted order. Returns nullptr if
// none.
ZNode *zset_seekge(ZSet *zset, double score, const char *name, size_t len);

// Find the last node <= (score, name) in sorted order. Returns nullptr if none.
ZNode *zset_seekle(ZSet *zset, double score, const char *name, size_t len);

// Step `offset` positions from `node` in sorted order (+1 = next, -1 = prev).
ZNode *znode_offset(ZNode *node, int64_t offset);

// Free all internal nodes (tree + hash map). Does NOT free the ZSet itself.
void zset_clear(ZSet *zset);

// Return the 0-based rank (position) of a node in sorted order.
int64_t zset_rank(ZNode *node);

// Count elements in [score1, score2) range. O(log N).
int64_t zset_count(ZSet *zset, double score1, double score2);
