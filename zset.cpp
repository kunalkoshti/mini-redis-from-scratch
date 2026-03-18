/**
 * @file zset.cpp
 * @brief Sorted Set implementation using an AVL tree + hash map.
 *
 * The AVL tree maintains elements sorted by (score, name) for
 * ordered queries. The hash map allows O(1) lookup/insert/delete
 * by name. Together they provide the backing store for ZADD, ZREM,
 * ZSCORE, ZQUERY, ZRANK, and ZCOUNT commands.
 */

#include "zset.h"
#include "utils.h"
#include <algorithm>
#include <stdlib.h>
#include <string.h>

// Allocate a new ZNode with flexible array for name (uses malloc, not new)
static ZNode *znode_new(const char *name, size_t len, double score) {
  ZNode *node = (ZNode *)malloc(sizeof(ZNode) + len);
  avl_init(&node->tree);
  node->hmap.next = nullptr;
  node->hmap.hcode = str_hash((uint8_t *)name, len);
  node->len = len;
  node->score = score;
  memcpy(node->name, name, len);
  return node;
}

static size_t min(size_t lhs, size_t rhs) { return lhs < rhs ? lhs : rhs; }

// Free a ZNode (allocated with malloc)
static void znode_del(ZNode *node) { free(node); }

// Hash map equality: compare ZNode name against HKey name
static bool hcmp(HNode *node, HNode *key) {
  ZNode *znode = container_of(node, ZNode, hmap);
  HKey *hkey = container_of(key, HKey, node);
  return (znode->len == hkey->len &&
          memcmp(znode->name, hkey->name, hkey->len) == 0);
}

ZNode *zset_lookup(ZSet *zset, const char *name, size_t len) {
  if (!zset->root) {
    return nullptr;
  }
  HKey key;
  key.node.hcode = str_hash((uint8_t *)name, len);
  key.len = len;
  key.name = name;
  HNode *found = hm_lookup(&zset->hmap, &key.node, &hcmp);
  return found ? container_of(found, ZNode, hmap) : nullptr;
}

// Compare an AVL node against (score, name, len).
// Returns true if the node is strictly less than the target.
static bool zless(AVLNode *lhs, double score, const char *name, size_t len) {
  ZNode *zl = container_of(lhs, ZNode, tree);
  if (zl->score != score) {
    return zl->score < score;
  }
  int rv = memcmp(zl->name, name, min(zl->len, len));
  if (rv != 0) {
    return rv < 0;
  }
  return zl->len < len;
}

// Overload: compare two AVL nodes
static bool zless(AVLNode *lhs, AVLNode *rhs) {
  ZNode *zr = container_of(rhs, ZNode, tree);
  return zless(lhs, zr->score, zr->name, zr->len);
}

// Insert a ZNode into the AVL tree in sorted position, then rebalance
static void tree_insert(ZSet *zset, ZNode *node) {
  AVLNode *parent = nullptr;
  AVLNode **from = &zset->root;
  while (*from) {
    parent = *from;
    from = zless(&node->tree, parent) ? &parent->left : &parent->right;
  }
  *from = &node->tree;
  node->tree.parent = parent;
  zset->root = avl_fix(&node->tree);
}

// Update a node's score: remove from tree, change score, re-insert
static void zset_update(ZSet *zset, ZNode *node, double score) {
  if (node->score == score) {
    return;
  }
  zset->root = avl_del(&node->tree);
  avl_init(&node->tree);
  node->score = score;
  tree_insert(zset, node);
}

bool zset_insert(ZSet *zset, const char *name, size_t len, double score) {
  ZNode *node = zset_lookup(zset, name, len);
  if (node) {
    zset_update(zset, node, score);
    return false;
  } else {
    node = znode_new(name, len, score);
    hm_insert(&zset->hmap, &node->hmap);
    tree_insert(zset, node);
    return true;
  }
}

void zset_delete(ZSet *zset, ZNode *node) {
  HKey key;
  key.node.hcode = node->hmap.hcode;
  key.name = node->name;
  key.len = node->len;
  hm_delete(&zset->hmap, &key.node, &hcmp);
  zset->root = avl_del(&node->tree);
  znode_del(node);
}

ZNode *zset_seekge(ZSet *zset, double score, const char *name, size_t len) {
  AVLNode *found = nullptr;
  for (AVLNode *node = zset->root; node;) {
    if (zless(node, score, name, len)) {
      node = node->right;
    } else {
      found = node;
      node = node->left;
    }
  }
  return found ? container_of(found, ZNode, tree) : nullptr;
}

ZNode *zset_seekle(ZSet *zset, double score, const char *name, size_t len) {
  AVLNode *found = nullptr;
  for (AVLNode *node = zset->root; node;) {
    if (zless(node, score, name, len)) {
      found = node;
      node = node->right;
    } else {
      ZNode *znode = container_of(node, ZNode, tree);
      if (znode->score == score && znode->len == len &&
          memcmp(znode->name, name, len) == 0) {
        found = node;
        break;
      }
      node = node->left;
    }
  }
  return found ? container_of(found, ZNode, tree) : nullptr;
}

ZNode *znode_offset(ZNode *node, int64_t offset) {
  AVLNode *tnode = node ? avl_offset(&node->tree, offset) : nullptr;
  return tnode ? container_of(tnode, ZNode, tree) : nullptr;
}

int64_t zset_count(ZSet *zset, double score1, double score2) {
  ZNode *node1 = zset_seekge(zset, score1, "", 0);
  ZNode *node2 = zset_seekle(zset, score2, "", 0);
  if (!node1 || !node2) {
    return 0;
  }
  int64_t rank1 = zset_rank(node1);
  int64_t rank2 = zset_rank(node2);
  return rank2 >= rank1 ? rank2 - rank1 + 1 : 0;
}

// Recursively free all ZNodes in the AVL tree
static void tree_dispose(AVLNode *node) {
  if (!node) {
    return;
  }
  tree_dispose(node->left);
  tree_dispose(node->right);
  znode_del(container_of(node, ZNode, tree));
}

void zset_clear(ZSet *zset) {
  hm_clear(&zset->hmap);
  tree_dispose(zset->root);
  zset->root = nullptr;
}

int64_t zset_rank(ZNode *node) { return avl_rank(&node->tree); }
