/**
 * @file avl.h
 * @brief Intrusive AVL tree node and public API.
 *
 * Provides the AVLNode struct (embed in your data type via container_of),
 * inline helpers for initialization and size queries, and the core
 * rebalancing (avl_fix) and deletion (avl_del) functions.
 */

#pragma once

#include <cstdint>

// Intrusive AVL tree node — embed in your data struct via container_of
struct AVLNode {
  AVLNode *left;
  AVLNode *right;
  AVLNode *parent;
  uint32_t height;
  uint32_t cnt;
};

// Initialize a freshly allocated node (leaf with no children)
inline void avl_init(AVLNode *node) {
  node->left = node->right = node->parent = nullptr;
  node->height = 1;
  node->cnt = 1;
}

inline uint32_t avl_height(AVLNode *node) {
  return node ? node->height : 0;
} // 0 for null
inline uint32_t avl_cnt(AVLNode *node) {
  return node ? node->cnt : 0;
} // 0 for null

// Fix balance from `node` up to root, returns new root
AVLNode *avl_fix(AVLNode *node);
// Delete `node` from tree, returns new root
AVLNode *avl_del(AVLNode *node);