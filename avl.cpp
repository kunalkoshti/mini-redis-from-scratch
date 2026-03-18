/**
 * @file avl.cpp
 * @brief AVL tree rebalancing and deletion implementation.
 *
 * Implements left/right rotations, double-rotation fixes for
 * left-heavy and right-heavy imbalances, bottom-up rebalancing
 * (avl_fix), and node deletion with successor swap (avl_del).
 */

#include "avl.h"
#include <cstdint>

static uint32_t max(uint32_t lhs, uint32_t rhs) {
  return lhs < rhs ? rhs : lhs;
}

// Recalculate height and subtree count after a structural change
static void avl_update(AVLNode *node) {
  node->height = 1 + max(avl_height(node->left), avl_height(node->right));
  node->cnt = 1 + avl_cnt(node->left) + avl_cnt(node->right);
}

// Left rotation: lifts node->right into node's position
static AVLNode *rot_left(AVLNode *node) {
  AVLNode *parent = node->parent;
  AVLNode *new_node = node->right;
  node->right = new_node->left;
  if (node->right) {
    node->right->parent = node;
  }
  new_node->left = node;
  node->parent = new_node;
  new_node->parent = parent;
  avl_update(node);
  avl_update(new_node);
  return new_node;
}

// Right rotation: lifts node->left into node's position
static AVLNode *rot_right(AVLNode *node) {
  AVLNode *parent = node->parent;
  AVLNode *new_node = node->left;
  node->left = new_node->right;
  if (node->left) {
    node->left->parent = node;
  }
  new_node->right = node;
  node->parent = new_node;
  new_node->parent = parent;
  avl_update(node);
  avl_update(new_node);
  return new_node;
}

// Fix left-heavy imbalance (may do left-right double rotation)
static AVLNode *avl_fix_left(AVLNode *node) {
  if (avl_height(node->left->left) < avl_height(node->left->right)) {
    node->left = rot_left(node->left);
  }
  return rot_right(node);
}

// Fix right-heavy imbalance (may do right-left double rotation)
static AVLNode *avl_fix_right(AVLNode *node) {
  if (avl_height(node->right->right) < avl_height(node->right->left)) {
    node->right = rot_right(node->right);
  }
  return rot_left(node);
}

// Walk from node to root, rebalancing at each ancestor. Returns new root.
AVLNode *avl_fix(AVLNode *node) {
  while (true) {
    AVLNode **from = &node;
    AVLNode *parent = node->parent;
    if (parent) {
      from = parent->left == node ? &parent->left : &parent->right;
    }
    avl_update(node);
    uint32_t l = avl_height(node->left);
    uint32_t r = avl_height(node->right);
    if (l == r + 2) {
      *from = avl_fix_left(node);
    } else if (r == l + 2) {
      *from = avl_fix_right(node);
    }
    if (!parent) {
      return *from;
    }
    node = parent;
  }
  return nullptr;
}

// Delete a node with 0 or 1 child (simple unlink + rebalance)
static AVLNode *avl_del_easy(AVLNode *node) {
  AVLNode *child = node->left ? node->left : node->right;
  AVLNode *parent = node->parent;
  if (child) {
    child->parent = parent;
  }
  if (!parent) {
    return child;
  }
  AVLNode **from = parent->left == node ? &parent->left : &parent->right;
  *from = child;
  return avl_fix(parent);
}

// Delete any node: swap with in-order successor if 2 children, then unlink
AVLNode *avl_del(AVLNode *node) {
  if (!node->left || !node->right) {
    return avl_del_easy(node);
  }
  AVLNode *victim = node->right;
  while (victim->left) {
    victim = victim->left;
  }
  AVLNode *root = avl_del_easy(victim);
  *victim = *node;
  if (victim->left) {
    victim->left->parent = victim;
  }
  if (victim->right) {
    victim->right->parent = victim;
  }
  AVLNode **from = &root;
  AVLNode *parent = victim->parent;
  if (parent) {
    from = parent->left == node ? &parent->left : &parent->right;
  }
  *from = victim;
  return root;
}

// Navigate from `node` by `offset` positions in sorted order.
// Positive offset moves right (higher), negative moves left (lower).
// Returns nullptr if the offset is out of bounds.
AVLNode *avl_offset(AVLNode *node, int64_t offset) {
  int64_t pos = 0;
  while (offset != pos) {
    if (pos < offset && pos + avl_cnt(node->right) >= offset) {
      node = node->right;
      pos += avl_cnt(node->left) + 1;
    } else if (pos > offset && pos - avl_cnt(node->left) <= offset) {
      node = node->left;
      pos -= avl_cnt(node->right) + 1;
    } else {
      AVLNode *parent = node->parent;
      if (!parent) {
        return nullptr;
      }
      if (parent->right == node) {
        pos -= avl_cnt(node->left) + 1;
      } else {
        pos += avl_cnt(node->right) + 1;
      }
      node = parent;
    }
  }
  return node;
}

// Returns the 0-based rank (in-order position) of `node` in the tree.
// Walks from node to root, accumulating left subtree sizes. O(log N).
int64_t avl_rank(AVLNode *node) {
  int64_t rank = avl_cnt(node->left);
  AVLNode *new_node = node;
  while (new_node->parent) {
    AVLNode *parent = new_node->parent;
    if (parent->right == new_node) {
      rank += (avl_cnt(parent->left) + 1);
    }
    new_node = parent;
  }
  return rank;
}
