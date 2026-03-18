/**
 * @file tests_avl.cpp
 * @brief Unit tests for the AVL tree implementation.
 *
 * Verifies insertion, deletion, duplicate handling, and tree balancing
 * by comparing the AVL tree against a reference std::multiset.
 *
 * Tests 1-3:  Basic operations (insert, lookup miss, delete)
 * Tests 4-5:  Sequential and random insertion with verification
 * Test 6:     Random deletion with verification
 * Test 7:     Exhaustive insert/delete at every position
 */

#include "../avl.h"
#include "../utils.h"
#include <assert.h>
#include <iostream>
#include <set>
#include <stdio.h>
#include <stdlib.h>

// Test node: wraps AVLNode with a uint32_t value for BST ordering
struct Data {
  AVLNode node;
  uint32_t val;
};

// Holds the root pointer for an AVL tree
struct Container {
  AVLNode *root = nullptr;
};

// Insert val into the BST, then rebalance
static void add(Container &c, uint32_t val) {
  Data *data = new Data();
  data->val = val;
  avl_init(&data->node);
  AVLNode *curr = nullptr;
  AVLNode **from = &c.root;
  while (*from) {
    curr = *from;
    uint32_t node_val = container_of(curr, Data, node)->val;
    from = (node_val <= val) ? &curr->right : &curr->left;
  }
  *from = &data->node;
  data->node.parent = curr;
  c.root = avl_fix(&data->node);
}

// Find and delete val from the BST, returns false if not found
static bool del(Container &c, uint32_t val) {
  AVLNode *curr = c.root;
  while (curr) {
    uint32_t node_val = container_of(curr, Data, node)->val;
    if (node_val == val) {
      break;
    }
    curr = (node_val <= val) ? curr->right : curr->left;
  }
  if (!curr) {
    return false;
  }
  c.root = avl_del(curr);
  delete container_of(curr, Data, node);
  return true;
}

// Recursively verify parent pointers, balance, height, cnt, and BST ordering
static void avl_verify(AVLNode *parent, AVLNode *node) {
  if (!node) {
    return;
  }

  assert(node->parent == parent);
  avl_verify(node, node->left);
  avl_verify(node, node->right);

  assert(node->cnt == 1 + avl_cnt(node->left) + avl_cnt(node->right));

  uint32_t l = avl_height(node->left);
  uint32_t r = avl_height(node->right);
  assert(l == r || l + 1 == r || l == r + 1);
  assert(node->height == 1 + std::max(l, r));

  uint32_t val = container_of(node, Data, node)->val;
  if (node->left) {
    assert(node->left->parent == node);
    assert(container_of(node->left, Data, node)->val <= val);
  }
  if (node->right) {
    assert(node->right->parent == node);
    assert(container_of(node->right, Data, node)->val >= val);
  }
}

// In-order traversal to collect all values into a multiset
static void extract(AVLNode *node, std::multiset<uint32_t> &extracted) {
  if (!node) {
    return;
  }
  extract(node->left, extracted);
  extracted.insert(container_of(node, Data, node)->val);
  extract(node->right, extracted);
}

// Verify tree structure and contents match the reference multiset
static void container_verify(Container &c, const std::multiset<uint32_t> &ref) {
  avl_verify(nullptr, c.root);
  assert(avl_cnt(c.root) == ref.size());
  std::multiset<uint32_t> extracted;
  extract(c.root, extracted);
  assert(extracted == ref);
}

// Delete all nodes and free memory
static void dispose(Container &c) {
  while (c.root) {
    AVLNode *node = c.root;
    c.root = avl_del(c.root);
    delete container_of(node, Data, node);
  }
}

// For each position, build tree without that value, insert it, verify
static void test_insert(uint32_t sz) {
  for (uint32_t val = 0; val < sz; ++val) {
    Container c;
    std::multiset<uint32_t> ref;
    for (uint32_t i = 0; i < sz; ++i) {
      if (i == val) {
        continue;
      }
      add(c, i);
      ref.insert(i);
    }
    container_verify(c, ref);

    add(c, val);
    ref.insert(val);
    container_verify(c, ref);
    dispose(c);
  }
}

// Insert all values including duplicates, verify tree handles them
static void test_insert_dup(uint32_t sz) {
  for (uint32_t val = 0; val < sz; ++val) {
    Container c;
    std::multiset<uint32_t> ref;
    for (uint32_t i = 0; i < sz; ++i) {
      add(c, i);
      ref.insert(i);
    }
    container_verify(c, ref);

    add(c, val);
    ref.insert(val);
    container_verify(c, ref);
    dispose(c);
  }
}

// For each position, build full tree, delete that value, verify
static void test_remove(uint32_t sz) {
  for (uint32_t val = 0; val < sz; ++val) {
    Container c;
    std::multiset<uint32_t> ref;
    for (uint32_t i = 0; i < sz; ++i) {
      add(c, i);
      ref.insert(i);
    }
    container_verify(c, ref);

    assert(del(c, val));
    ref.erase(val);
    container_verify(c, ref);
    dispose(c);
  }
}

int main() {
  Container c;

  std::cout << "[Test 1] Empty Tree Verification... ";
  container_verify(c, {});
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 2] Single Insert & Delete... ";
  add(c, 123);
  container_verify(c, {123});
  assert(!del(c, 124));
  assert(del(c, 123));
  container_verify(c, {});
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3] Sequential Insertion (334 keys)... ";
  std::multiset<uint32_t> ref;
  for (uint32_t i = 0; i < 1000; i += 3) {
    add(c, i);
    ref.insert(i);
    container_verify(c, ref);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 4] Random Insertion (100 keys)... ";
  for (uint32_t i = 0; i < 100; i++) {
    uint32_t val = (uint32_t)rand() % 1000;
    add(c, val);
    ref.insert(val);
    container_verify(c, ref);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 5] Random Deletion (200 ops)... ";
  for (uint32_t i = 0; i < 200; i++) {
    uint32_t val = (uint32_t)rand() % 1000;
    auto it = ref.find(val);
    if (it == ref.end()) {
      assert(!del(c, val));
    } else {
      assert(del(c, val));
      ref.erase(it);
    }
    container_verify(c, ref);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 6] Exhaustive Insert/Dup/Remove (sz 0..199)... "
            << std::endl;
  for (uint32_t i = 0; i < 200; ++i) {
    test_insert(i);
    test_insert_dup(i);
    test_remove(i);
    if (i % 50 == 0)
      std::cout << "  Completed sz=" << i << std::endl;
  }
  std::cout << "PASSED" << std::endl;

  dispose(c);

  std::cout << "\nCongratulations! All AVL tests passed (6/6).\n" << std::endl;
  return 0;
}