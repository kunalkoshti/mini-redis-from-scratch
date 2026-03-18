/**
 * @file tests_zset.cpp
 * @brief Unit tests for the ZSet (Sorted Set) data structure.
 *
 * Tests the ZSet API directly without a running server.
 * Covers insert, lookup, delete, seekge, seekle, offset, rank, and count.
 *
 * Compile: g++ -O2 -Wall -Wextra tests_zset.cpp zset.cpp avl.cpp
 *          hashtable.cpp utils.cpp -o tests_zset
 */

#include "../avl.h"
#include "../utils.h"
#include "../zset.h"
#include <assert.h>
#include <iostream>
#include <string.h>

// AVL offset exhaustive test (from user's provided test)

struct Data {
  AVLNode node;
  uint32_t val = 0;
};

struct Container {
  AVLNode *root = NULL;
};

static void add(Container &c, uint32_t val) {
  Data *data = new Data();
  avl_init(&data->node);
  data->val = val;

  if (!c.root) {
    c.root = &data->node;
    return;
  }

  AVLNode *cur = c.root;
  while (true) {
    AVLNode **from =
        (val < container_of(cur, Data, node)->val) ? &cur->left : &cur->right;
    if (!*from) {
      *from = &data->node;
      data->node.parent = cur;
      c.root = avl_fix(&data->node);
      break;
    }
    cur = *from;
  }
}

static void dispose(AVLNode *node) {
  if (node) {
    dispose(node->left);
    dispose(node->right);
    delete container_of(node, Data, node);
  }
}

static void test_avl_offset(uint32_t sz) {
  Container c;
  for (uint32_t i = 0; i < sz; ++i) {
    add(c, i);
  }

  AVLNode *min = c.root;
  while (min && min->left) {
    min = min->left;
  }
  for (uint32_t i = 0; i < sz; ++i) {
    AVLNode *node = avl_offset(min, (int64_t)i);
    assert(container_of(node, Data, node)->val == i);

    for (uint32_t j = 0; j < sz; ++j) {
      int64_t offset = (int64_t)j - (int64_t)i;
      AVLNode *n2 = avl_offset(node, offset);
      assert(container_of(n2, Data, node)->val == j);
    }
    assert(!avl_offset(node, -(int64_t)i - 1));
    assert(!avl_offset(node, sz - i));
  }

  dispose(c.root);
}

// ZSet data structure tests

// Helper to create a ZSet and insert some elements
static ZSet *make_test_zset() {
  ZSet *zset = new ZSet();
  zset->root = nullptr;
  zset->hmap = {};
  return zset;
}

// Helper to free a ZSet
static void free_test_zset(ZSet *zset) {
  zset_clear(zset);
  delete zset;
}

int main() {
  // AVL offset tests
  std::cout << "[Test 1] AVL offset exhaustive (sz 1..200)... " << std::flush;
  for (uint32_t i = 1; i <= 200; ++i) {
    test_avl_offset(i);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet insert & lookup
  std::cout << "[Test 2] ZSet insert & lookup... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    // Insert 3 elements
    assert(zset_insert(zset, "alice", 5, 10.0) == true);
    assert(zset_insert(zset, "bob", 3, 20.0) == true);
    assert(zset_insert(zset, "charlie", 7, 15.0) == true);

    // Lookup existing
    ZNode *n = zset_lookup(zset, "alice", 5);
    assert(n != nullptr);
    assert(n->score == 10.0);
    assert(n->len == 5);
    assert(memcmp(n->name, "alice", 5) == 0);

    n = zset_lookup(zset, "bob", 3);
    assert(n != nullptr);
    assert(n->score == 20.0);

    // Lookup non-existent
    n = zset_lookup(zset, "dave", 4);
    assert(n == nullptr);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet duplicate insert (score update)
  std::cout << "[Test 3] ZSet duplicate insert (score update)... "
            << std::flush;
  {
    ZSet *zset = make_test_zset();
    assert(zset_insert(zset, "alice", 5, 10.0) == true);  // new
    assert(zset_insert(zset, "alice", 5, 25.0) == false); // update
    ZNode *n = zset_lookup(zset, "alice", 5);
    assert(n != nullptr);
    assert(n->score == 25.0); // score was updated
    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet delete
  std::cout << "[Test 4] ZSet delete... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "alice", 5, 10.0);
    zset_insert(zset, "bob", 3, 20.0);

    ZNode *n = zset_lookup(zset, "alice", 5);
    assert(n != nullptr);
    zset_delete(zset, n);

    // alice should be gone
    assert(zset_lookup(zset, "alice", 5) == nullptr);
    // bob should still be there
    assert(zset_lookup(zset, "bob", 3) != nullptr);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet seekge
  std::cout << "[Test 5] ZSet seekge... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 1.0);
    zset_insert(zset, "b", 1, 3.0);
    zset_insert(zset, "c", 1, 5.0);

    // seekge(2.0) should find "b" (score 3.0)
    ZNode *n = zset_seekge(zset, 2.0, "", 0);
    assert(n != nullptr);
    assert(n->score == 3.0);

    // seekge(3.0) should find "b" (score 3.0, name "b" >= "")
    n = zset_seekge(zset, 3.0, "", 0);
    assert(n != nullptr);
    assert(n->score == 3.0);

    // seekge(6.0) should find nothing
    n = zset_seekge(zset, 6.0, "", 0);
    assert(n == nullptr);

    // seekge(0.0) should find "a" (score 1.0)
    n = zset_seekge(zset, 0.0, "", 0);
    assert(n != nullptr);
    assert(n->score == 1.0);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet seekle
  std::cout << "[Test 6] ZSet seekle... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 1.0);
    zset_insert(zset, "b", 1, 3.0);
    zset_insert(zset, "c", 1, 5.0);

    // seekle(4.0, "", 0) should find "b" (score 3.0, which is < 4.0)
    // Note: seekle with "" finds strictly less than (score, "")
    ZNode *n = zset_seekle(zset, 4.0, "", 0);
    assert(n != nullptr);
    assert(n->score == 3.0);

    // seekle(3.0, "b", 1) — exact match for "b"
    n = zset_seekle(zset, 3.0, "b", 1);
    assert(n != nullptr);
    assert(n->score == 3.0);
    assert(memcmp(n->name, "b", 1) == 0);

    // seekle(0.5, "", 0) should find nothing (everything is bigger)
    n = zset_seekle(zset, 0.5, "", 0);
    assert(n == nullptr);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet offset traversal
  std::cout << "[Test 7] ZSet offset traversal... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 1.0);
    zset_insert(zset, "b", 1, 2.0);
    zset_insert(zset, "c", 1, 3.0);
    zset_insert(zset, "d", 1, 4.0);

    // Start at "a" (rank 0)
    ZNode *n = zset_seekge(zset, 0.0, "", 0);
    assert(n != nullptr && n->score == 1.0);

    // offset +1 → "b"
    ZNode *next = znode_offset(n, 1);
    assert(next != nullptr && next->score == 2.0);

    // offset +2 → "c"
    next = znode_offset(n, 2);
    assert(next != nullptr && next->score == 3.0);

    // offset +3 → "d"
    next = znode_offset(n, 3);
    assert(next != nullptr && next->score == 4.0);

    // offset +4 → out of bounds
    next = znode_offset(n, 4);
    assert(next == nullptr);

    // Start at "d" (rank 3), offset -1 → "c"
    n = zset_seekge(zset, 4.0, "", 0);
    next = znode_offset(n, -1);
    assert(next != nullptr && next->score == 3.0);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet rank
  std::cout << "[Test 8] ZSet rank... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 10.0);
    zset_insert(zset, "b", 1, 20.0);
    zset_insert(zset, "c", 1, 30.0);
    zset_insert(zset, "d", 1, 40.0);

    ZNode *n;
    n = zset_lookup(zset, "a", 1);
    assert(zset_rank(n) == 0);

    n = zset_lookup(zset, "b", 1);
    assert(zset_rank(n) == 1);

    n = zset_lookup(zset, "c", 1);
    assert(zset_rank(n) == 2);

    n = zset_lookup(zset, "d", 1);
    assert(zset_rank(n) == 3);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet count [score1, score2)
  std::cout << "[Test 9] ZSet count [score1, score2)... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 1.0);
    zset_insert(zset, "b", 1, 2.0);
    zset_insert(zset, "c", 1, 3.0);
    zset_insert(zset, "d", 1, 4.0);
    zset_insert(zset, "e", 1, 5.0);

    // [1.0, 5.0) → a,b,c,d = 4
    assert(zset_count(zset, 1.0, 5.0) == 4);

    // [2.0, 4.0) → b,c = 2
    assert(zset_count(zset, 2.0, 4.0) == 2);

    // [1.0, 6.0) → all 5
    assert(zset_count(zset, 1.0, 6.0) == 5);

    // [3.0, 3.0) → empty (exclusive upper bound)
    assert(zset_count(zset, 3.0, 3.0) == 0);

    // [10.0, 20.0) → empty (no elements in range)
    assert(zset_count(zset, 10.0, 20.0) == 0);

    // [1.0, 1.0) → empty
    assert(zset_count(zset, 1.0, 1.0) == 0);

    // [1.0, 2.0) → just a = 1
    assert(zset_count(zset, 1.0, 2.0) == 1);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet empty set operations
  std::cout << "[Test 10] ZSet empty set operations... " << std::flush;
  {
    ZSet *zset = make_test_zset();

    assert(zset_lookup(zset, "x", 1) == nullptr);
    assert(zset_seekge(zset, 0.0, "", 0) == nullptr);
    assert(zset_seekle(zset, 0.0, "", 0) == nullptr);
    assert(zset_count(zset, 0.0, 10.0) == 0);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ZSet rank after score update
  std::cout << "[Test 11] ZSet rank after score update... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "a", 1, 10.0);
    zset_insert(zset, "b", 1, 20.0);
    zset_insert(zset, "c", 1, 30.0);

    // "a" is rank 0 with score 10
    ZNode *n = zset_lookup(zset, "a", 1);
    assert(zset_rank(n) == 0);

    // Update "a" to score 25 (should now be between b and c)
    zset_insert(zset, "a", 1, 25.0);
    n = zset_lookup(zset, "a", 1);
    assert(n->score == 25.0);
    assert(zset_rank(n) == 1); // b(20) < a(25) < c(30)

    // Update "a" to score 35 (should now be last)
    zset_insert(zset, "a", 1, 35.0);
    n = zset_lookup(zset, "a", 1);
    assert(zset_rank(n) == 2); // b(20) < c(30) < a(35)

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // ---- ZSet same score, different names (lexicographic order) ----
  std::cout << "[Test 12] ZSet same score, lexicographic order... "
            << std::flush;
  {
    ZSet *zset = make_test_zset();
    zset_insert(zset, "charlie", 7, 5.0);
    zset_insert(zset, "alice", 5, 5.0);
    zset_insert(zset, "bob", 3, 5.0);

    // All have score 5.0 — should be sorted by name: alice < bob < charlie
    ZNode *n = zset_seekge(zset, 5.0, "", 0);
    assert(n != nullptr);
    assert(memcmp(n->name, "alice", 5) == 0);

    n = znode_offset(n, 1);
    assert(n != nullptr);
    assert(memcmp(n->name, "bob", 3) == 0);

    n = znode_offset(n, 1);
    assert(n != nullptr);
    assert(memcmp(n->name, "charlie", 7) == 0);

    n = znode_offset(n, 1);
    assert(n == nullptr);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  // Large ZSet stress test
  std::cout << "[Test 13] Large ZSet (1000 elements)... " << std::flush;
  {
    ZSet *zset = make_test_zset();
    for (int i = 0; i < 1000; ++i) {
      std::string name = "node" + std::to_string(i);
      zset_insert(zset, name.data(), name.size(), (double)i);
    }

    // Verify all ranks
    for (int i = 0; i < 1000; ++i) {
      std::string name = "node" + std::to_string(i);
      ZNode *n = zset_lookup(zset, name.data(), name.size());
      assert(n != nullptr);
      assert(n->score == (double)i);
    }

    // Count [0, 500) should be 500
    assert(zset_count(zset, 0.0, 500.0) == 500);

    // Count [0, 1000) should be 1000
    assert(zset_count(zset, 0.0, 1000.0) == 1000);

    // Delete half
    for (int i = 0; i < 500; ++i) {
      std::string name = "node" + std::to_string(i);
      ZNode *n = zset_lookup(zset, name.data(), name.size());
      assert(n != nullptr);
      zset_delete(zset, n);
    }

    // Count [0, 1000) should now be 500
    assert(zset_count(zset, 0.0, 1000.0) == 500);

    // Remaining elements start at score 500
    ZNode *first = zset_seekge(zset, 0.0, "", 0);
    assert(first != nullptr);
    assert(first->score == 500.0);

    free_test_zset(zset);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! All ZSet tests passed (13/13).\n"
            << std::endl;
  return 0;
}
