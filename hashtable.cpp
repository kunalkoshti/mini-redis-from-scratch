#include "hashtable.h"
#include "utils.h"
#include <cstdlib>

static const size_t k_initial_cap = 8;
static const size_t k_max_load_factor = 8;
static const size_t k_rehashing_work = 128;

static void h_init(HTab *h, size_t n) {
  if (n == 0 || (n & (n - 1)) != 0) {
    die("hashtable size (n) must be power of 2");
  }
  h->tab = (HNode **)calloc(n, sizeof(HNode *));
  if (!h->tab) {
    die("calloc failed");
  }
  h->mask = n - 1;
  h->size = 0;
}

static void h_insert(HTab *htab, HNode *node) {
  uint64_t pos = node->hcode & htab->mask;
  node->next = htab->tab[pos];
  htab->tab[pos] = node;
  htab->size++;
}

static HNode **h_lookup(HTab *htab, HNode *key, bool (*eq)(HNode *, HNode *)) {
  if (!htab->tab) {
    return NULL;
  }
  size_t pos = key->hcode & htab->mask;
  HNode **from = &htab->tab[pos];
  for (HNode *curr; (curr = *from) != NULL; from = &curr->next) {
    if (curr->hcode == key->hcode && eq(curr, key)) {
      return from;
    }
  }
  return NULL;
}

static HNode *h_detach(HTab *htab, HNode **from) {
  HNode *node = *from;
  *from = node->next;
  htab->size--;
  return node;
}

static void hm_trigger_rehashing(HMap *hmap) {
  hmap->older = hmap->newer;
  h_init(&hmap->newer, hmap->newer.size * 2);
  hmap->migrate_pos = 0;
}

static void hm_help_rehashing(HMap *hmap) {
  size_t nwork = 0;
  while (nwork < k_rehashing_work && hmap->older.size > 0) {
    HNode **from = &hmap->older.tab[hmap->migrate_pos];
    if (!*from) {
      hmap->migrate_pos++;
      continue;
    }
    h_insert(&hmap->newer, h_detach(&hmap->older, from));
    nwork++;
  }
  if (hmap->older.size == 0 && hmap->older.tab) {
    free(hmap->older.tab);
    hmap->older = HTab{};
  }
}

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
  HNode **from = h_lookup(&(hmap->newer), key, eq);
  if (!from) {
    from = h_lookup(&(hmap->older), key, eq);
  }
  return from ? *from : NULL;
}

HNode *hm_delete(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
  if (HNode **from = h_lookup(&hmap->newer, key, eq)) {
    return h_detach(&hmap->newer, from);
  }
  if (HNode **from = h_lookup(&hmap->older, key, eq)) {
    return h_detach(&hmap->older, from);
  }
  return NULL;
}

void hm_insert(HMap *hmap, HNode *node) {
  if (!hmap->newer.tab) {
    h_init(&hmap->newer, k_initial_cap);
  }
  h_insert(&hmap->newer, node);
  if (!hmap->older.tab) {
    size_t shreshold = (hmap->newer.mask + 1) * k_max_load_factor;
    if (hmap->newer.size >= shreshold) {
      hm_trigger_rehashing(hmap);
    }
  }
  hm_help_rehashing(hmap);
}

void hm_clear(HMap *hmap) {
  free(hmap->newer.tab);
  free(hmap->older.tab);
  *hmap = HMap{};
}

size_t hm_size(HMap *hmap) { return hmap->newer.size + hmap->older.size; }

static bool h_foreach(HTab *htab, bool (*f)(HNode *, void *), void *arg) {
  for (size_t i = 0; htab->mask != 0 && i <= htab->mask; i++) {
    for (HNode *node = htab->tab[i]; node != NULL; node = node->next) {
      if (!f(node, arg)) {
        return false;
      }
    }
  }
  return true;
}

bool hm_foreach(HMap *hmap, bool (*f)(HNode *, void *), void *arg) {
  return (h_foreach(&hmap->newer, f, arg) && h_foreach(&hmap->older, f, arg));
}
