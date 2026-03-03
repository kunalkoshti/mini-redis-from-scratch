#pragma once
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define container_of(ptr, T, member) ((T *)((char *)ptr - offsetof(T, member)))

struct HNode {
  HNode *next = NULL;
  uint64_t hcode = 0;
};

struct HTab {
  HNode **tab = NULL;
  size_t mask = 0;
  size_t size = 0;
};

struct HMap {
  HTab newer;
  HTab older;
  size_t migrate_pos = 0;
};

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
void hm_insert(HMap *hmap, HNode *node);
HNode *hm_delete(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
void hm_clear(HMap *hmap);
size_t hm_size(HMap *hmap);
