#pragma once

#include <stddef.h>
#include <stdint.h>

struct HeapItem {
  // Min-heap key (used as an absolute expiration timestamp in ms for TTL).
  uint64_t val = 0;

  // Pointer to the owning object's heap index; updated as heap elements move.
  size_t *ref = NULL;
};

void heap_update(HeapItem *a, size_t pos, size_t len);
