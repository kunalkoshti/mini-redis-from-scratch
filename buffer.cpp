#include "buffer.h"
#include <cstdlib>
#include <cstring>

Buffer::Buffer() {}

Buffer::~Buffer() { free(storage); }

Buffer::Buffer(Buffer &&other) noexcept
    : storage(other.storage), data_start(other.data_start),
      data_end(other.data_end), cap(other.cap) {
  other.storage = nullptr;
  other.data_start = 0;
  other.data_end = 0;
  other.cap = 0;
}

Buffer &Buffer::operator=(Buffer &&other) noexcept {
  if (this != &other) {
    free(storage);
    storage = other.storage;
    data_start = other.data_start;
    data_end = other.data_end;
    cap = other.cap;
    other.storage = nullptr;
    other.data_start = 0;
    other.data_end = 0;
    other.cap = 0;
  }
  return *this;
}

void Buffer::compact() {
  if (data_start == 0)
    return;
  size_t len = size();
  if (len > 0)
    memmove(storage, storage + data_start, len);
  data_start = 0;
  data_end = len;
}

uint8_t *Buffer::data() { return storage + data_start; }

const uint8_t *Buffer::data() const { return storage + data_start; }

size_t Buffer::size() const { return data_end - data_start; }

bool Buffer::empty() const { return data_end == data_start; }

// O(1) consume — just advance the read pointer
// Compaction is deferred to append() when space is actually needed
void Buffer::consume(size_t len) {
  if (len >= size()) {
    data_start = 0;
    data_end = 0;
    // --- SHRINK FIX ---
    if (cap > 64 * 1024) { // Only bother shrinking if it's holding >64KB
      free(storage);
      storage = nullptr;
      cap = 0;
    }
  } else {
    data_start += len;
  }
}

// Returns false on allocation failure (OOM)
bool Buffer::append(const uint8_t *src, size_t len) {
  // Check if we need more space
  if (data_end + len > cap) {
    // Try compacting first to reclaim wasted space at front
    compact();

    if (data_end + len > cap) {
      // Need to grow
      size_t new_cap = cap == 0 ? 1024 : cap;
      while (new_cap < data_end + len)
        new_cap *= 2;
      uint8_t *new_storage = (uint8_t *)realloc(storage, new_cap);
      if (!new_storage)
        return false;
      storage = new_storage;
      cap = new_cap;
    }
  }
  memcpy(storage + data_end, src, len);
  data_end += len;
  return true;
}

uint8_t *Buffer::back() { return storage + data_end; }

size_t Buffer::free_capacity() const { return cap - data_end; }

bool Buffer::ensure_capacity(size_t len) {
  if (free_capacity() < len) {
    compact();
    if (free_capacity() < len) {
      // Grow by exactly the requested length (e.g. 64KB)
      size_t new_cap = cap + len;

      uint8_t *new_storage = (uint8_t *)realloc(storage, new_cap);
      if (!new_storage)
        return false;
      storage = new_storage;
      cap = new_cap;
    }
  }
  return true;
}

void Buffer::advance(size_t len) {
  data_end += len;
  if (data_end > cap)
    data_end = cap;
}
