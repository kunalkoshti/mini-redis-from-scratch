#ifndef BUFFER_H
#define BUFFER_H

#include <cstdint>
#include <stddef.h>

class Buffer {
private:
  uint8_t *storage = nullptr;
  size_t data_start = 0; // Offset of valid data start
  size_t data_end = 0;   // Offset of valid data end
  size_t cap = 0;

  void compact();

public:
  Buffer();
  ~Buffer();

  // Disable copy constructor/assignment to prevent double-frees
  Buffer(const Buffer &) = delete;
  Buffer &operator=(const Buffer &) = delete;

  // Move constructor/assignment
  Buffer(Buffer &&other) noexcept;
  Buffer &operator=(Buffer &&other) noexcept;

  uint8_t *data();
  const uint8_t *data() const;
  size_t size() const;
  bool empty() const;

  void consume(size_t len);
  bool append(const uint8_t *data, size_t len);
};

#endif
