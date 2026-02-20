#include "protocol.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

const size_t k_max_msg_size = 32 << 20; // 32MB limit

// Parse protocol: 4-byte header for length followed by body
int try_one_request(Conn *conn) {
  if (conn->incoming.size() < 4)
    return 0; // Need more data for header

  uint32_t msg_len = 0;
  memcpy(&msg_len, conn->incoming.data(), 4);
  msg_len = ntohl(msg_len);

  if (msg_len > k_max_msg_size)
    return -1; // Protect against OOM/malicious size
  if (4 + msg_len > conn->incoming.size())
    return 0; // Body not fully received yet

  const uint8_t *msg = conn->incoming.data() + 4;
  printf("client says: len:%d data:%.*s\n", msg_len,
         msg_len < 100 ? msg_len : 100, msg);

  // Echo back protocol: length + body
  uint32_t net_len = htonl(msg_len);
  if (!conn->outgoing.append((const uint8_t *)&net_len, 4))
    return -1;
  if (!conn->outgoing.append(msg, msg_len))
    return -1;
  conn->incoming.consume(4 + msg_len);
  return 1;
}
