#include "protocol.h"
#include "commands.h"
#include "serialization.h"
#include "utils.h"
#include <arpa/inet.h>
#include <string.h>

/**
 * Attempts to parse and process one request from the connection buffer.
 *
 * @param conn Client connection structure.
 * @return 1 on success, 0 if data is incomplete, -1 on protocol error.
 */
int try_one_request(Conn *conn) {
  if (conn->incoming.size() < 4) {
    return 0;
  }
  uint32_t len = 0;
  memcpy(&len, conn->incoming.data(), 4);
  len = ntohl(len);
  if (len > k_max_msg) {
    msg("too long");
    return -1;
  }
  if (4 + len > conn->incoming.size()) {
    return 0;
  }
  const uint8_t *request = conn->incoming.data() + 4;

  std::vector<std::string> cmd;
  if (parse_req(request, len, cmd) < 0) {
    msg("bad request");
    return -1;
  }

  size_t header_pos = 0;
  if (!response_begin(conn->outgoing, &header_pos)) {
    return -1;
  }

  if (!do_request(cmd, conn->outgoing)) {
    msg("failed to process request");
    return -1;
  }
  if (!response_end(conn->outgoing, header_pos)) {
    msg("failed to finalize response");
    return -1;
  }
  conn->incoming.consume(4 + len);
  return 1;
}
