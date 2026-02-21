#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "conn.h"
#include <stdint.h>
#include <string>
#include <vector>

// Process one request from the connection if there is enough data
// Returns 1 to keep processing, 0 if we need more data, -1 if we want to close
int try_one_request(Conn *conn);

#endif
