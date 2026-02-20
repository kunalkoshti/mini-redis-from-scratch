#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "conn.h"
#include <cstddef>

extern const size_t k_max_msg_size;

int try_one_request(Conn *conn);

#endif
