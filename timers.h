#pragma once

#include <cstdint>

int32_t next_timer_ms();
void process_timers(int epfd);
