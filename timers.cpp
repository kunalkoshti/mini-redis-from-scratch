#include "timers.h"
#include "conn.h"
#include "list.h"
#include "utils.h"

#define IDLE_TIMEOUT_MS (5 * 1000)
#define PARTIAL_READ_TIMEOUT_MS (2 * 1000)
#define PARTIAL_WRITE_TIMEOUT_MS (3 * 1000)

static bool no_clients_connected() { return dlist_empty(&g_idle_list); }

static uint64_t idle_deadline_ms(Conn *conn) {
  return conn->last_active_ms + IDLE_TIMEOUT_MS;
}

static uint64_t read_deadline_ms(Conn *conn) {
  return conn->partial_read.last_read_ms + PARTIAL_READ_TIMEOUT_MS;
}

static uint64_t write_deadline_ms(Conn *conn) {
  return conn->partial_write.last_write_ms + PARTIAL_WRITE_TIMEOUT_MS;
}

int32_t next_timer_ms() {
  if (no_clients_connected()) {
    return -1; // no timers, no timeouts
  }
  uint64_t now_ms = get_monotonic_msec();
  Conn *conn = container_of(g_idle_list.next, Conn, idle_node);
  uint64_t next_ms = idle_deadline_ms(conn);
  if (!dlist_empty(&g_read_pending_list)) {
    Conn *pconn =
        container_of(g_read_pending_list.next, Conn, read_pending_node);
    uint64_t pnext_ms = read_deadline_ms(pconn);
    if (pnext_ms < next_ms) {
      next_ms = pnext_ms;
    }
  }

  if (!dlist_empty(&g_write_pending_list)) {
    Conn *pconn =
        container_of(g_write_pending_list.next, Conn, write_pending_node);
    uint64_t pnext_ms = write_deadline_ms(pconn);
    if (pnext_ms < next_ms) {
      next_ms = pnext_ms;
    }
  }

  if (next_ms <= now_ms) {
    return 0; // missed
  }
  return (int32_t)(next_ms - now_ms);
}

void process_timers(int epfd) {
  uint64_t now_ms = get_monotonic_msec();
  while (!dlist_empty(&g_idle_list)) {
    Conn *conn = container_of(g_idle_list.next, Conn, idle_node);
    uint64_t next_ms = idle_deadline_ms(conn);
    if (next_ms > now_ms) {
      break; // not expired
    }
    msg("Connection idle timeout");
    connection_destroy(conn->fd, epfd);
  }
  while (!dlist_empty(&g_read_pending_list)) {
    Conn *conn =
        container_of(g_read_pending_list.next, Conn, read_pending_node);
    uint64_t next_ms = read_deadline_ms(conn);
    if (next_ms > now_ms) {
      break; // not expired
    }
    msg("Connection partial read timeout");
    connection_destroy(conn->fd, epfd);
  }
  while (!dlist_empty(&g_write_pending_list)) {
    Conn *wconn =
        container_of(g_write_pending_list.next, Conn, write_pending_node);
    uint64_t wnext_ms = write_deadline_ms(wconn);
    if (wnext_ms > now_ms) {
      break; // not expired
    }
    msg("Connection partial write timeout");
    connection_destroy(wconn->fd, epfd);
  }
}
