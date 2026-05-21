#include "timers.h"
#include "commands_internal.h"
#include "conn.h"
#include "list.h"
#include "utils.h"
#include <vector>

#define IDLE_TIMEOUT_MS (5 * 1000)
#define PARTIAL_READ_TIMEOUT_MS (2 * 1000)
#define PARTIAL_WRITE_TIMEOUT_MS (3 * 1000)
const size_t k_max_works = 2000;

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

  if (!g_data.heap.empty() && g_data.heap[0].val < next_ms) {
    // TTL heap is a global min-heap of key expiration timestamps.
    next_ms = g_data.heap[0].val;
  }

  if (next_ms <= now_ms) {
    return 0; // missed
  }
  return (int32_t)(next_ms - now_ms);
}

static bool hnode_same(HNode *node, HNode *key) { return node == key; }

static void process_idle_conn_timers(int epfd, uint64_t now_ms) {
  while (!dlist_empty(&g_idle_list)) {
    Conn *conn = container_of(g_idle_list.next, Conn, idle_node);
    uint64_t next_ms = idle_deadline_ms(conn);
    if (next_ms > now_ms) {
      break; // not expired
    }
    msg("Connection idle timeout");
    connection_destroy(conn->fd, epfd);
  }
}

static void process_partial_read_timers(int epfd, uint64_t now_ms) {
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
}

static void process_partial_write_timers(int epfd, uint64_t now_ms) {
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

static void process_key_ttl_timers(uint64_t now_ms) {
  size_t n_works = 0;
  const std::vector<HeapItem> &heap = g_data.heap;
  // Expire at most k_max_works keys per tick to bound worst-case latency.
  while (!heap.empty() && heap[0].val <= now_ms && n_works < k_max_works) {
    Entry *ent = container_of(heap[0].ref, Entry, heap_idx);
    HNode *node = hm_delete(&g_data.db, &ent->node, &hnode_same);
    if (node) {
      entry_del(ent);
    }

    n_works++;
  }
}

void process_timers(int epfd) {
  uint64_t now_ms = get_monotonic_msec();
  process_idle_conn_timers(epfd, now_ms);
  process_partial_read_timers(epfd, now_ms);
  process_partial_write_timers(epfd, now_ms);
  process_key_ttl_timers(now_ms);
}
