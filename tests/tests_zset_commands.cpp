/**
 * @file tests_zset_commands.cpp
 * @brief Integration tests for ZSet commands (ZADD, ZREM, ZSCORE, ZQUERY,
 *        ZRANK, ZCOUNT).
 *
 * Requires a running server on localhost:1234.
 * Tests cover basic CRUD, score updates, range queries, rank lookups,
 * count operations, type checking, and edge cases.
 *
 * Compile (from project root):
 *   g++ -O2 -Wall -Wextra tests/tests_zset_commands.cpp utils.cpp
 *       -o tests/tests_zset_commands
 */

#include "tests_helpers.h"

int main() {
  std::cout << "\n--- ZSET COMMAND TESTS ---\n" << std::endl;

  // ZSCORE on non-existent key returns nil
  std::cout << "[ZSet Test 1] ZSCORE on non-existent key... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zscore", "asdf", "n1"});
    assert(read_response(fd) == ""); // nil
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZQUERY on non-existent key returns empty array
  std::cout << "[ZSet Test 2] ZQUERY on non-existent key... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zquery", "xxx", "1", "asdf", "1", "10"});
    Response r = read_response_full(fd);
    assert(r.tag == TAG_ARR);
    assert(r.arr_len == 0);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZADD new members
  std::cout << "[ZSet Test 3] ZADD new members... " << std::flush;
  {
    int fd = connect_to_server();
    // Clean up from any previous run
    send_request(fd, {"del", "zset"});
    read_response(fd);

    send_request(fd, {"zadd", "zset", "1", "n1"});
    assert(read_response(fd) == "1"); // newly inserted
    send_request(fd, {"zadd", "zset", "2", "n2"});
    assert(read_response(fd) == "1"); // newly inserted
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZADD update existing (score change)
  std::cout << "[ZSet Test 4] ZADD score update... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zadd", "zset", "1.1", "n1"});
    assert(read_response(fd) == "0"); // updated, not new
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZSCORE returns updated score
  std::cout << "[ZSet Test 5] ZSCORE returns updated score... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zscore", "zset", "n1"});
    assert(read_response(fd) == "1.1");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZQUERY range query (ascending)
  std::cout << "[ZSet Test 6] ZQUERY range query ascending... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zquery", "zset", "1", "", "0", "10"});
    Response r = read_response_full(fd);
    assert(r.tag == TAG_ARR);
    assert(r.arr_len == 4); // n1(1.1), n2(2) → 4 items (name+score pairs)
    assert(r.arr_items[0].tag == TAG_STR);
    assert(r.arr_items[0].value == "n1");
    assert(r.arr_items[1].tag == TAG_DBL);
    assert(r.arr_items[1].value == "1.1");
    assert(r.arr_items[2].value == "n2");
    assert(r.arr_items[3].value == "2");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZQUERY with offset
  std::cout << "[ZSet Test 7] ZQUERY with offset... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zquery", "zset", "1.1", "", "1", "10"});
    Response r = read_response_full(fd);
    assert(r.tag == TAG_ARR);
    assert(r.arr_len == 2); // only n2(2)
    assert(r.arr_items[0].value == "n2");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZQUERY with large offset
  std::cout << "[ZSet Test 8] ZQUERY offset beyond range... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zquery", "zset", "1.1", "", "2", "10"});
    Response r = read_response_full(fd);
    assert(r.tag == TAG_ARR);
    assert(r.arr_len == 0);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZREM non-existent member
  std::cout << "[ZSet Test 9] ZREM non-existent member... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zrem", "zset", "adsf"});
    assert(read_response(fd) == "0");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZREM existing member
  std::cout << "[ZSet Test 10] ZREM existing member... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zrem", "zset", "n1"});
    assert(read_response(fd) == "1");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZQUERY after ZREM
  std::cout << "[ZSet Test 11] ZQUERY after ZREM... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zquery", "zset", "1", "", "0", "10"});
    Response r = read_response_full(fd);
    assert(r.tag == TAG_ARR);
    assert(r.arr_len == 2); // only n2(2)
    assert(r.arr_items[0].value == "n2");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZRANK
  std::cout << "[ZSet Test 12] ZRANK... " << std::flush;
  {
    int fd = connect_to_server();
    // Rebuild a fresh zset
    send_request(fd, {"del", "zset"});
    read_response(fd);
    send_request(fd, {"zadd", "zset", "10", "a"});
    read_response(fd);
    send_request(fd, {"zadd", "zset", "20", "b"});
    read_response(fd);
    send_request(fd, {"zadd", "zset", "30", "c"});
    read_response(fd);

    // rank of "a" should be 0
    send_request(fd, {"zrank", "zset", "a"});
    assert(read_response(fd) == "0");
    // rank of "b" should be 1
    send_request(fd, {"zrank", "zset", "b"});
    assert(read_response(fd) == "1");
    // rank of "c" should be 2
    send_request(fd, {"zrank", "zset", "c"});
    assert(read_response(fd) == "2");
    // rank of nonexistent member → nil
    send_request(fd, {"zrank", "zset", "x"});
    assert(read_response(fd) == ""); // nil
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZCOUNT [min, max)
  std::cout << "[ZSet Test 13] ZCOUNT [min, max)... " << std::flush;
  {
    int fd = connect_to_server();
    // zset has a(10), b(20), c(30) from above
    send_request(fd, {"zcount", "zset", "10", "30"});
    assert(read_response(fd) == "2"); // a(10), b(20) — 30 is excluded

    send_request(fd, {"zcount", "zset", "10", "31"});
    assert(read_response(fd) == "3"); // all three

    send_request(fd, {"zcount", "zset", "20", "20"});
    assert(read_response(fd) == "0"); // empty [20,20)

    send_request(fd, {"zcount", "zset", "100", "200"});
    assert(read_response(fd) == "0"); // no elements
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZSET TYPE for zset key
  std::cout << "[ZSet Test 14] TYPE on zset key... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"type", "zset"});
    assert(read_response(fd) == "zset");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // GET on zset key → type error
  std::cout << "[ZSet Test 15] GET on zset key → type error... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"get", "zset"});
    assert(read_response(fd) == "not a valid type");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZADD on string key → type error
  std::cout << "[ZSet Test 16] ZADD on string key → type error... "
            << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "strkey", "hello"});
    read_response(fd);
    send_request(fd, {"zadd", "strkey", "1.0", "member"});
    assert(read_response(fd) == "expect zset");
    // Clean up
    send_request(fd, {"del", "strkey"});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // DEL on zset key
  std::cout << "[ZSet Test 17] DEL on zset key... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"del", "zset"});
    assert(read_response(fd) == "1"); // deleted
    send_request(fd, {"zscore", "zset", "a"});
    assert(read_response(fd) == ""); // nil — gone
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZADD with invalid score
  std::cout << "[ZSet Test 18] ZADD with invalid score... " << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zadd", "z2", "notanumber", "m1"});
    assert(read_response(fd) == "invalid score value.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // Wrong argument counts
  std::cout << "[ZSet Test 19] Wrong argument counts... " << std::flush;
  {
    int fd = connect_to_server();
    // ZADD needs exactly 4 args
    send_request(fd, {"zadd", "z", "1"});
    assert(read_response(fd) == "unknown command.");
    // ZREM needs exactly 3 args
    send_request(fd, {"zrem", "z"});
    assert(read_response(fd) == "unknown command.");
    // ZSCORE needs exactly 3 args
    send_request(fd, {"zscore", "z"});
    assert(read_response(fd) == "unknown command.");
    // ZQUERY needs 6 or 7 args
    send_request(fd, {"zquery", "z"});
    assert(read_response(fd) == "unknown command.");
    // ZRANK needs exactly 3 args
    send_request(fd, {"zrank", "z"});
    assert(read_response(fd) == "unknown command.");
    // ZCOUNT needs exactly 4 args
    send_request(fd, {"zcount", "z", "1"});
    assert(read_response(fd) == "unknown command.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  // ZREM last element garbage-collects ZSet
  std::cout << "[ZSet Test 20] ZREM last element garbage-collects ZSet... "
            << std::flush;
  {
    int fd = connect_to_server();
    send_request(fd, {"zadd", "gc_zset", "1.0", "only"});
    read_response(fd);
    send_request(fd, {"zrem", "gc_zset", "only"});
    assert(read_response(fd) == "1");
    // Key should be completely gone now
    send_request(fd, {"type", "gc_zset"});
    assert(read_response(fd) == ""); // nil — key doesn't exist
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! All ZSet command tests passed (20/20).\n"
            << std::endl;
  return 0;
}
