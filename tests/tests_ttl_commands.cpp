/**
 * @file tests_ttl_commands.cpp
 * @brief Integration tests for TTL commands (PTTL, PEXPIRE).
 *
 * Requires a running server on localhost:1234.
 *
 * Compile (from project root):
 *   g++ -O2 -Wall -Wextra -std=c++17 tests/tests_ttl_commands.cpp utils.cpp \
 *       -o tests/tests_ttl_commands
 *
 * Run:
 *   ./server_epoll
 *   ./tests/tests_ttl_commands
 */

#include "tests_helpers.h"

#include <chrono>
#include <thread>

static int64_t parse_i64(const std::string &s) {
  assert(!s.empty());
  return std::stoll(s);
}

static std::string uniq_key(const char *prefix) {
  // Keep it deterministic enough for debugging, but unique across runs.
  return std::string(prefix) + std::to_string((long long)getpid()) + "_" +
         std::to_string((unsigned long long)get_monotonic_msec());
}

int main() {
  std::cout << "\n--- TTL COMMAND TESTS (PTTL / PEXPIRE) ---\n" << std::endl;

  std::cout << "[TTL Test 1] PTTL on missing key returns nil... " << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pttl_missing_");
    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 2] PEXPIRE on missing key returns nil... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_missing_");
    send_request(fd, {"pexpire", k, "1000"});
    assert(read_response(fd) == "");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 3] PTTL on existing key without TTL returns -1... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pttl_no_ttl_");
    send_request(fd, {"set", k, "v"});
    assert(read_response(fd) == "");

    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "-1");

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 4] PEXPIRE invalid TTL returns TAG_ERR... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_bad_");
    send_request(fd, {"set", k, "v"});
    read_response(fd);

    send_request(fd, {"pexpire", k, "not_an_int"});
    assert(read_response(fd) == "invalid integer TTL value.");

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 5] PEXPIRE sets TTL; PTTL returns remaining ms... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_sets_");
    send_request(fd, {"set", k, "v"});
    read_response(fd);

    send_request(fd, {"pexpire", k, "5000"});
    assert(read_response(fd) == "1");

    send_request(fd, {"pttl", k});
    int64_t ttl = parse_i64(read_response(fd));
    assert(ttl > 0);
    assert(ttl <= 5000);

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 6] Expiry deletes key (PTTL becomes nil)... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_expires_");
    send_request(fd, {"set", k, "v"});
    read_response(fd);

    send_request(fd, {"pexpire", k, "200"});
    assert(read_response(fd) == "1");

    std::this_thread::sleep_for(std::chrono::milliseconds(350));

    send_request(fd, {"pttl", k});
    // With your current contract: missing key => nil.
    assert(read_response(fd) == "");

    send_request(fd, {"get", k});
    assert(read_response(fd) == "");

    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 7] Negative TTL removes TTL (acts like persist)... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_persist_");
    send_request(fd, {"set", k, "v"});
    read_response(fd);

    send_request(fd, {"pexpire", k, "5000"});
    assert(read_response(fd) == "1");

    send_request(fd, {"pexpire", k, "-1"});
    assert(read_response(fd) == "1");

    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "-1");

    send_request(fd, {"get", k});
    assert(read_response(fd) == "v");

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 8] DEL removes TTL (no stale TTL on recreate)... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("pexpire_del_recreate_");

    send_request(fd, {"set", k, "v1"});
    read_response(fd);
    send_request(fd, {"pexpire", k, "5000"});
    assert(read_response(fd) == "1");

    send_request(fd, {"del", k});
    assert(read_response(fd) == "1");

    send_request(fd, {"set", k, "v2"});
    read_response(fd);

    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "-1");

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 9] TTL works on zset keys (PTTL/PEXPIRE)... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("ttl_zset_");

    // Create a zset key
    send_request(fd, {"del", k});
    read_response(fd);
    send_request(fd, {"zadd", k, "1", "m1"});
    assert(read_response(fd) == "1");
    send_request(fd, {"zscore", k, "m1"});
    assert(read_response(fd) == "1");

    // Set TTL and ensure PTTL returns a positive value
    send_request(fd, {"pexpire", k, "5000"});
    assert(read_response(fd) == "1");
    send_request(fd, {"pttl", k});
    int64_t ttl = parse_i64(read_response(fd));
    assert(ttl > 0);
    assert(ttl <= 5000);

    // Remove TTL (your current semantics: negative TTL => persist)
    send_request(fd, {"pexpire", k, "-1"});
    assert(read_response(fd) == "1");
    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "-1");

    // Ensure the zset is still present and usable
    send_request(fd, {"zscore", k, "m1"});
    assert(read_response(fd) == "1");

    // cleanup
    send_request(fd, {"del", k});
    read_response(fd);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[TTL Test 10] Expiry deletes zset key (ZSCORE becomes nil)... "
            << std::flush;
  {
    int fd = connect_to_server();
    std::string k = uniq_key("ttl_zset_expires_");

    send_request(fd, {"del", k});
    read_response(fd);
    send_request(fd, {"zadd", k, "1", "m1"});
    assert(read_response(fd) == "1");

    send_request(fd, {"pexpire", k, "200"});
    assert(read_response(fd) == "1");

    std::this_thread::sleep_for(std::chrono::milliseconds(350));

    // missing key => nil
    send_request(fd, {"pttl", k});
    assert(read_response(fd) == "");
    send_request(fd, {"zscore", k, "m1"});
    assert(read_response(fd) == "");

    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! TTL command tests passed (10/10).\n"
            << std::endl;
  return 0;
}
