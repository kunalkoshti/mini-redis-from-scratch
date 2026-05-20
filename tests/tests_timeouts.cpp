/**
 * @file tests_timeouts.cpp
 * @brief Timeout behavior integration tests.
 *
 * Requires a running server on localhost:1234.
 *
 * Compile:
 *   g++ -O2 -Wall -Wextra -std=c++17 tests/tests_timeouts.cpp utils.cpp -o tests/tests_timeouts
 *
 * Run:
 *   ./tests/tests_timeouts
 */

#include "tests_helpers.h"
#include <chrono>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <thread>

static bool connection_closed(int fd) {
  uint8_t b = 0;
  ssize_t n = recv(fd, &b, 1, MSG_DONTWAIT);
  if (n == 0) {
    return true; // EOF
  }
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    return false; // still open, no data yet
  }
  return n < 0; // other errors treated as closed for this test
}

int main() {
  // Avoid SIGPIPE terminating process when writing to a timed-out socket.
  signal(SIGPIPE, SIG_IGN);

  std::cout << "\n--- TIMEOUT TESTS (SERVER MUST ALREADY BE RUNNING) ---\n"
            << std::endl;

  std::cout << "[Test 1] Idle Timeout Closes Persistent Connection... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "idle_t", "1"});
    (void)read_response(fd); // consume response

    std::this_thread::sleep_for(std::chrono::milliseconds(6200));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    assert(connection_closed(fd) && "expected connection closed by idle timeout");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 2] Partial Read Timeout Closes Connection... ";
  {
    int fd = connect_to_server();

    // Send only 2 bytes of the 4-byte frame header.
    uint8_t partial_hdr[2] = {0x00, 0x00};
    ssize_t w = send(fd, partial_hdr, sizeof(partial_hdr), 0);
    assert(w == (ssize_t)sizeof(partial_hdr));

    std::this_thread::sleep_for(std::chrono::milliseconds(3800));

    // Try to continue sending; server should already have timed out the socket.
    uint8_t rest_hdr[2] = {0x00, 0x01};
    (void)send(fd, rest_hdr, sizeof(rest_hdr), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    assert(connection_closed(fd) &&
           "expected connection closed by partial-read timeout");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3] Partial Write Timeout Closes Slow-Reader Connection... ";
  {
    int fd = connect_to_server();

    // Seed a large value so GET responses quickly build write backpressure.
    std::string big_value(256 * 1024, 'x');
    send_request(fd, {"set", "pw_key", big_value});
    (void)read_response(fd); // consume SET response

    // Pipeline GET requests but never read responses on this socket.
    for (int i = 0; i < 300; ++i) {
      send_request(fd, {"get", "pw_key"});
    }

    // Do not read; let server write side stall and timeout.
    std::this_thread::sleep_for(std::chrono::milliseconds(4200));

    // Closure can surface as EOF or write error; allow a brief retry window.
    bool closed = false;
    for (int i = 0; i < 20 && !closed; ++i) {
      if (connection_closed(fd)) {
        closed = true;
        break;
      }
      uint8_t b = 0;
      ssize_t w = send(fd, &b, 1, MSG_NOSIGNAL);
      if (w < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN)) {
        closed = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    assert(closed && "expected connection closed by partial-write timeout");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! Timeout tests passed (3/3).\n" << std::endl;
  return 0;
}
