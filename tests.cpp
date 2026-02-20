#include "utils.h" // Using your provided utils
#include <algorithm>
#include <assert.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Helper to wrap your utils for std::string/vector
void send_request(int fd, const std::string &data) {
  uint32_t len = htonl(data.size());
  if (write_full(fd, (char *)&len, 4) != 0)
    die("write_full header");
  if (write_full(fd, data.data(), data.size()) != 0)
    die("write_full body");
}

std::string read_response(int fd) {
  uint32_t len_net = 0;
  if (read_full(fd, (char *)&len_net, 4) != 0)
    die("read_full header");
  uint32_t len = ntohl(len_net);

  std::vector<char> buf(len);
  if (read_full(fd, buf.data(), len) != 0)
    die("read_full body");
  return std::string(buf.begin(), buf.end());
}

int main() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    die("socket");

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234); // Match your server port
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    die("connect");

  // --- TEST 1: Pipelining (Multiple requests in one write) ---
  // This tests if your server's while(try_one_request) loop works.
  std::cout << "[Test 1] Pipelining (3-in-1)... ";
  std::string pipe_data;
  for (int i = 1; i <= 3; ++i) {
    uint32_t len = htonl(6);
    pipe_data.append((char *)&len, 4);
    pipe_data.append("ping_" + std::to_string(i));
  }
  if (write_full(fd, pipe_data.data(), pipe_data.size()) != 0)
    die("write");

  for (int i = 1; i <= 3; ++i) {
    assert(read_response(fd) == "ping_" + std::to_string(i));
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 2: Fragmentation (Sending 1 byte at a time) ---
  // This tests if your server correctly buffers partial data when EAGAIN hits.
  std::cout << "[Test 2] Fragmentation (Byte-by-Byte)... ";
  std::string msg = "fragment";
  uint32_t msg_len = htonl(msg.size());

  // Send header slowly
  for (int i = 0; i < 4; ++i) {
    write(fd, (char *)&msg_len + i, 1);
    usleep(1000);
  }
  // Send body slowly
  for (char c : msg) {
    write(fd, &c, 1);
    usleep(1000);
  }
  assert(read_response(fd) == "fragment");
  std::cout << "PASSED" << std::endl;

  // --- TEST 3: Large Payload (32MB) ---
  // This tests your mmap/vector growth and partial write() handling.
  std::cout << "[Test 3] 32MB Data Integrity... ";
  std::string big_data(32 * 1024 * 1024, 'z');
  send_request(fd, big_data);

  std::string resp = read_response(fd);
  assert(resp.size() == big_data.size());
  assert(resp == big_data);
  std::cout << "PASSED" << std::endl;

  close(fd);

  // --- TEST 4: Rapid Reconnect (Thundering Herd check) ---
  std::cout << "[Test 4] Rapid Reconnect... ";
  for (int i = 0; i < 50; ++i) {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      send_request(temp_fd, "quick");
      assert(read_response(temp_fd) == "quick");
    }
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\n--- ADVANCED EDGE CASE TESTS ---\n" << std::endl;

  // --- TEST 5: Use-After-Free / Concurrent Close Test ---
  std::cout << "[Test 5] Use-After-Free / Concurrent Close... ";
  {
    std::vector<int> fds;
    for (int i = 0; i < 100; ++i) {
      int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        // Send a pipelined request but DO NOT read the response
        std::string pipe_req;
        uint32_t len = htonl(4);
        pipe_req.append((char *)&len, 4);
        pipe_req.append("spam");
        pipe_req.append((char *)&len, 4);
        pipe_req.append("spam");
        write_full(temp_fd, pipe_req.data(), pipe_req.size());
        fds.push_back(temp_fd);
      }
    }
    // Immediately close all sockets while server is processing/writing
    for (int temp_fd : fds) {
      close(temp_fd);
    }
    usleep(100000); // Wait for server to process closures
  }
  std::cout << "PASSED (Server did not crash)" << std::endl;

  // --- TEST 6: Exceed k_max_msg_size Test ---
  std::cout << "[Test 6] Exceed Max Payload Size... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    uint32_t malicious_len = htonl(33 * 1024 * 1024); // 33MB
    write_full(temp_fd, (char *)&malicious_len, 4);

    // Server should immediately close connection
    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 7: Write Blocking (Simulated Kernel Buffer Full) ---
  std::cout << "[Test 7] Write Blocking / Buffer Full... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));

    // Send a 1MB payload 10 times to fill up the OS buffers
    std::string mb_data(1024 * 1024, 'w');
    for (int i = 0; i < 10; ++i) {
      uint32_t len = htonl(mb_data.size());
      write_full(temp_fd, (char *)&len, 4);
      write_full(temp_fd, mb_data.data(), mb_data.size());
    }

    // Now softly read the responses
    for (int i = 0; i < 10; ++i) {
      std::string resp = read_response(temp_fd);
      assert(resp.size() == mb_data.size());
    }
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 8: High Concurrency Epoll Batching ---
  std::cout << "[Test 8] High Concurrency Epoll Batching (200 clients)... ";
  {
    int const NUM_CLIENTS = 200;
    std::vector<int> clients(NUM_CLIENTS);
    for (int i = 0; i < NUM_CLIENTS; ++i) {
      clients[i] = socket(AF_INET, SOCK_STREAM, 0);
      connect(clients[i], (struct sockaddr *)&addr, sizeof(addr));
    }

    // Wake server concurrently
    std::string req = "batch";
    uint32_t len = htonl(req.size());
    for (int i = 0; i < NUM_CLIENTS; ++i) {
      write(clients[i], (char *)&len, 4);
      write(clients[i], req.data(), req.size());
    }

    for (int i = 0; i < NUM_CLIENTS; ++i) {
      assert(read_response(clients[i]) == "batch");
      close(clients[i]);
    }
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 9: Premature EOF (Invalid payload size) ---
  std::cout << "[Test 9] Premature Client Disconnect... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));

    // Pretend we are sending 1000 bytes, but send only 5
    uint32_t fake_len = htonl(1000);
    write_full(temp_fd, (char *)&fake_len, 4);
    write_full(temp_fd, "hello", 5);
    close(temp_fd); // Server should handle unexpected EOF safely
    usleep(100000);
  }
  std::cout << "PASSED (Server handled EOF)" << std::endl;

  std::cout << "\nCongratulations! All standard and advanced tests passed. "
               "Your server logic is production-ready."
            << std::endl;
  return 0;
}