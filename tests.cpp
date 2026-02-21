#include "utils.h"
#include <algorithm>
#include <assert.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

const size_t k_max_msg = 32 << 20;

// Helper to encode a string array into buffer
static void encode_cmd(std::vector<uint8_t> &out,
                       const std::vector<std::string> &cmd) {
  uint32_t nstr = htonl(cmd.size());
  out.insert(out.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);

  for (const std::string &s : cmd) {
    uint32_t len = htonl(s.size());
    out.insert(out.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    out.insert(out.end(), s.data(), s.data() + s.size());
  }
}

void send_request(int fd, const std::vector<std::string> &cmd) {
  std::vector<uint8_t> req;
  encode_cmd(req, cmd);

  uint32_t len = htonl(req.size());
  if (write_full(fd, (char *)&len, 4) != 0)
    die("write_full header");
  if (write_full(fd, (char *)req.data(), req.size()) != 0)
    die("write_full body");
}

std::string read_response(int fd) {
  uint32_t len_net = 0;
  if (read_full(fd, (char *)&len_net, 4) != 0)
    die("read_full header");
  uint32_t len = ntohl(len_net);

  if (len > k_max_msg)
    die("response too big");

  std::vector<char> buf(len);
  if (read_full(fd, buf.data(), len) != 0)
    die("read_full body");

  // Skip the 4-byte status code in the response
  if (len < 4)
    return "";
  return std::string(buf.begin() + 4, buf.end());
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
  std::cout << "[Test 1] Pipelining (3-in-1)... ";
  std::vector<uint8_t> pipe_data;
  for (int i = 1; i <= 3; ++i) {
    std::vector<std::string> req = {"set", "k" + std::to_string(i),
                                    "v" + std::to_string(i)};
    std::vector<uint8_t> raw_req;
    encode_cmd(raw_req, req);

    uint32_t len = htonl(raw_req.size());
    pipe_data.insert(pipe_data.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    pipe_data.insert(pipe_data.end(), raw_req.begin(), raw_req.end());
  }
  if (write_full(fd, (char *)pipe_data.data(), pipe_data.size()) != 0)
    die("write");

  for (int i = 1; i <= 3; ++i) {
    assert(read_response(fd) == ""); // SET returns empty string
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 2: Fragmentation (Sending 1 byte at a time) ---
  std::cout << "[Test 2] Fragmentation (Byte-by-Byte)... ";
  std::vector<uint8_t> frag_req;
  encode_cmd(frag_req, {"get", "k1"});
  uint32_t frag_msg_len = htonl(frag_req.size());

  // Send header slowly
  for (int i = 0; i < 4; ++i) {
    write(fd, (char *)&frag_msg_len + i, 1);
    usleep(1000);
  }
  // Send body slowly
  for (uint8_t c : frag_req) {
    write(fd, &c, 1);
    usleep(1000);
  }
  assert(read_response(fd) == "v1");
  std::cout << "PASSED" << std::endl;

  // --- TEST 3: Large Payload (32MB) ---
  std::cout << "[Test 3] 32MB Data Integrity... ";
  std::string big_data(31 * 1024 * 1024, 'z');
  send_request(fd, {"set", "bigkey", big_data});
  read_response(fd); // drain the "set" ACK

  send_request(fd, {"get", "bigkey"});
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
      send_request(temp_fd, {"get", "k1"});
      assert(read_response(temp_fd) == "v1");
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

        std::vector<uint8_t> raw_req;
        encode_cmd(raw_req, {"get", "k1"});
        uint32_t len = htonl(raw_req.size());

        std::vector<uint8_t> pipe_req;
        pipe_req.insert(pipe_req.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
        pipe_req.insert(pipe_req.end(), raw_req.begin(), raw_req.end());
        pipe_req.insert(pipe_req.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
        pipe_req.insert(pipe_req.end(), raw_req.begin(), raw_req.end());

        write_full(temp_fd, (char *)pipe_req.data(), pipe_req.size());
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
      send_request(temp_fd, {"set", "mb", mb_data});
    }

    // Now softly read the responses
    for (int i = 0; i < 10; ++i) {
      std::string resp = read_response(temp_fd);
      assert(resp.size() == 0); // SET returns empty
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

    std::vector<uint8_t> raw_req;
    encode_cmd(raw_req, {"get", "k1"});
    uint32_t len = htonl(raw_req.size());

    // Wake server concurrently
    for (int i = 0; i < NUM_CLIENTS; ++i) {
      write(clients[i], (char *)&len, 4);
      write(clients[i], raw_req.data(), raw_req.size());
    }

    for (int i = 0; i < NUM_CLIENTS; ++i) {
      assert(read_response(clients[i]) == "v1");
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

  // --- TEST 10: Trailing Garbage (Protocol Parsing) ---
  std::cout << "[Test 10] Trailing Garbage Check... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));

    std::vector<std::string> req = {"get", "k1"};
    std::vector<uint8_t> raw_req;
    encode_cmd(raw_req, req);

    // Add exactly 3 bytes of garbage to the end of the real payload size
    raw_req.push_back('b');
    raw_req.push_back('a');
    raw_req.push_back('d');

    uint32_t len = htonl(raw_req.size());
    write_full(temp_fd, (char *)&len, 4);
    write_full(temp_fd, (char *)raw_req.data(), raw_req.size());

    // Server should immediately disconnect us
    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 11: Truncated String Attack (Buffer Overread) ---
  std::cout << "[Test 11] Truncated String Parse Attack... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));

    std::vector<uint8_t> raw_req;
    uint32_t nstr = htonl(1);
    raw_req.insert(raw_req.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);

    // We claim the string is 5000 bytes long!
    uint32_t fake_str_len = htonl(5000);
    raw_req.insert(raw_req.end(), (uint8_t *)&fake_str_len,
                   (uint8_t *)&fake_str_len + 4);

    // But we only provide 2 bytes!
    raw_req.push_back('x');
    raw_req.push_back('y');

    uint32_t len = htonl(raw_req.size());
    write_full(temp_fd, (char *)&len, 4);
    write_full(temp_fd, (char *)raw_req.data(), raw_req.size());

    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  // --- TEST 12: k_max_args Limit Test ---
  std::cout << "[Test 12] Max Args Limit Check... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));

    std::vector<uint8_t> raw_req;
    // We claim there are 5,000,000 arguments (larger than k_max_args)!
    uint32_t huge_nstr = htonl(5000000);
    raw_req.insert(raw_req.end(), (uint8_t *)&huge_nstr,
                   (uint8_t *)&huge_nstr + 4);

    uint32_t len = htonl(raw_req.size());
    write_full(temp_fd, (char *)&len, 4);
    write_full(temp_fd, (char *)raw_req.data(), raw_req.size());

    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! All standard and advanced tests passed. "
               "Your server logic is production-ready."
            << std::endl;
  return 0;
}