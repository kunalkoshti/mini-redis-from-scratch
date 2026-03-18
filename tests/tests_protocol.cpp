/**
 * @file tests_protocol.cpp
 * @brief Protocol and edge case integration tests.
 *
 * Requires a running server on localhost:1234.
 * Tests 1-4:  Protocol basics (pipelining, fragmentation, large payloads)
 * Tests 3.1-5: Hashmap operations (CRUD, rehashing, reconnect)
 * Tests 5-12: Edge cases (concurrency, max payload, malformed requests)
 *
 * Compile: g++ -O2 -Wall -Wextra tests_protocol.cpp utils.cpp -o tests_protocol
 */

#include "tests_helpers.h"

int main() {
  int fd = connect_to_server();

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
    assert(read_response(fd) == "");
  }
  std::cout << "PASSED" << std::endl;

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  std::cout << "[Test 2] Fragmentation (Byte-by-Byte)... ";
  std::vector<uint8_t> frag_req;
  encode_cmd(frag_req, {"get", "k1"});
  uint32_t frag_msg_len = htonl(frag_req.size());

  for (int i = 0; i < 4; ++i) {
    write(fd, (char *)&frag_msg_len + i, 1);
    usleep(1000);
  }
  for (uint8_t c : frag_req) {
    write(fd, &c, 1);
    usleep(1000);
  }
  assert(read_response(fd) == "v1");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3] 32MB Data Integrity... ";
  std::string big_data(31 * 1024 * 1024, 'z');
  send_request(fd, {"set", "bigkey", big_data});
  read_response(fd);

  send_request(fd, {"get", "bigkey"});
  std::string resp = read_response(fd);
  assert(resp.size() == big_data.size());
  assert(resp == big_data);
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.1] Hashmap: Get Non-Existent Key... ";
  send_request(fd, {"get", "does_not_exist"});
  assert(read_response(fd) == "");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.2] Hashmap: Update Existing Key... ";
  send_request(fd, {"set", "update_key", "val1"});
  read_response(fd);
  send_request(fd, {"set", "update_key", "val2"});
  read_response(fd);
  send_request(fd, {"get", "update_key"});
  assert(read_response(fd) == "val2");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.3] Hashmap: Delete Key... ";
  send_request(fd, {"del", "update_key"});
  assert(read_response(fd) == "1");
  send_request(fd, {"get", "update_key"});
  assert(read_response(fd) == "");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.4] Hashmap: Empty Keys & Values... ";
  send_request(fd, {"set", "", "empty_key_val"});
  read_response(fd);
  send_request(fd, {"get", ""});
  assert(read_response(fd) == "empty_key_val");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.5] Hashmap: Trigger Rehashing (1000 keys)... \n";
  for (int i = 0; i < 1000; i++) {
    send_request(fd,
                 {"set", "key" + std::to_string(i), "val" + std::to_string(i)});
    read_response(fd);
    if (i % 100 == 0)
      std::cout << "Inserted " << i << " keys\n";
  }
  send_request(fd, {"get", "key0"});
  assert(read_response(fd) == "val0");
  send_request(fd, {"get", "key500"});
  assert(read_response(fd) == "val500");
  send_request(fd, {"get", "key999"});
  assert(read_response(fd) == "val999");
  std::cout << "PASSED" << std::endl;

  close(fd);

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
    for (int temp_fd : fds) {
      close(temp_fd);
    }
    usleep(100000);
  }
  std::cout << "PASSED (Server did not crash)" << std::endl;

  std::cout << "[Test 6] Exceed Max Payload Size... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    uint32_t malicious_len = htonl(33 * 1024 * 1024);
    write_full(temp_fd, (char *)&malicious_len, 4);
    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 7] Write Blocking / Buffer Full... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    std::string mb_data(1024 * 1024, 'w');
    for (int i = 0; i < 10; ++i) {
      send_request(temp_fd, {"set", "mb", mb_data});
    }
    for (int i = 0; i < 10; ++i) {
      std::string resp = read_response(temp_fd);
      assert(resp.size() == 0);
    }
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

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

  std::cout << "[Test 9] Premature Client Disconnect... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    uint32_t fake_len = htonl(1000);
    write_full(temp_fd, (char *)&fake_len, 4);
    write_full(temp_fd, "hello", 5);
    close(temp_fd);
    usleep(100000);
  }
  std::cout << "PASSED (Server handled EOF)" << std::endl;

  std::cout << "[Test 10] Trailing Garbage Check... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    std::vector<std::string> req = {"get", "k1"};
    std::vector<uint8_t> raw_req;
    encode_cmd(raw_req, req);
    raw_req.push_back('b');
    raw_req.push_back('a');
    raw_req.push_back('d');
    uint32_t len = htonl(raw_req.size());
    write_full(temp_fd, (char *)&len, 4);
    write_full(temp_fd, (char *)raw_req.data(), raw_req.size());
    char dummy;
    int rv = read(temp_fd, &dummy, 1);
    assert(rv == 0 || (rv < 0 && errno == ECONNRESET));
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 11] Truncated String Parse Attack... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    std::vector<uint8_t> raw_req;
    uint32_t nstr = htonl(1);
    raw_req.insert(raw_req.end(), (uint8_t *)&nstr, (uint8_t *)&nstr + 4);
    uint32_t fake_str_len = htonl(5000);
    raw_req.insert(raw_req.end(), (uint8_t *)&fake_str_len,
                   (uint8_t *)&fake_str_len + 4);
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

  std::cout << "[Test 12] Max Args Limit Check... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    std::vector<uint8_t> raw_req;
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

  std::cout << "\nCongratulations! All protocol tests passed (12/12).\n"
            << std::endl;
  return 0;
}
