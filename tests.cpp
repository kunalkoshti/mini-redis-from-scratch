/**
 * @file tests.cpp
 * @brief Integration tests for the mini-redis server.
 *
 * Requires a running server on localhost:1234.
 * Tests 1-4:   Protocol basics (pipelining, fragmentation, large payloads)
 * Tests 3.1-5: Hashmap operations (CRUD, rehashing, reconnect)
 * Tests 5-12:  Edge cases (concurrency, max payload, malformed requests)
 * Tests 13-17: Command coverage (errors, DEL returns, KEYS, arg counts, binary
 * safety) Tests 18-30: Typed values (SETINT, SETDBL, INCR, INCRBY, TYPE,
 * cross-type)
 */

#include "utils.h"
#include <algorithm>
#include <assert.h>
#include <cstring>
#include <endian.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

const size_t k_max_msg = 32 << 20;

enum {
  TAG_NIL = 0, // nil
  TAG_ERR = 1, // error code + msg
  TAG_STR = 2, // string
  TAG_INT = 3, // int64
  TAG_DBL = 4, // double
  TAG_ARR = 5, // array
};

/**
 * Encodes a command into the binary protocol format.
 */
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

/**
 * Sends a command request to the server.
 */
void send_request(int fd, const std::vector<std::string> &cmd) {
  std::vector<uint8_t> req;
  encode_cmd(req, cmd);

  uint32_t len = htonl(req.size());
  if (write_full(fd, (char *)&len, 4) != 0)
    die("write_full header");
  if (write_full(fd, (char *)req.data(), req.size()) != 0)
    die("write_full body");
}

/**
 * Reads and parses a typed response from the server.
 * Returns the payload as a string:
 *   TAG_NIL → ""
 *   TAG_STR → the string value
 *   TAG_INT → decimal string of the int64 value
 *   TAG_ERR → the error message
 *   TAG_DBL → decimal string of the double
 *   TAG_ARR → ""  (array contents are not returned)
 */
std::string read_response(int fd) {
  uint32_t len_net = 0;
  if (read_full(fd, (char *)&len_net, 4) != 0)
    die("read_full header");
  uint32_t len = ntohl(len_net);

  if (len > k_max_msg)
    die("response too big");

  std::vector<uint8_t> buf(len);
  if (read_full(fd, (char *)buf.data(), len) != 0)
    die("read_full body");

  if (len < 1)
    return "";

  switch (buf[0]) {
  case TAG_NIL:
    return "";
  case TAG_STR: {
    if (len < 1 + 4)
      return "";
    uint32_t slen = 0;
    memcpy(&slen, &buf[1], 4);
    slen = ntohl(slen);
    if (len < 1 + 4 + slen)
      return "";
    return std::string((char *)&buf[1 + 4], slen);
  }
  case TAG_INT: {
    if (len < 1 + 8)
      return "";
    int64_t val = 0;
    memcpy(&val, &buf[1], 8);
    val = (int64_t)be64toh((uint64_t)val);
    return std::to_string(val);
  }
  case TAG_DBL: {
    if (len < 1 + 8)
      return "";
    uint64_t tmp = 0;
    memcpy(&tmp, &buf[1], 8);
    tmp = be64toh(tmp);
    double val = 0;
    memcpy(&val, &tmp, 8);
    return std::to_string(val);
  }
  case TAG_ERR: {
    // TAG_ERR layout: [tag(1)] [code(4)] [msg_len(4)] [msg(msg_len)]
    if (len < 1 + 8)
      return "";
    uint32_t mlen = 0;
    memcpy(&mlen, &buf[1 + 4], 4);
    mlen = ntohl(mlen);
    if (len < 1 + 8 + mlen)
      return "";
    return std::string((char *)&buf[1 + 8], mlen);
  }
  case TAG_ARR:
    return "";
  default:
    return "";
  }
}

int main() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    die("socket");

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    die("connect");

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
  // Expect empty string (since our read_response returns "" for RES_NX/empty)
  assert(read_response(fd) == "");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.2] Hashmap: Update Existing Key... ";
  send_request(fd, {"set", "update_key", "val1"});
  read_response(fd);
  send_request(fd, {"set", "update_key", "val2"}); // Overwrite
  read_response(fd);
  send_request(fd, {"get", "update_key"});
  assert(read_response(fd) == "val2");
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 3.3] Hashmap: Delete Key... ";
  send_request(fd, {"del", "update_key"});
  assert(read_response(fd) == "1"); // TAG_INT: 1 = deleted
  send_request(fd, {"get", "update_key"});
  assert(read_response(fd) == ""); // TAG_NIL: gone
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
  // Verify a few elements to ensure rehashing didn't lose data
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

  std::cout << "\n--- TYPED RESPONSE & COMMAND COVERAGE TESTS ---\n"
            << std::endl;

  std::cout << "[Test 13] Unknown Command Returns TAG_ERR... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"bogus", "cmd"});
    std::string resp = read_response(temp_fd);
    assert(resp == "unknown command.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 14] DEL Return Values... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Insert then delete
    send_request(temp_fd, {"set", "del_test", "val"});
    read_response(temp_fd);
    send_request(temp_fd, {"del", "del_test"});
    assert(read_response(temp_fd) == "1"); // found & deleted
    // Double-delete should return 0
    send_request(temp_fd, {"del", "del_test"});
    assert(read_response(temp_fd) == "0"); // not found
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 15] KEYS Command... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Clear some known keys and set exactly 3
    send_request(temp_fd, {"set", "keys_a", "1"});
    read_response(temp_fd);
    send_request(temp_fd, {"set", "keys_b", "2"});
    read_response(temp_fd);
    send_request(temp_fd, {"set", "keys_c", "3"});
    read_response(temp_fd);

    // Read the KEYS response as raw bytes to verify TAG_ARR structure
    send_request(temp_fd, {"keys"});
    uint32_t len_net = 0;
    read_full(temp_fd, (char *)&len_net, 4);
    uint32_t len = ntohl(len_net);
    assert(len >= 1 + 4); // at least TAG_ARR + count
    std::vector<uint8_t> buf(len);
    read_full(temp_fd, (char *)buf.data(), len);
    assert(buf[0] == TAG_ARR);
    uint32_t arr_len = 0;
    memcpy(&arr_len, &buf[1], 4);
    arr_len = ntohl(arr_len);
    // We inserted 1000+ keys in Test 3.5, plus extras. Just check > 0.
    assert(arr_len > 0);
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 16] Wrong Argument Count... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // GET with wrong arg count
    send_request(temp_fd, {"get"});
    assert(read_response(temp_fd) == "unknown command.");
    // SET with wrong arg count
    send_request(temp_fd, {"set", "only_key"});
    assert(read_response(temp_fd) == "unknown command.");
    // DEL with wrong arg count
    send_request(temp_fd, {"del"});
    assert(read_response(temp_fd) == "unknown command.");
    // SETINT with wrong arg count
    send_request(temp_fd, {"setint", "only_key"});
    assert(read_response(temp_fd) == "unknown command.");
    // SETDBL with wrong arg count
    send_request(temp_fd, {"setdbl"});
    assert(read_response(temp_fd) == "unknown command.");
    // INCR with wrong arg count
    send_request(temp_fd, {"incr"});
    assert(read_response(temp_fd) == "unknown command.");
    // INCRBY with wrong arg count
    send_request(temp_fd, {"incrby", "key"});
    assert(read_response(temp_fd) == "unknown command.");
    // TYPE with wrong arg count
    send_request(temp_fd, {"type"});
    assert(read_response(temp_fd) == "unknown command.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 17] Binary-Safe Keys & Values... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Key and value with embedded null bytes
    std::string bin_key("bin\x00key", 7);
    std::string bin_val("val\x00ue\x01\x02", 8);
    send_request(temp_fd, {"set", bin_key, bin_val});
    read_response(temp_fd);
    send_request(temp_fd, {"get", bin_key});
    std::string resp = read_response(temp_fd);
    assert(resp.size() == bin_val.size());
    assert(resp == bin_val);
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\n--- TYPED VALUE TESTS ---\n" << std::endl;

  std::cout << "[Test 18] SETINT / GET Integer... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setint", "counter", "42"});
    assert(read_response(temp_fd) == ""); // nil = success
    send_request(temp_fd, {"get", "counter"});
    assert(read_response(temp_fd) == "42");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 19] SETINT Negative Value... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setint", "neg", "-100"});
    assert(read_response(temp_fd) == "");
    send_request(temp_fd, {"get", "neg"});
    assert(read_response(temp_fd) == "-100");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 20] SETINT Invalid Value... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setint", "bad", "not_a_number"});
    assert(read_response(temp_fd) == "invalid integer value.");
    send_request(temp_fd, {"setint", "bad2", "12.5"});
    assert(read_response(temp_fd) == "invalid integer value.");
    send_request(temp_fd, {"setint", "bad3", ""});
    assert(read_response(temp_fd) == "invalid integer value.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 21] SETDBL / GET Double... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setdbl", "pi", "3.14"});
    assert(read_response(temp_fd) == ""); // nil = success
    send_request(temp_fd, {"get", "pi"});
    std::string resp = read_response(temp_fd);
    // std::to_string(double) uses %f format → "3.140000"
    double got = std::stod(resp);
    assert(got > 3.139 && got < 3.141);
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 22] SETDBL Invalid & Inf/NaN... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setdbl", "bad", "hello"});
    assert(read_response(temp_fd) == "invalid double value.");
    send_request(temp_fd, {"setdbl", "bad", "inf"});
    assert(read_response(temp_fd) == "invalid double value.");
    send_request(temp_fd, {"setdbl", "bad", "-inf"});
    assert(read_response(temp_fd) == "invalid double value.");
    send_request(temp_fd, {"setdbl", "bad", "nan"});
    assert(read_response(temp_fd) == "invalid double value.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 23] INCR on Non-Existent Key... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Make sure key doesn't exist
    send_request(temp_fd, {"del", "incr_new"});
    read_response(temp_fd);
    send_request(temp_fd, {"incr", "incr_new"});
    assert(read_response(temp_fd) == "1");
    send_request(temp_fd, {"get", "incr_new"});
    assert(read_response(temp_fd) == "1");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 24] INCR on Existing Integer... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setint", "incr_ex", "10"});
    read_response(temp_fd);
    send_request(temp_fd, {"incr", "incr_ex"});
    assert(read_response(temp_fd) == "11");
    send_request(temp_fd, {"incr", "incr_ex"});
    assert(read_response(temp_fd) == "12");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 25] INCR on String Key → Type Error... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"set", "str_key", "hello"});
    read_response(temp_fd);
    send_request(temp_fd, {"incr", "str_key"});
    assert(read_response(temp_fd) == "value is not an integer.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 26] INCR on Double Key → Type Error... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    send_request(temp_fd, {"setdbl", "dbl_key", "2.5"});
    read_response(temp_fd);
    send_request(temp_fd, {"incr", "dbl_key"});
    assert(read_response(temp_fd) == "value is not an integer.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 27] INCRBY Various Cases... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Non-existent key → create with increment
    send_request(temp_fd, {"del", "ib_key"});
    read_response(temp_fd);
    send_request(temp_fd, {"incrby", "ib_key", "5"});
    assert(read_response(temp_fd) == "5");
    // Positive increment
    send_request(temp_fd, {"incrby", "ib_key", "10"});
    assert(read_response(temp_fd) == "15");
    // Negative increment (decrement)
    send_request(temp_fd, {"incrby", "ib_key", "-20"});
    assert(read_response(temp_fd) == "-5");
    // Invalid increment string
    send_request(temp_fd, {"incrby", "ib_key", "abc"});
    assert(read_response(temp_fd) == "invalid integer increment value.");
    // Type mismatch
    send_request(temp_fd, {"set", "ib_str", "hello"});
    read_response(temp_fd);
    send_request(temp_fd, {"incrby", "ib_str", "1"});
    assert(read_response(temp_fd) == "value is not an integer.");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 28] TYPE Command... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // String type
    send_request(temp_fd, {"set", "t_str", "hello"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "t_str"});
    assert(read_response(temp_fd) == "string");
    // Int type
    send_request(temp_fd, {"setint", "t_int", "99"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "t_int"});
    assert(read_response(temp_fd) == "int");
    // Double type
    send_request(temp_fd, {"setdbl", "t_dbl", "1.5"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "t_dbl"});
    assert(read_response(temp_fd) == "double");
    // Non-existent key → nil
    send_request(temp_fd, {"type", "no_such_key_type"});
    assert(read_response(temp_fd) == ""); // nil
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 29] Cross-Type Overwrite... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Start as string
    send_request(temp_fd, {"set", "cross", "hello"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "cross"});
    assert(read_response(temp_fd) == "string");
    // Overwrite with int
    send_request(temp_fd, {"setint", "cross", "42"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "cross"});
    assert(read_response(temp_fd) == "int");
    send_request(temp_fd, {"get", "cross"});
    assert(read_response(temp_fd) == "42");
    // Overwrite with double
    send_request(temp_fd, {"setdbl", "cross", "9.81"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "cross"});
    assert(read_response(temp_fd) == "double");
    // Overwrite back to string
    send_request(temp_fd, {"set", "cross", "back_to_str"});
    read_response(temp_fd);
    send_request(temp_fd, {"type", "cross"});
    assert(read_response(temp_fd) == "string");
    send_request(temp_fd, {"get", "cross"});
    assert(read_response(temp_fd) == "back_to_str");
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 30] DEL on Typed Values... ";
  {
    int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr));
    // Delete an int key
    send_request(temp_fd, {"setint", "del_int", "77"});
    read_response(temp_fd);
    send_request(temp_fd, {"del", "del_int"});
    assert(read_response(temp_fd) == "1");
    send_request(temp_fd, {"get", "del_int"});
    assert(read_response(temp_fd) == ""); // nil
    // Delete a double key
    send_request(temp_fd, {"setdbl", "del_dbl", "2.72"});
    read_response(temp_fd);
    send_request(temp_fd, {"del", "del_dbl"});
    assert(read_response(temp_fd) == "1");
    send_request(temp_fd, {"get", "del_dbl"});
    assert(read_response(temp_fd) == ""); // nil
    close(temp_fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! All tests passed (30/30).\n" << std::endl;
  return 0;
}