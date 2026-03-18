/**
 * @file tests_kv_commands.cpp
 * @brief KV command integration tests.
 *
 * Requires a running server on localhost:1234.
 * Tests 13-17: Command coverage (errors, DEL returns, KEYS, arg counts, binary
 *              safety)
 * Tests 18-30: Typed values (SETINT, SETDBL, INCR, INCRBY, TYPE, cross-type)
 *
 * Compile: g++ -O2 -Wall -Wextra tests_kv_commands.cpp utils.cpp
 *          -o tests_kv_commands
 */

#include "tests_helpers.h"

int main() {
  std::cout << "\n--- TYPED RESPONSE & COMMAND COVERAGE TESTS ---\n"
            << std::endl;

  std::cout << "[Test 13] Unknown Command Returns TAG_ERR... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"bogus", "cmd"});
    std::string resp = read_response(fd);
    assert(resp == "unknown command.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 14] DEL Return Values... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "del_test", "val"});
    read_response(fd);
    send_request(fd, {"del", "del_test"});
    assert(read_response(fd) == "1");
    send_request(fd, {"del", "del_test"});
    assert(read_response(fd) == "0");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 15] KEYS Command... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "keys_a", "1"});
    read_response(fd);
    send_request(fd, {"set", "keys_b", "2"});
    read_response(fd);
    send_request(fd, {"set", "keys_c", "3"});
    read_response(fd);

    send_request(fd, {"keys"});
    uint32_t len_net = 0;
    read_full(fd, (char *)&len_net, 4);
    uint32_t len = ntohl(len_net);
    assert(len >= 1 + 4);
    std::vector<uint8_t> buf(len);
    read_full(fd, (char *)buf.data(), len);
    assert(buf[0] == TAG_ARR);
    uint32_t arr_len = 0;
    memcpy(&arr_len, &buf[1], 4);
    arr_len = ntohl(arr_len);
    assert(arr_len > 0);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 16] Wrong Argument Count... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"get"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"set", "only_key"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"del"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"setint", "only_key"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"setdbl"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"incr"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"incrby", "key"});
    assert(read_response(fd) == "unknown command.");
    send_request(fd, {"type"});
    assert(read_response(fd) == "unknown command.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 17] Binary-Safe Keys & Values... ";
  {
    int fd = connect_to_server();
    std::string bin_key("bin\x00key", 7);
    std::string bin_val("val\x00ue\x01\x02", 8);
    send_request(fd, {"set", bin_key, bin_val});
    read_response(fd);
    send_request(fd, {"get", bin_key});
    std::string resp = read_response(fd);
    assert(resp.size() == bin_val.size());
    assert(resp == bin_val);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\n--- TYPED VALUE TESTS ---\n" << std::endl;

  std::cout << "[Test 18] SETINT / GET Integer... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setint", "counter", "42"});
    assert(read_response(fd) == "");
    send_request(fd, {"get", "counter"});
    assert(read_response(fd) == "42");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 19] SETINT Negative Value... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setint", "neg", "-100"});
    assert(read_response(fd) == "");
    send_request(fd, {"get", "neg"});
    assert(read_response(fd) == "-100");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 20] SETINT Invalid Value... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setint", "bad", "not_a_number"});
    assert(read_response(fd) == "invalid integer value.");
    send_request(fd, {"setint", "bad2", "12.5"});
    assert(read_response(fd) == "invalid integer value.");
    send_request(fd, {"setint", "bad3", ""});
    assert(read_response(fd) == "invalid integer value.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 21] SETDBL / GET Double... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setdbl", "pi", "3.14"});
    assert(read_response(fd) == "");
    send_request(fd, {"get", "pi"});
    std::string resp = read_response(fd);
    double got = std::stod(resp);
    assert(got > 3.139 && got < 3.141);
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 22] SETDBL Invalid & Inf/NaN... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setdbl", "bad", "hello"});
    assert(read_response(fd) == "invalid double value.");
    send_request(fd, {"setdbl", "bad", "inf"});
    assert(read_response(fd) == "invalid double value.");
    send_request(fd, {"setdbl", "bad", "-inf"});
    assert(read_response(fd) == "invalid double value.");
    send_request(fd, {"setdbl", "bad", "nan"});
    assert(read_response(fd) == "invalid double value.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 23] INCR on Non-Existent Key... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"del", "incr_new"});
    read_response(fd);
    send_request(fd, {"incr", "incr_new"});
    assert(read_response(fd) == "1");
    send_request(fd, {"get", "incr_new"});
    assert(read_response(fd) == "1");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 24] INCR on Existing Integer... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setint", "incr_ex", "10"});
    read_response(fd);
    send_request(fd, {"incr", "incr_ex"});
    assert(read_response(fd) == "11");
    send_request(fd, {"incr", "incr_ex"});
    assert(read_response(fd) == "12");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 25] INCR on String Key → Type Error... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "str_key", "hello"});
    read_response(fd);
    send_request(fd, {"incr", "str_key"});
    assert(read_response(fd) == "value is not an integer.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 26] INCR on Double Key → Type Error... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setdbl", "dbl_key", "2.5"});
    read_response(fd);
    send_request(fd, {"incr", "dbl_key"});
    assert(read_response(fd) == "value is not an integer.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 27] INCRBY Various Cases... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"del", "ib_key"});
    read_response(fd);
    send_request(fd, {"incrby", "ib_key", "5"});
    assert(read_response(fd) == "5");
    send_request(fd, {"incrby", "ib_key", "10"});
    assert(read_response(fd) == "15");
    send_request(fd, {"incrby", "ib_key", "-20"});
    assert(read_response(fd) == "-5");
    send_request(fd, {"incrby", "ib_key", "abc"});
    assert(read_response(fd) == "invalid integer increment value.");
    send_request(fd, {"set", "ib_str", "hello"});
    read_response(fd);
    send_request(fd, {"incrby", "ib_str", "1"});
    assert(read_response(fd) == "value is not an integer.");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 28] TYPE Command... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "t_str", "hello"});
    read_response(fd);
    send_request(fd, {"type", "t_str"});
    assert(read_response(fd) == "string");
    send_request(fd, {"setint", "t_int", "99"});
    read_response(fd);
    send_request(fd, {"type", "t_int"});
    assert(read_response(fd) == "int");
    send_request(fd, {"setdbl", "t_dbl", "1.5"});
    read_response(fd);
    send_request(fd, {"type", "t_dbl"});
    assert(read_response(fd) == "double");
    send_request(fd, {"type", "no_such_key_type"});
    assert(read_response(fd) == "");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 29] Cross-Type Overwrite... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"set", "cross", "hello"});
    read_response(fd);
    send_request(fd, {"type", "cross"});
    assert(read_response(fd) == "string");
    send_request(fd, {"setint", "cross", "42"});
    read_response(fd);
    send_request(fd, {"type", "cross"});
    assert(read_response(fd) == "int");
    send_request(fd, {"get", "cross"});
    assert(read_response(fd) == "42");
    send_request(fd, {"setdbl", "cross", "9.81"});
    read_response(fd);
    send_request(fd, {"type", "cross"});
    assert(read_response(fd) == "double");
    send_request(fd, {"set", "cross", "back_to_str"});
    read_response(fd);
    send_request(fd, {"type", "cross"});
    assert(read_response(fd) == "string");
    send_request(fd, {"get", "cross"});
    assert(read_response(fd) == "back_to_str");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "[Test 30] DEL on Typed Values... ";
  {
    int fd = connect_to_server();
    send_request(fd, {"setint", "del_int", "77"});
    read_response(fd);
    send_request(fd, {"del", "del_int"});
    assert(read_response(fd) == "1");
    send_request(fd, {"get", "del_int"});
    assert(read_response(fd) == "");
    send_request(fd, {"setdbl", "del_dbl", "2.72"});
    read_response(fd);
    send_request(fd, {"del", "del_dbl"});
    assert(read_response(fd) == "1");
    send_request(fd, {"get", "del_dbl"});
    assert(read_response(fd) == "");
    close(fd);
  }
  std::cout << "PASSED" << std::endl;

  std::cout << "\nCongratulations! All KV command tests passed (18/18).\n"
            << std::endl;
  return 0;
}
