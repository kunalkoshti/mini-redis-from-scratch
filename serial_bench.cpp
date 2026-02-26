#include "utils.h"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace std::chrono;

// Helper to serialize a command for the basic-key-value-server protocol
// Format: [total_len (4)] [n_args (4)] [[len (4)] [arg (len)]]...
vector<uint8_t> serialize_cmd(const vector<string> &args) {
  vector<uint8_t> out;
  uint32_t n_args = htonl(args.size());

  // Total length = 4 (for n_args) + sum of (4 + arg_len)
  uint32_t total_len = 4;
  for (const string &s : args)
    total_len += 4 + s.size();

  uint32_t total_len_net = htonl(total_len);
  out.insert(out.end(), (uint8_t *)&total_len_net,
             (uint8_t *)&total_len_net + 4);
  out.insert(out.end(), (uint8_t *)&n_args, (uint8_t *)&n_args + 4);

  for (const string &s : args) {
    uint32_t len = htonl(s.size());
    out.insert(out.end(), (uint8_t *)&len, (uint8_t *)&len + 4);
    out.insert(out.end(), (uint8_t *)s.data(), (uint8_t *)s.data() + s.size());
  }
  return out;
}

int main(int argc, char **argv) {
  int num_requests = (argc > 1) ? atoi(argv[1]) : 10000;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(1234)};
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    die("connect");

  int val = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  vector<long long> latencies;
  latencies.reserve(num_requests);

  // Payload: SET key value
  vector<uint8_t> req = serialize_cmd({"set", "key", "val"});

  for (int i = 0; i < num_requests; ++i) {
    if (i % 10000 == 0 && i > 0)
      cout << "Finished " << i << " requests..." << endl;

    auto begin = high_resolution_clock::now();

    if (write_full(fd, (char *)req.data(), req.size()) != 0)
      die("write req");

    uint32_t resp_len = 0;
    if (read_full(fd, (char *)&resp_len, 4) != 0)
      die("read resp_len EOF");

    vector<char> body(ntohl(resp_len));
    if (read_full(fd, body.data(), body.size()) != 0)
      die("read body EOF");

    auto end = high_resolution_clock::now();
    latencies.push_back(duration_cast<microseconds>(end - begin).count());
  }

  sort(latencies.begin(), latencies.end());
  cout << "P50: " << latencies[num_requests / 2] << " us | "
       << "P99: " << latencies[num_requests * 99 / 100] << " us" << endl;

  close(fd);
  return 0;
}
