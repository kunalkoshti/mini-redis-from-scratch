#include "utils.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace std::chrono;

atomic<long> total_completed(0);

vector<uint8_t> serialize_cmd(const vector<string> &args) {
  vector<uint8_t> out;
  uint32_t n_args = htonl(args.size());
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

void client_thread(int id, int requests_per_thread) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(1234)};
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return;

  int val = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  vector<uint8_t> req = serialize_cmd({"set", "k", "v"});

  for (int i = 0; i < requests_per_thread; ++i) {
    if (write_full(fd, (char *)req.data(), req.size()) != 0)
      break;

    uint32_t resp_len;
    if (read_full(fd, (char *)&resp_len, 4) != 0)
      break;
    vector<char> buf(ntohl(resp_len));
    if (read_full(fd, buf.data(), buf.size()) != 0)
      break;

    total_completed++;
  }
  close(fd);
}

int main(int argc, char **argv) {
  int num_threads = (argc > 1) ? atoi(argv[1]) : 10;
  int req_per_thread = (argc > 2) ? atoi(argv[2]) : 1000;
  vector<thread> threads;

  auto start = high_resolution_clock::now();
  for (int i = 0; i < num_threads; ++i)
    threads.emplace_back(client_thread, i, req_per_thread);
  for (auto &t : threads)
    t.join();
  auto end = high_resolution_clock::now();

  double duration = duration_cast<milliseconds>(end - start).count() / 1000.0;
  cout << "Threads: " << num_threads
       << " | Throughput: " << (total_completed / duration) << " req/s" << endl;
  return 0;
}
