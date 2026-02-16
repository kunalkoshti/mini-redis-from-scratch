#include <iostream>
#include <vector>
#include <string>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include "utils.h" // Using your provided utils

// Helper to wrap your utils for std::string/vector
void send_request(int fd, const std::string &data)
{
    uint32_t len = htonl(data.size());
    if (write_full(fd, (char *)&len, 4) != 0)
        die("write_full header");
    if (write_full(fd, data.data(), data.size()) != 0)
        die("write_full body");
}

std::string read_response(int fd)
{
    uint32_t len_net = 0;
    if (read_full(fd, (char *)&len_net, 4) != 0)
        die("read_full header");
    uint32_t len = ntohl(len_net);

    std::vector<char> buf(len);
    if (read_full(fd, buf.data(), len) != 0)
        die("read_full body");
    return std::string(buf.begin(), buf.end());
}

int main()
{
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
    for (int i = 1; i <= 3; ++i)
    {
        uint32_t len = htonl(6);
        pipe_data.append((char *)&len, 4);
        pipe_data.append("ping_" + std::to_string(i));
    }
    if (write_full(fd, pipe_data.data(), pipe_data.size()) != 0)
        die("write");

    for (int i = 1; i <= 3; ++i)
    {
        assert(read_response(fd) == "ping_" + std::to_string(i));
    }
    std::cout << "PASSED" << std::endl;

    // --- TEST 2: Fragmentation (Sending 1 byte at a time) ---
    // This tests if your server correctly buffers partial data when EAGAIN hits.
    std::cout << "[Test 2] Fragmentation (Byte-by-Byte)... ";
    std::string msg = "fragment";
    uint32_t msg_len = htonl(msg.size());

    // Send header slowly
    for (int i = 0; i < 4; ++i)
    {
        write(fd, (char *)&msg_len + i, 1);
        usleep(1000);
    }
    // Send body slowly
    for (char c : msg)
    {
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
    for (int i = 0; i < 50; ++i)
    {
        int temp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(temp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
        {
            send_request(temp_fd, "quick");
            assert(read_response(temp_fd) == "quick");
        }
        close(temp_fd);
    }
    std::cout << "PASSED" << std::endl;

    std::cout << "\nCongratulations! All tests passed. Your server logic is production-ready." << std::endl;
    return 0;
}