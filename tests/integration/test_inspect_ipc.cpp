#include <gtest/gtest.h>

#ifndef _WIN32

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/core/io_context.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

namespace toxtunnel::integration {
namespace {

// Use a short /tmp path. macOS's $TMPDIR is too long to fit a Unix socket
// (sun_path == 104 bytes), so we sidestep std::filesystem::temp_directory_path.
std::filesystem::path temp_dir() {
    auto ts = std::chrono::steady_clock::now().time_since_epoch().count() % 1000000;
    std::filesystem::path path =
        std::filesystem::path("/tmp") /
        (std::string("ttinspint-") + std::to_string(::getpid()) + "-" + std::to_string(ts));
    std::filesystem::create_directories(path);
    return path;
}

std::string request_via_socket(const std::filesystem::path& sock_path, const std::string& line) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return {};
    }
    ::sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto p = sock_path.string();
    std::memcpy(addr.sun_path, p.data(), p.size());
    if (::connect(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return {};
    }
    ::write(fd, line.data(), line.size());
    std::string out;
    char buf[1024];
    ssize_t n = 0;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

// Boots an InspectServer on a real IoContext-backed thread pool and drives
// several concurrent inspect clients against it. Mirrors how the daemon
// hosts the inspect server during normal operation, minus the toxcore pieces.
TEST(InspectIpcIntegration, ParallelClientsAllSeeConsistentSnapshot) {
    core::IoContext io_pool(2);
    io_pool.run();

    auto data_dir = temp_dir();
    tunnel::TunnelManager manager(io_pool.get_io_context());

    app::InspectProviders providers;
    providers.mode = [] { return std::string("server"); };
    providers.version = [] { return std::string("0.0.0-int"); };
    providers.friends_online = []() -> std::size_t { return 0; };
    providers.friend_pk_prefix = [](uint16_t) -> std::string { return {}; };
    providers.snapshot = [&] { return manager.snapshot(); };

    app::InspectServer inspect;
    ASSERT_TRUE(inspect.start(io_pool.get_io_context(), data_dir, std::move(providers)));

    const auto sock_path = data_dir / "toxtunnel.sock";

    // 16 parallel clients exercises the accept loop and per-session shutdown
    // path under load — any race in stream reuse shows up as a partial or
    // empty reply.
    constexpr int kClients = 16;
    std::vector<std::thread> threads;
    std::atomic<int> successes{0};
    threads.reserve(kClients);
    for (int i = 0; i < kClients; ++i) {
        threads.emplace_back([&] {
            auto reply = request_via_socket(sock_path, "GET /tunnels\n");
            if (reply.find("\"tunnels\":[]") != std::string::npos) {
                ++successes;
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(successes.load(), kClients);

    inspect.stop();
    io_pool.stop();
    std::filesystem::remove_all(data_dir);
}

TEST(InspectIpcIntegration, StatusRequestReturnsValidJson) {
    core::IoContext io_pool(1);
    io_pool.run();

    auto data_dir = temp_dir();
    tunnel::TunnelManager manager(io_pool.get_io_context());

    app::InspectProviders providers;
    providers.mode = [] { return std::string("server"); };
    providers.version = [] { return std::string("0.0.0-int"); };
    providers.friends_online = []() -> std::size_t { return 2; };
    providers.snapshot = [&] { return manager.snapshot(); };

    app::InspectServer inspect;
    ASSERT_TRUE(inspect.start(io_pool.get_io_context(), data_dir, std::move(providers)));

    auto reply = request_via_socket(data_dir / "toxtunnel.sock", "GET /status\n");

    EXPECT_NE(reply.find("\"mode\":\"server\""), std::string::npos) << reply;
    EXPECT_NE(reply.find("\"friends_online\":2"), std::string::npos) << reply;

    inspect.stop();
    io_pool.stop();
    std::filesystem::remove_all(data_dir);
}

}  // namespace
}  // namespace toxtunnel::integration

#endif  // !_WIN32
