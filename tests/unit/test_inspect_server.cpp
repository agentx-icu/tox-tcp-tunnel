#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/tunnel/tunnel_manager.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

using namespace toxtunnel;
using app::InspectProviders;
using app::InspectServer;

namespace {

InspectProviders make_providers_with_one_tunnel() {
    InspectProviders p;
    p.mode = [] { return std::string("server"); };
    p.version = [] { return std::string("0.0.0-test"); };
    p.friends_online = []() -> std::size_t { return 1; };
    p.friend_pk_prefix = [](uint16_t) -> std::string { return std::string("AABBCCDD"); };
    p.snapshot = []() -> tunnel::ManagerSnapshot {
        tunnel::ManagerSnapshot snap;
        snap.bytes_in = 1234;
        snap.bytes_out = 5678;
        snap.frames_in = 7;
        snap.frames_out = 9;
        tunnel::TunnelSnapshot t;
        t.id = 1;
        t.target_host = "127.0.0.1";
        t.target_port = 22;
        t.state = "Connected";
        t.bytes_in = 1234;
        t.bytes_out = 5678;
        t.idle_seconds = std::chrono::seconds(3);
        snap.tunnels.push_back(t);
        return snap;
    };
    return p;
}

#ifndef _WIN32
// Use short paths under /tmp directly — macOS's $TMPDIR
// (/var/folders/.../T/) plus our nested name pushes sun_path past its 104B
// limit on darwin. The test tag is enough to keep parallel tests from
// colliding.
std::filesystem::path unique_temp_dir(std::string_view tag) {
    auto ts = std::chrono::steady_clock::now().time_since_epoch().count() % 1000000;
    std::filesystem::path path =
        std::filesystem::path("/tmp") / (std::string("ttinsp-") + std::string(tag) + "-" +
                                         std::to_string(::getpid()) + "-" + std::to_string(ts));
    std::filesystem::create_directories(path);
    return path;
}

std::string send_request(const std::filesystem::path& sock_path, const std::string& line) {
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
    // GCC's -Wunused-result is intentionally not suppressed by (void) /
    // static_cast<void> — assign to a [[maybe_unused]] sink instead.
    [[maybe_unused]] auto write_rc = ::write(fd, line.data(), line.size());
    std::string out;
    char buf[1024];
    ssize_t n = 0;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}
#endif

}  // namespace

// ===========================================================================
// JSON shape tests — exercise the platform-independent rendering directly.
// ===========================================================================

TEST(InspectServerJson, TunnelsContainsExpectedFields) {
    auto providers = make_providers_with_one_tunnel();
    const auto json = InspectServer::render_tunnels_json(providers);

    EXPECT_NE(json.find("\"mode\":\"server\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"version\":\"0.0.0-test\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"friends_online\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"tunnels\":["), std::string::npos) << json;
    EXPECT_NE(json.find("\"id\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"target\":\"127.0.0.1:22\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"state\":\"Connected\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"bytes_in\":1234"), std::string::npos) << json;
    EXPECT_NE(json.find("\"bytes_out\":5678"), std::string::npos) << json;
    EXPECT_NE(json.find("\"idle_seconds\":3"), std::string::npos) << json;
    EXPECT_NE(json.find("\"friend_pk_prefix\":\"AABBCCDD\""), std::string::npos) << json;
}

TEST(InspectServerJson, StatusContainsExpectedFields) {
    auto providers = make_providers_with_one_tunnel();
    const auto json = InspectServer::render_status_json(providers);

    EXPECT_NE(json.find("\"mode\":\"server\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"friends_online\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"tunnels_active\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"bytes_in\":1234"), std::string::npos) << json;
    EXPECT_NE(json.find("\"bytes_out\":5678"), std::string::npos) << json;
}

TEST(InspectServerJson, ErrorRendersWellFormedObject) {
    const auto json = InspectServer::render_error_json("bad request");
    EXPECT_EQ(json, std::string("{\"error\":\"bad request\"}"));
}

TEST(InspectServerJson, TunnelsEmptyWhenNoTunnels) {
    InspectProviders providers;
    providers.mode = [] { return std::string("client"); };
    providers.snapshot = []() -> tunnel::ManagerSnapshot { return {}; };
    const auto json = InspectServer::render_tunnels_json(providers);
    EXPECT_NE(json.find("\"tunnels\":[]"), std::string::npos) << json;
}

TEST(InspectServerJson, IdleSecondsOmittedWhenZero) {
    InspectProviders providers;
    providers.snapshot = []() -> tunnel::ManagerSnapshot {
        tunnel::ManagerSnapshot snap;
        tunnel::TunnelSnapshot t;
        t.id = 7;
        t.target_host = "h";
        t.target_port = 1;
        t.state = "Connecting";
        t.idle_seconds = std::chrono::seconds(0);
        snap.tunnels.push_back(t);
        return snap;
    };
    const auto json = InspectServer::render_tunnels_json(providers);
    EXPECT_EQ(json.find("idle_seconds"), std::string::npos) << json;
}

// ===========================================================================
// POSIX-only IPC tests — exercise the AF_UNIX bind/accept/reply path.
// ===========================================================================

#ifndef _WIN32

TEST(InspectServerSocket, AcceptsTunnelsRequestAndReturnsJson) {
    asio::io_context io_ctx;
    auto data_dir = unique_temp_dir("ok");

    InspectServer server;
    ASSERT_TRUE(server.start(io_ctx, data_dir, make_providers_with_one_tunnel()))
        << "start should succeed";

    std::thread worker([&] {
        auto guard = asio::make_work_guard(io_ctx);
        io_ctx.run();
    });

    auto reply = send_request(data_dir / "toxtunnel.sock", "GET /tunnels\n");

    server.stop();
    io_ctx.stop();
    worker.join();

    EXPECT_NE(reply.find("\"tunnels\":["), std::string::npos) << reply;
    EXPECT_NE(reply.find("\"id\":1"), std::string::npos) << reply;

    std::filesystem::remove_all(data_dir);
}

TEST(InspectServerSocket, StaleSocketFileIsUnlinkedOnStart) {
    asio::io_context io_ctx;
    auto data_dir = unique_temp_dir("stale");

    // Drop a stale regular file at the socket path — simulates a daemon
    // crash that left the leftover on disk.
    const auto sock_path = data_dir / "toxtunnel.sock";
    {
        std::ofstream stale(sock_path);
        stale << "leftover";
    }
    ASSERT_TRUE(std::filesystem::exists(sock_path));

    InspectServer server;
    ASSERT_TRUE(server.start(io_ctx, data_dir, make_providers_with_one_tunnel()))
        << "start must clear a stale path and rebind";

    // After start, the path exists and is a socket (not the old regular file).
    struct stat st {};
    ASSERT_EQ(::stat(sock_path.c_str(), &st), 0);
    EXPECT_TRUE(S_ISSOCK(st.st_mode)) << "path should be a socket after rebind";

    server.stop();
    io_ctx.stop();
    std::filesystem::remove_all(data_dir);
}

TEST(InspectServerSocket, InvalidRequestLineProducesErrorJson) {
    asio::io_context io_ctx;
    auto data_dir = unique_temp_dir("invalid");

    InspectServer server;
    ASSERT_TRUE(server.start(io_ctx, data_dir, make_providers_with_one_tunnel()));

    std::thread worker([&] {
        auto guard = asio::make_work_guard(io_ctx);
        io_ctx.run();
    });

    auto reply = send_request(data_dir / "toxtunnel.sock", "GET /garbage\n");

    server.stop();
    io_ctx.stop();
    worker.join();

    EXPECT_NE(reply.find("\"error\""), std::string::npos) << reply;
    std::filesystem::remove_all(data_dir);
}

TEST(InspectServerSocket, StopUnlinksSocketFile) {
    asio::io_context io_ctx;
    auto data_dir = unique_temp_dir("unlink");

    InspectServer server;
    ASSERT_TRUE(server.start(io_ctx, data_dir, make_providers_with_one_tunnel()));
    const auto sock_path = data_dir / "toxtunnel.sock";
    ASSERT_TRUE(std::filesystem::exists(sock_path));

    server.stop();
    io_ctx.stop();

    EXPECT_FALSE(std::filesystem::exists(sock_path))
        << "stop() should unlink the socket so it doesn't look like a stale daemon";
    std::filesystem::remove_all(data_dir);
}

#endif  // !_WIN32
