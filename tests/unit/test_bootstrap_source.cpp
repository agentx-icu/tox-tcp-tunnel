#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include "toxtunnel/tox/bootstrap_source.hpp"

namespace toxtunnel::tox {
namespace {

class BootstrapSourceTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto unique_suffix =
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        temp_dir_ = std::filesystem::temp_directory_path() /
                    ("toxtunnel_bootstrap_source_test_" + unique_suffix);
        std::filesystem::remove_all(temp_dir_);
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override { std::filesystem::remove_all(temp_dir_); }

    void write_cache(const std::string& json) {
        const auto cache_path = BootstrapSource::cache_file_path(temp_dir_);
        std::filesystem::create_directories(cache_path.parent_path());
        std::ofstream out(cache_path);
        out << json;
    }

    std::filesystem::path temp_dir_;
};

TEST_F(BootstrapSourceTest, ParseNodesJsonPrefersOnlineUdpNodes) {
    const std::string json = R"({
  "nodes": [
    {
      "ipv4": "203.0.113.10",
      "port": 33445,
      "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "status_udp": true,
      "status_tcp": true
    },
    {
      "ipv4": "203.0.113.20",
      "port": 33445,
      "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "status_udp": false,
      "status_tcp": true
    },
    {
      "ipv6": "2001:db8::1234",
      "port": 33445,
      "public_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      "status_udp": true,
      "status_tcp": false
    }
  ]
})";

    auto result = BootstrapSource::parse_nodes_json(json, 8);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& nodes = result.value();
    ASSERT_EQ(nodes.size(), 2u);
    EXPECT_EQ(nodes[0].ip, "203.0.113.10");
    EXPECT_EQ(nodes[1].ip, "2001:db8::1234");
}

TEST_F(BootstrapSourceTest, ResolveBootstrapNodesUsesExplicitNodesWithoutFetching) {
    const auto explicit_pk =
        parse_public_key("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");
    ASSERT_TRUE(explicit_pk.has_value()) << explicit_pk.error();

    std::vector<BootstrapNode> configured = {
        BootstrapNode{"198.51.100.42", 33445, explicit_pk.value()}};

    bool fetch_called = false;
    auto result = BootstrapSource::resolve_bootstrap_nodes(
        configured, BootstrapMode::Auto, temp_dir_,
        [&fetch_called]() -> util::Expected<std::string, BootstrapFetchError> {
            fetch_called = true;
            return util::unexpected(BootstrapFetchError{std::string("should not fetch")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(result.value()[0].ip, "198.51.100.42");
    EXPECT_FALSE(fetch_called);
}

TEST_F(BootstrapSourceTest, ResolveBootstrapNodesFallsBackToCacheWhenFetchFails) {
    write_cache(R"([
  {
    "ipv4": "203.0.113.30",
    "port": 33445,
    "public_key": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    "status_udp": true,
    "status_tcp": true
  }
])");

    auto result = BootstrapSource::resolve_bootstrap_nodes(
        {}, BootstrapMode::Auto, temp_dir_,
        []() -> util::Expected<std::string, BootstrapFetchError> {
            return util::unexpected(BootstrapFetchError{std::string("network down")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(result.value()[0].ip, "203.0.113.30");
}

// C-15 / 2026-05-20 finding: when a usable cache exists,
// resolve_bootstrap_nodes must return immediately without waiting on the
// (potentially long-running) fetcher. The previous implementation blocked
// startup for up to 20 seconds on every boot. The fetcher is now invoked
// fire-and-forget for the next-run refresh; this test guards the
// no-block-on-cache-hit invariant.
TEST_F(BootstrapSourceTest, ResolveBootstrapNodesDoesNotBlockOnFetcherWhenCacheValid) {
    write_cache(R"([
  {
    "ipv4": "203.0.113.40",
    "port": 33445,
    "public_key": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "status_udp": true,
    "status_tcp": true
  }
])");

    std::atomic<bool> fetcher_called{false};
    auto slow_fetcher = [&fetcher_called]() -> util::Expected<std::string, BootstrapFetchError> {
        fetcher_called.store(true);
        // Pretend the network call takes 5s; the foreground path must not
        // wait for us.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return util::unexpected(BootstrapFetchError{std::string("slow")});
    };

    const auto t0 = std::chrono::steady_clock::now();
    auto result =
        BootstrapSource::resolve_bootstrap_nodes({}, BootstrapMode::Auto, temp_dir_, slow_fetcher);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(result.value()[0].ip, "203.0.113.40");

    // Generous bound — must be well under the 5s the fetcher would burn.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 500)
        << "resolve_bootstrap_nodes blocked on fetcher despite a valid cache";
}

TEST_F(BootstrapSourceTest, ResolveBootstrapNodesLanModeSkipsFetchAndCache) {
    write_cache(R"([
  {
    "ipv4": "203.0.113.30",
    "port": 33445,
    "public_key": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    "status_udp": true,
    "status_tcp": true
  }
])");

    bool fetch_called = false;
    auto result = BootstrapSource::resolve_bootstrap_nodes(
        {}, BootstrapMode::Lan, temp_dir_,
        [&fetch_called]() -> util::Expected<std::string, BootstrapFetchError> {
            fetch_called = true;
            return util::unexpected(BootstrapFetchError{std::string("should not fetch")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().empty());
    EXPECT_FALSE(fetch_called);
}

TEST_F(BootstrapSourceTest, ResolveBootstrapNodesLanModeReturnsExplicitNodes) {
    const auto explicit_pk =
        parse_public_key("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    ASSERT_TRUE(explicit_pk.has_value()) << explicit_pk.error();

    std::vector<BootstrapNode> configured = {
        BootstrapNode{"192.168.1.20", 33445, explicit_pk.value()}};

    bool fetch_called = false;
    auto result = BootstrapSource::resolve_bootstrap_nodes(
        configured, BootstrapMode::Lan, temp_dir_,
        [&fetch_called]() -> util::Expected<std::string, BootstrapFetchError> {
            fetch_called = true;
            return util::unexpected(BootstrapFetchError{std::string("should not fetch")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(result.value()[0].ip, "192.168.1.20");
    EXPECT_FALSE(fetch_called);
}

}  // namespace
}  // namespace toxtunnel::tox
