#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <string>

#include "toxtunnel/tox/tox_adapter.hpp"

namespace toxtunnel::tox {
namespace {

TEST(ToxAdapterTest, DispatchesQueuedFriendRequestCallbacksOnlyWhenDrained) {
    ToxAdapter adapter;

    bool called = false;
    std::string observed_message;
    adapter.set_on_friend_request(
        [&called, &observed_message](const PublicKeyArray&, std::string_view message) {
            called = true;
            observed_message = std::string(message);
        });

    PublicKeyArray public_key{};
    public_key.fill(0x42);

    adapter.enqueue_friend_request_for_test(public_key, "hello");
    EXPECT_FALSE(called);

    adapter.dispatch_pending_events_for_test();
    EXPECT_TRUE(called);
    EXPECT_EQ(observed_message, "hello");
}

TEST(ToxAdapterTest, ResolveBootstrapNodesForConfigSkipsFetchInLanModeWithoutNodes) {
    ToxAdapterConfig config;
    config.bootstrap_mode = BootstrapMode::Lan;
    config.local_discovery_enabled = true;
    config.data_dir = "/tmp/toxtunnel_tox_adapter_test";

    bool fetch_called = false;
    auto result = ToxAdapter::resolve_bootstrap_nodes_for_config(
        config, [&fetch_called]() -> util::Expected<std::string, BootstrapFetchError> {
            fetch_called = true;
            return util::unexpected(BootstrapFetchError{std::string("should not fetch")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().empty());
    EXPECT_FALSE(fetch_called);
}

TEST(ToxAdapterTest, ResolveBootstrapNodesForConfigKeepsConfiguredLanNodes) {
    ToxAdapterConfig config;
    config.bootstrap_mode = BootstrapMode::Lan;
    config.local_discovery_enabled = true;

    auto public_key =
        parse_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    ASSERT_TRUE(public_key.has_value()) << public_key.error();
    config.bootstrap_nodes.push_back(BootstrapNode{"192.168.1.20", 33445, public_key.value()});

    bool fetch_called = false;
    auto result = ToxAdapter::resolve_bootstrap_nodes_for_config(
        config, [&fetch_called]() -> util::Expected<std::string, BootstrapFetchError> {
            fetch_called = true;
            return util::unexpected(BootstrapFetchError{std::string("should not fetch")});
        });

    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(result.value()[0].ip, "192.168.1.20");
    EXPECT_FALSE(fetch_called);
}

TEST(ToxAdapterTest, GetToxIdOnlyReturnsStableIdForSameDirectory) {
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto test_dir = temp_root / ("toxtunnel_test_toxid_" + std::to_string(unique));
    std::error_code ec;
    std::filesystem::remove_all(test_dir, ec);

    auto first = ToxAdapter::get_tox_id_only(test_dir);
    ASSERT_TRUE(first.has_value()) << first.error();
    EXPECT_EQ(first.value().size(), kToxIdHexLen);

    auto second = ToxAdapter::get_tox_id_only(test_dir);
    ASSERT_TRUE(second.has_value()) << second.error();
    EXPECT_EQ(second.value(), first.value());

    std::filesystem::remove_all(test_dir, ec);
}

TEST(ToxAdapterTest, RejectsSaveFilenameWithPathComponents) {
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto test_dir = temp_root / ("toxtunnel_test_bad_save_name_" + std::to_string(unique));
    std::error_code ec;
    std::filesystem::remove_all(test_dir, ec);

    for (const std::string save_filename :
         {"../tox_save.dat", "nested/tox_save.dat", R"(nested\tox_save.dat)", ".", "..", ""}) {
        ToxAdapter adapter;
        ToxAdapterConfig config;
        config.data_dir = test_dir;
        config.save_filename = save_filename;
        config.udp_enabled = false;
        config.local_discovery_enabled = false;
        config.bootstrap_mode = BootstrapMode::Lan;

        auto result = adapter.initialize(config);
        EXPECT_FALSE(result.has_value()) << save_filename;
        if (!result.has_value()) {
            EXPECT_NE(result.error().find("plain filename"), std::string::npos);
        }
    }

    std::filesystem::remove_all(test_dir, ec);
}

// Regression: a *directory* left where tox_save.dat (a regular file) is
// expected must not crash. Previously load_save_data() opened it with
// ifstream(ios::ate) and used tellg() as the size; on a directory that
// returned ~2^63, so sizing a vector threw std::bad_alloc on every startup.
// The loader now rejects non-regular files and starts with a fresh identity.
TEST(ToxAdapterTest, DirectoryAtSaveFilePathDoesNotCrash) {
    const auto temp_root = std::filesystem::temp_directory_path();
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto test_dir = temp_root / ("toxtunnel_test_savedir_" + std::to_string(unique));
    std::error_code ec;
    std::filesystem::remove_all(test_dir, ec);
    std::filesystem::create_directories(test_dir / "tox_save.dat", ec);
    ASSERT_FALSE(ec) << ec.message();

    // Must return a valid (fresh) Tox ID rather than aborting with bad_alloc.
    auto id = ToxAdapter::get_tox_id_only(test_dir);
    ASSERT_TRUE(id.has_value()) << id.error();
    EXPECT_EQ(id.value().size(), kToxIdHexLen);

    std::filesystem::remove_all(test_dir, ec);
}

}  // namespace
}  // namespace toxtunnel::tox

namespace toxtunnel::tox {
namespace {

// ---------------------------------------------------------------------------
// Bootstrap lifetime retry (issue #34): a failed startup fetch of the node list
// is retried for as long as the node is not connected to the DHT, on a worker
// that never touches toxcore; the Tox thread consumes what it fetched.
// ---------------------------------------------------------------------------

TEST(ToxAdapterTest, BootstrapRetriesTheNodeListFetchUntilItSucceeds) {
    const auto test_dir = std::filesystem::temp_directory_path() / "toxtunnel_bootstrap_retry_test";
    std::filesystem::remove_all(test_dir);

    std::atomic<int> fetches{0};
    ToxAdapterConfig config;
    config.data_dir = test_dir;
    config.udp_enabled = false;  // no sockets needed; bootstrap() still runs
    config.bootstrap_mode = BootstrapMode::Auto;
    config.bootstrap_retry_initial_delay = std::chrono::milliseconds(30);
    config.bootstrap_retry_max_delay = std::chrono::milliseconds(100);
    config.bootstrap_fetcher = [&fetches]() -> util::Expected<std::string, BootstrapFetchError> {
        const int n = fetches.fetch_add(1) + 1;
        if (n < 3) {
            return util::unexpected(BootstrapFetchError{std::string("simulated outage")});
        }
        return std::string(
            R"({"nodes":[{"ipv4":"127.0.0.1","port":33445,"status_udp":true,)"
            R"("public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]})");
    };

    ToxAdapter adapter;
    auto init = adapter.initialize(config);
    ASSERT_TRUE(init.has_value()) << init.error();
    ASSERT_TRUE(adapter.start());

    // The startup fetch fails and there is no cache: zero nodes, as in the
    // field. This must no longer be permanent.
    EXPECT_EQ(adapter.bootstrap(), 0u);
    EXPECT_EQ(adapter.bootstrap_node_count(), 0u);
    EXPECT_EQ(fetches.load(), 1);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (adapter.bootstrap_node_count() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(adapter.bootstrap_node_count(), 1u) << "the retry must adopt the fetched list";
    EXPECT_GE(fetches.load(), 3);
    EXPECT_GE(adapter.bootstrap_retry_attempts(), 2u);
    // The successful fetch also refreshed the cache for the next start.
    EXPECT_TRUE(std::filesystem::exists(BootstrapSource::cache_file_path(test_dir)));

    adapter.stop();
    std::filesystem::remove_all(test_dir);
}

TEST(ToxAdapterTest, BootstrapRetryIsNotArmedInLanMode) {
    const auto test_dir = std::filesystem::temp_directory_path() / "toxtunnel_bootstrap_lan_test";
    std::filesystem::remove_all(test_dir);

    std::atomic<int> fetches{0};
    ToxAdapterConfig config;
    config.data_dir = test_dir;
    config.udp_enabled = false;
    config.bootstrap_mode = BootstrapMode::Lan;
    config.bootstrap_retry_initial_delay = std::chrono::milliseconds(10);
    config.bootstrap_fetcher = [&fetches]() -> util::Expected<std::string, BootstrapFetchError> {
        fetches.fetch_add(1);
        return util::unexpected(BootstrapFetchError{std::string("must not be called")});
    };

    ToxAdapter adapter;
    auto init = adapter.initialize(config);
    ASSERT_TRUE(init.has_value()) << init.error();
    ASSERT_TRUE(adapter.start());
    EXPECT_EQ(adapter.bootstrap(), 0u);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(fetches.load(), 0) << "LAN mode has no public node list to fetch";
    EXPECT_EQ(adapter.bootstrap_retry_attempts(), 0u);

    adapter.stop();
    std::filesystem::remove_all(test_dir);
}

}  // namespace
}  // namespace toxtunnel::tox
