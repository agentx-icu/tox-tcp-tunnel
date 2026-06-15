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
