#include <gtest/gtest.h>

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

}  // namespace
}  // namespace toxtunnel::tox
