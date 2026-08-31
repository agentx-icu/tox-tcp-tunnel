// Does the CLIENT actually bind a forward where `local_address` says?
//
// WHY THIS EXISTS SEPARATELY from the unit tests. The unit tests prove the
// rule->bind mapping: a ForwardRule carrying 127.0.0.1 produces a listener whose
// endpoint is loopback. They construct TcpListener directly, so they would all
// stay green if TunnelClient went back to the port-only constructor and ignored
// the field entirely — which is precisely the P0 bug. What is untested there is
// the wiring: that the client passes the address through, at BOTH of its bind
// sites (startup and hot-reload additions).
//
// HOW IT DISCRIMINATES, without exposing the client's private internals. Point a
// forward at an address that is valid, parseable, and NOT assigned to any
// interface on this host (RFC 5737 TEST-NET-1). Then:
//
//   correct code  -> binds 192.0.2.1, fails with EADDRNOTAVAIL, reports it
//   pre-fix code  -> ignores the address, binds 0.0.0.0, SUCCEEDS
//
// So the observable outcome — startup refusing to come up, reload reporting a
// warning — is exactly inverted by the bug. No private access needed.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "toxtunnel/app/tunnel_client.hpp"
#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/util/config.hpp"

namespace toxtunnel::integration {
namespace {

/// RFC 5737 TEST-NET-1: reserved for documentation, so it is guaranteed not to
/// be a real host, and in practice is not assigned to a local interface.
constexpr const char* kUnassignedAddress = "192.0.2.1";

constexpr const char* kValidToxId =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Grab a port, then let it go, so we can name a port that was free a moment
/// ago instead of guessing a literal and colliding with whatever else runs here.
[[nodiscard]] std::uint16_t borrow_free_port() {
    asio::io_context io;
    asio::ip::tcp::acceptor probe(io,
                                  asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = probe.local_endpoint().port();
    probe.close();
    return port;
}

/// True when this host refuses to bind the unassigned address, which is what
/// makes the discrimination above work. Some hosts permit non-local binds
/// (Linux `ip_nonlocal_bind`, jails, unusual sandboxes); there the premise does
/// not hold and the test must say so rather than assert something false.
[[nodiscard]] bool unassigned_address_refuses_bind() {
    asio::io_context io;
    // shared_ptr, not a stack object: TcpListener documents that it must be
    // held that way because it relies on enable_shared_from_this, and
    // shared_from_this() on a stack instance is undefined behaviour even if
    // this probe never reaches an accept.
    const auto probe =
        std::make_shared<core::TcpListener>(io, kUnassignedAddress, borrow_free_port());
    return !probe->is_bound();
}

class ForwardBindWiringTest : public ::testing::Test {
   protected:
    void SetUp() override {
        if (!unassigned_address_refuses_bind()) {
            GTEST_SKIP() << "this host allows binding " << kUnassignedAddress
                         << ", so it cannot distinguish an honoured local_address from an "
                            "ignored one";
        }
        data_dir_ =
            std::filesystem::temp_directory_path() /
            ("toxtunnel-fwd-bind-" +
             std::to_string(::testing::UnitTest::GetInstance()->current_test_info()->line()));
        std::filesystem::remove_all(data_dir_);
        std::filesystem::create_directories(data_dir_);
    }

    void TearDown() override {
        client_.reset();
        std::error_code ec;
        std::filesystem::remove_all(data_dir_, ec);
    }

    [[nodiscard]] Config config_with(const std::vector<ForwardRule>& forwards) const {
        Config c = Config::default_client();
        c.data_dir = data_dir_.string();
        c.client->server_id = kValidToxId;
        c.client->forwards = forwards;
        return c;
    }

    std::filesystem::path data_dir_;
    std::unique_ptr<app::TunnelClient> client_;
};

// ---------------------------------------------------------------------------
// Bind site 1: startup
// ---------------------------------------------------------------------------

TEST_F(ForwardBindWiringTest, StartupBindsTheConfiguredAddressAndFailsWhenItIsUnavailable) {
    client_ = std::make_unique<app::TunnelClient>();
    const auto port = borrow_free_port();

    auto result = client_->initialize(
        config_with({ForwardRule{port, "127.0.0.1", 22, std::string(kUnassignedAddress)}}));

    ASSERT_FALSE(result.has_value())
        << "startup came up healthy with a forward it could not have bound where asked — "
           "the address was ignored and something else got bound instead";
    EXPECT_NE(result.error().find(kUnassignedAddress), std::string::npos)
        << "the failure must name the address that could not be bound: " << result.error();
}

TEST_F(ForwardBindWiringTest, StartupSucceedsOnAnAvailableAddress) {
    // The control for the test above: proves the failure there comes from the
    // address, not from initialize() being unable to run in this environment.
    client_ = std::make_unique<app::TunnelClient>();
    const auto port = borrow_free_port();

    auto result = client_->initialize(
        config_with({ForwardRule{port, "127.0.0.1", 22, std::string("127.0.0.1")}}));

    ASSERT_TRUE(result.has_value()) << result.error();
}

// ---------------------------------------------------------------------------
// Bind site 2: hot-reload additions
// ---------------------------------------------------------------------------
//
// The second site is the one the original design note missed, and it is not
// covered by the startup test: it is a separate construction of TcpListener.

TEST_F(ForwardBindWiringTest, ReloadBindsTheConfiguredAddressOnAnAddedForward) {
    client_ = std::make_unique<app::TunnelClient>();
    const auto working_port = borrow_free_port();
    const ForwardRule working{working_port, "127.0.0.1", 22, std::string("127.0.0.1")};

    ASSERT_TRUE(client_->initialize(config_with({working})).has_value());

    const auto added_port = borrow_free_port();
    const ForwardRule unbindable{added_port, "127.0.0.1", 80, std::string(kUnassignedAddress)};

    auto reloaded = client_->reload(config_with({working, unbindable}));

    // Reload is best-effort per forward: it applies, and reports the one that
    // could not bind. A pre-fix client binds the wildcard instead and reports
    // nothing at all.
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error();
    EXPECT_FALSE(reloaded.value().warnings.empty())
        << "an added forward that cannot bind its configured address was reported as fine — "
           "the address was ignored on the reload path";
    EXPECT_NE(reloaded.value().warnings.find(kUnassignedAddress), std::string::npos)
        << "the warning must name the address: " << reloaded.value().warnings;
}

TEST_F(ForwardBindWiringTest, ReloadAddsAForwardOnAnAvailableAddressWithoutWarnings) {
    // Control for the reload path.
    client_ = std::make_unique<app::TunnelClient>();
    const auto first_port = borrow_free_port();
    const ForwardRule first{first_port, "127.0.0.1", 22, std::string("127.0.0.1")};
    ASSERT_TRUE(client_->initialize(config_with({first})).has_value());

    const auto second_port = borrow_free_port();
    const ForwardRule second{second_port, "127.0.0.1", 80, std::string("127.0.0.1")};

    auto reloaded = client_->reload(config_with({first, second}));
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error();
    EXPECT_TRUE(reloaded.value().warnings.empty()) << reloaded.value().warnings;
}

}  // namespace
}  // namespace toxtunnel::integration
