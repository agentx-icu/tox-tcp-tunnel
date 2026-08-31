// `client.forwards[].local_address` — which interface a static forward binds.
//
// THE PROBLEM THIS FIXES. Before v0.4.13 a static forward was always built
// with the port-only TcpListener constructor, which binds `asio::ip::tcp::v4()`
// — the wildcard. There was no key to say otherwise, so every forward was
// reachable from anything that could route to the host, while the docs and
// examples implied it was local-only. Operators were exposing services without
// knowing.
//
// THE PROVENANCE RULE, which most of these tests are about. `local_address` is
// `std::optional` and its ABSENCE is preserved rather than collapsed into a
// default string, because two states that produce the same bind must still be
// told apart:
//
//   absent            -> binds 127.0.0.1 (since v0.5.0; 0.0.0.0 before) AND
//                        earns a migration notice saying the default changed
//   explicit anything -> binds what it says and is met with SILENCE
//
// An operator who wrote an address made an informed choice; warning them
// would be noise they cannot turn off. Anything that flattens the optional into
// a string — a defaulted field, an encoder that always writes the effective
// value — destroys that distinction and silences the notice for exactly the
// people it exists for.

#include <gtest/gtest.h>

#include <asio.hpp>
#include <memory>
#include <optional>
#include <string>

#include "toxtunnel/core/tcp_listener.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/config_diagnostics.hpp"
#include "toxtunnel/util/config_reload.hpp"

using namespace toxtunnel;

namespace {

/// A Tox ID that passes checksum validation, so `validate()` reaches the
/// forward rules instead of failing earlier.
constexpr const char* kValidToxId =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000";

/// A minimal valid client config carrying one forward.
Config client_config_with(const ForwardRule& rule) {
    Config c = Config::default_client();
    c.data_dir = "/tmp/toxtunnel-test";
    c.client->server_id = kValidToxId;
    c.client->forwards.push_back(rule);
    return c;
}

// ---------------------------------------------------------------------------
// Provenance: absent vs explicit
// ---------------------------------------------------------------------------

TEST(ForwardBindAddressTest, AbsentFallsBackToLoopbackButIsNotExplicit) {
    const ForwardRule rule{2222, "10.0.0.5", 22, std::nullopt};
    EXPECT_FALSE(rule.has_explicit_local_address());
    EXPECT_EQ(rule.effective_local_address(), "127.0.0.1")
        << "the v0.5.0 default is loopback (issue #27); LAN reach must be asked for";
}

TEST(ForwardBindAddressTest, ExplicitValueIsUsedAndReportedAsExplicit) {
    const ForwardRule rule{2222, "10.0.0.5", 22, std::string("127.0.0.1")};
    EXPECT_TRUE(rule.has_explicit_local_address());
    EXPECT_EQ(rule.effective_local_address(), "127.0.0.1");
}

TEST(ForwardBindAddressTest, AnExplicitLoopbackIsDistinguishableFromAnAbsentOne) {
    // The distinction the whole notice design rests on. Both bind the same
    // address; only one of them asked for it.
    const ForwardRule absent{2222, "10.0.0.5", 22, std::nullopt};
    const ForwardRule explicit_loopback{2222, "10.0.0.5", 22, std::string("127.0.0.1")};

    EXPECT_EQ(absent.effective_local_address(), explicit_loopback.effective_local_address());
    EXPECT_NE(absent.has_explicit_local_address(), explicit_loopback.has_explicit_local_address());
}

// ---------------------------------------------------------------------------
// The advisory
// ---------------------------------------------------------------------------

TEST(ForwardBindAdvisoryTest, NoticesWhenTheKeyWasNeverSet) {
    const ForwardRule rule{2222, "10.0.0.5", 22, std::nullopt};
    auto advisory = forward_bind_advisory(rule);
    ASSERT_TRUE(advisory) << "an operator who never chose this must be told what was chosen "
                             "for them — especially across the v0.5.0 default flip";
    // The message has to carry the fix, not just the diagnosis: both the way
    // back to the old reach and the way to accept the new default.
    EXPECT_NE(advisory->find("local_address"), std::string::npos) << *advisory;
    EXPECT_NE(advisory->find("127.0.0.1"), std::string::npos) << *advisory;
    EXPECT_NE(advisory->find("0.0.0.0"), std::string::npos) << *advisory;
    // ...and enough identity to act on when several forwards are configured.
    EXPECT_NE(advisory->find("2222"), std::string::npos) << *advisory;
}

TEST(ForwardBindAdvisoryTest, IsSilentWhenTheOperatorExplicitlyChoseTheWildcard) {
    // THE POINT OF THE OPTIONAL. Same bind, same exposure, no warning: this
    // operator decided, and an unsilenceable warning gets filtered out along
    // with the ones that matter.
    const ForwardRule rule{2222, "10.0.0.5", 22, std::string("0.0.0.0")};
    EXPECT_FALSE(forward_bind_advisory(rule).has_value());
}

TEST(ForwardBindAdvisoryTest, IsSilentForLoopbackAndForAnyExplicitAddress) {
    for (const char* addr : {"127.0.0.1", "::1"}) {
        const ForwardRule rule{2222, "10.0.0.5", 22, std::string(addr)};
        EXPECT_FALSE(forward_bind_advisory(rule).has_value()) << addr;
    }
    // A deliberate LAN bind is legitimate and silent — it is explicit.
    const ForwardRule lan{2222, "10.0.0.5", 22, std::string("0.0.0.0")};
    EXPECT_FALSE(forward_bind_advisory(lan).has_value());
}

// ---------------------------------------------------------------------------
// YAML round trip
// ---------------------------------------------------------------------------

TEST(ForwardBindAddressYamlTest, AnAbsentAddressIsNotWrittenAndStaysAbsent) {
    const Config original = client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::nullopt});
    const std::string yaml = original.to_yaml();

    EXPECT_EQ(yaml.find("local_address"), std::string::npos)
        << "writing the effective address would forge consent the operator never gave:\n"
        << yaml;

    auto reparsed = Config::from_string(yaml);
    ASSERT_TRUE(reparsed.has_value()) << reparsed.error();
    ASSERT_EQ(reparsed.value().client->forwards.size(), 1u);
    EXPECT_FALSE(reparsed.value().client->forwards[0].has_explicit_local_address())
        << "a round trip turned 'never set' into 'chose the wildcard'";
}

TEST(ForwardBindAddressYamlTest, AnExplicitWildcardSurvivesARoundTrip) {
    // The other half: an explicit choice must not be dropped as "same as the
    // default", or the operator gets warned again on the next start.
    const Config original =
        client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::string("0.0.0.0")});
    const std::string yaml = original.to_yaml();
    EXPECT_NE(yaml.find("local_address"), std::string::npos) << yaml;

    auto reparsed = Config::from_string(yaml);
    ASSERT_TRUE(reparsed.has_value()) << reparsed.error();
    ASSERT_EQ(reparsed.value().client->forwards.size(), 1u);
    EXPECT_TRUE(reparsed.value().client->forwards[0].has_explicit_local_address());
    EXPECT_EQ(reparsed.value().client->forwards[0].effective_local_address(), "0.0.0.0");
    EXPECT_FALSE(forward_bind_advisory(reparsed.value().client->forwards[0]).has_value())
        << "silence must survive the round trip too";
}

TEST(ForwardBindAddressYamlTest, AnOrdinaryAddressSurvivesARoundTrip) {
    const Config original =
        client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::string("127.0.0.1")});
    auto reparsed = Config::from_string(original.to_yaml());
    ASSERT_TRUE(reparsed.has_value()) << reparsed.error();
    ASSERT_EQ(reparsed.value().client->forwards.size(), 1u);
    EXPECT_EQ(reparsed.value().client->forwards[0].local_address, std::string("127.0.0.1"));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

TEST(ForwardBindAddressValidationTest, RejectsAnUnparseableAddress) {
    // `localhost` is the trap the field name exists to avoid: it is a perfectly
    // good `remote_host`, and not a valid `local_address`.
    for (const char* bad : {"localhost", "not-an-address", "999.1.1.1", ""}) {
        const Config cfg = client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::string(bad)});
        auto result = cfg.validate();
        EXPECT_FALSE(result.has_value()) << "accepted invalid local_address '" << bad << "'";
        if (!result.has_value()) {
            EXPECT_NE(result.error().find("local_address"), std::string::npos) << result.error();
        }
    }
}

TEST(ForwardBindAddressValidationTest, AcceptsIpv4Ipv6AndBothWildcards) {
    for (const char* good : {"127.0.0.1", "0.0.0.0", "::1", "::", "192.168.1.10"}) {
        const Config cfg = client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::string(good)});
        auto result = cfg.validate();
        EXPECT_TRUE(result.has_value())
            << "rejected valid local_address '" << good
            << "': " << (result.has_value() ? std::string{} : result.error());
    }
}

TEST(ForwardBindAddressValidationTest, ANonLoopbackBindIsAllowed) {
    // Deliberately NOT restricted to loopback, unlike client.socks5.listen:
    // serving a forward to other machines is a legitimate deployment.
    const Config cfg =
        client_config_with(ForwardRule{2222, "10.0.0.5", 22, std::string("0.0.0.0")});
    EXPECT_TRUE(cfg.validate().has_value());
}

// ---------------------------------------------------------------------------
// Strict-mode key acceptance
// ---------------------------------------------------------------------------

TEST(ForwardBindAddressStrictTest, TheKeyIsKnownToStrictValidation) {
    // Without the allowlist entry, every config using the new key would fail
    // `toxtunnel config check --strict` as carrying an unknown key.
    const std::string yaml = R"(mode: client
data_dir: /tmp/toxtunnel-test
client:
  server_id: )" + std::string(kValidToxId) +
                             R"(
  forwards:
    - local_port: 2222
      local_address: 127.0.0.1
      remote_host: 10.0.0.5
      remote_port: 22
)";
    const auto unknown = util::find_unknown_config_keys_in_string(yaml);
    for (const auto& key : unknown) {
        EXPECT_EQ(key.path.find("local_address"), std::string::npos)
            << "local_address reported as unknown: " << key.path;
    }
}

// ---------------------------------------------------------------------------
// Reload diffing
// ---------------------------------------------------------------------------

TEST(ForwardBindAddressReloadTest, AbsentAndExplicitLoopbackCompareEqual) {
    // Adding `local_address: 127.0.0.1` to a config that was already binding
    // loopback by default changes nothing observable, so it must NOT stop and
    // rebind a live listener.
    const ForwardRule absent{2222, "h1", 22, std::nullopt};
    const ForwardRule explicit_loopback{2222, "h1", 22, std::string("127.0.0.1")};
    EXPECT_TRUE(absent == explicit_loopback);

    const auto diff = util::diff_forwards({absent}, {explicit_loopback});
    EXPECT_TRUE(diff.added.empty()) << "a no-op edit rebound the listener";
    EXPECT_TRUE(diff.removed.empty()) << "a no-op edit dropped the listener";
}

TEST(ForwardBindAddressReloadTest, AChangedAddressIsADifferentRuleAndRebinds) {
    const ForwardRule wildcard{2222, "h1", 22, std::string("0.0.0.0")};
    const ForwardRule loopback{2222, "h1", 22, std::string("127.0.0.1")};
    EXPECT_FALSE(wildcard == loopback);

    const auto diff = util::diff_forwards({wildcard}, {loopback});
    ASSERT_EQ(diff.added.size(), 1u) << "tightening the bind never took effect";
    ASSERT_EQ(diff.removed.size(), 1u) << "the exposed listener was left running";
    EXPECT_EQ(diff.added[0].effective_local_address(), "127.0.0.1");
    EXPECT_EQ(diff.removed[0].effective_local_address(), "0.0.0.0");
}

TEST(ForwardBindAddressReloadTest, RestoringTheOldWildcardDefaultIsARebind) {
    // The v0.5.0 migration edit itself: an operator whose absent-key forward
    // used to serve the LAN writes `local_address: 0.0.0.0` to get that reach
    // back. Absent now means loopback, so this MUST rebind.
    const ForwardRule absent{2222, "h1", 22, std::nullopt};
    const ForwardRule explicit_wildcard{2222, "h1", 22, std::string("0.0.0.0")};
    EXPECT_FALSE(absent == explicit_wildcard);

    const auto diff = util::diff_forwards({absent}, {explicit_wildcard});
    ASSERT_EQ(diff.added.size(), 1u) << "the widened bind never took effect";
    ASSERT_EQ(diff.removed.size(), 1u);
}

// ---------------------------------------------------------------------------
// The bind actually happens where the rule says
// ---------------------------------------------------------------------------
//
// These assert the OBSERVABLE outcome — which interface the socket is on —
// rather than that a string was passed along. A forward that reports 127.0.0.1
// and still answers on a routable address is the whole bug.

TEST(ForwardBindAddressListenerTest, AnExplicitLoopbackRuleBindsLoopback) {
    asio::io_context io;
    const ForwardRule rule{0, "10.0.0.5", 22, std::string("127.0.0.1")};
    auto listener =
        std::make_shared<core::TcpListener>(io, rule.effective_local_address(), rule.local_port);
    ASSERT_TRUE(listener->is_bound()) << listener->bind_error().message();
    EXPECT_TRUE(listener->local_endpoint().address().is_loopback())
        << "bound " << listener->local_endpoint().address().to_string();
}

TEST(ForwardBindAddressListenerTest, AnAbsentRuleBindsLoopback) {
    // The v0.5.0 guarantee, asserted rather than assumed: a forward that
    // never asked for reach does not get any.
    asio::io_context io;
    const ForwardRule rule{0, "10.0.0.5", 22, std::nullopt};
    auto listener =
        std::make_shared<core::TcpListener>(io, rule.effective_local_address(), rule.local_port);
    ASSERT_TRUE(listener->is_bound()) << listener->bind_error().message();
    EXPECT_TRUE(listener->local_endpoint().address().is_loopback())
        << "bound " << listener->local_endpoint().address().to_string();
}

TEST(ForwardBindAddressListenerTest, AnIpv6RuleBinds) {
    asio::io_context io;
    const ForwardRule rule{0, "10.0.0.5", 22, std::string("::1")};
    auto listener =
        std::make_shared<core::TcpListener>(io, rule.effective_local_address(), rule.local_port);
    if (!listener->is_bound()) {
        GTEST_SKIP() << "no IPv6 loopback on this host: " << listener->bind_error().message();
    }
    EXPECT_TRUE(listener->local_endpoint().address().is_loopback());
    EXPECT_TRUE(listener->local_endpoint().address().is_v6());
}

}  // namespace
