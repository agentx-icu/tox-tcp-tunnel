// TcpListener bind-failure behaviour.
//
// A local port that is already in use is an ordinary operator mistake (two
// daemons, or another process on the port). It used to escape TcpListener's
// constructor as an uncaught std::system_error — std::terminate at startup,
// and terminate from inside an asio handler when a SIGHUP reload added a busy
// forward. These tests pin the non-throwing contract.

#include <gtest/gtest.h>

#include <memory>

#include "toxtunnel/core/tcp_listener.hpp"

namespace toxtunnel::test {
namespace {

TEST(TcpListenerBindTest, EphemeralPortBinds) {
    asio::io_context io;
    auto listener = std::make_shared<core::TcpListener>(io, "127.0.0.1", uint16_t{0});
    EXPECT_TRUE(listener->is_bound());
    EXPECT_FALSE(listener->bind_error());
    EXPECT_NE(listener->local_endpoint().port(), 0);
}

TEST(TcpListenerBindTest, BusyPortDoesNotThrowAndReportsError) {
    asio::io_context io;
    auto first = std::make_shared<core::TcpListener>(io, "127.0.0.1", uint16_t{0});
    ASSERT_TRUE(first->is_bound());
    const auto port = first->local_endpoint().port();

    std::shared_ptr<core::TcpListener> second;
    ASSERT_NO_THROW(second = std::make_shared<core::TcpListener>(io, "127.0.0.1", port));
    EXPECT_FALSE(second->is_bound());
    EXPECT_TRUE(second->bind_error());

    // An unbound listener is inert rather than half-armed.
    bool accepted = false;
    second->start_accept([&accepted](std::shared_ptr<core::TcpConnection>) { accepted = true; });
    EXPECT_FALSE(second->is_accepting());
    EXPECT_FALSE(accepted);
}

TEST(TcpListenerBindTest, InvalidAddressDoesNotThrow) {
    asio::io_context io;
    std::shared_ptr<core::TcpListener> listener;
    ASSERT_NO_THROW(listener = std::make_shared<core::TcpListener>(io, "not-an-ip", uint16_t{0}));
    EXPECT_FALSE(listener->is_bound());
    EXPECT_TRUE(listener->bind_error());
}

}  // namespace
}  // namespace toxtunnel::test
