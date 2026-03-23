#include <gtest/gtest.h>

#include <string>

#include "toxtunnel/util/qr_code.hpp"

namespace toxtunnel::util {
namespace {

TEST(QrCodeTest, RejectsEmptyText) {
    auto result = generate_qr_terminal("", false);
    EXPECT_FALSE(result.has_value());
}

TEST(QrCodeTest, GeneratesMultilineQrWithoutAnsiByDefault) {
    auto result = generate_qr_terminal("HELLO-TOXTUNNEL", false);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_NE(result.value().find('\n'), std::string::npos);
    EXPECT_EQ(result.value().find("\x1b["), std::string::npos);
}

TEST(QrCodeTest, GeneratesAnsiWhenColorEnabled) {
    auto result = generate_qr_terminal("HELLO-TOXTUNNEL", true);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_NE(result.value().find("\x1b["), std::string::npos);
}

}  // namespace
}  // namespace toxtunnel::util
