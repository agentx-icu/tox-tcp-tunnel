#include <gtest/gtest.h>

#include "toxtunnel/util/expected.hpp"

using toxtunnel::util::Expected;

TEST(ExpectedTest, ConstructWithValue) {
    Expected<int, std::string> result(42);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 42);
}

TEST(ExpectedTest, ConstructWithError) {
    Expected<int, std::string> result(toxtunnel::util::make_unexpected(std::string("error")));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), "error");
}

TEST(ExpectedTest, ErrorAccessOnError) {
    Expected<int, std::string> result(
        toxtunnel::util::make_unexpected(std::string("something went wrong")));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), "something went wrong");
}

TEST(ExpectedTest, ValueThrowsOnError) {
    Expected<int, std::string> result(toxtunnel::util::make_unexpected(std::string("error")));
    EXPECT_THROW(result.value(), std::runtime_error);
}

TEST(ExpectedTest, ErrorThrowsOnValue) {
    Expected<int, std::string> result(42);
    EXPECT_THROW(result.error(), std::runtime_error);
}

TEST(ExpectedTest, ValueOrDefault) {
    Expected<int, std::string> success(42);
    Expected<int, std::string> failure(toxtunnel::util::make_unexpected(std::string("error")));

    EXPECT_EQ(success.value_or(0), 42);
    EXPECT_EQ(failure.value_or(0), 0);
}
