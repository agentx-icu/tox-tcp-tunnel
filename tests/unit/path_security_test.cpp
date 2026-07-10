// is_plain_filename tests.
//
// The validator is intentionally pure string inspection: the manylinux2014
// release toolchain (devtoolset GCC 10, COW-string ABI) mis-parses
// std::filesystem::path components, so an fs::path-based implementation
// could reject the default "tox_save.dat" or wave a traversal through on
// release binaries (see parent_dir_of in atomic_file.cpp).

#include "toxtunnel/util/path_security.hpp"

#include <gtest/gtest.h>

namespace toxtunnel::test {
namespace {

TEST(IsPlainFilenameTest, AcceptsOrdinaryFilenames) {
    EXPECT_TRUE(util::is_plain_filename("tox_save.dat"));
    EXPECT_TRUE(util::is_plain_filename("known_servers.yaml"));
    EXPECT_TRUE(util::is_plain_filename("a"));
    EXPECT_TRUE(util::is_plain_filename("weird name with spaces.bin"));
    EXPECT_TRUE(util::is_plain_filename("..hidden"));
    EXPECT_TRUE(util::is_plain_filename(".dotfile"));
}

TEST(IsPlainFilenameTest, RejectsEmptyAndDotDirs) {
    EXPECT_FALSE(util::is_plain_filename(""));
    EXPECT_FALSE(util::is_plain_filename("."));
    EXPECT_FALSE(util::is_plain_filename(".."));
}

TEST(IsPlainFilenameTest, RejectsSeparatorsAndTraversal) {
    EXPECT_FALSE(util::is_plain_filename("a/b"));
    EXPECT_FALSE(util::is_plain_filename("../escape"));
    EXPECT_FALSE(util::is_plain_filename("/absolute"));
    EXPECT_FALSE(util::is_plain_filename("a\\b"));
    EXPECT_FALSE(util::is_plain_filename("\\\\server\\share"));
    EXPECT_FALSE(util::is_plain_filename("dir/"));
}

TEST(IsPlainFilenameTest, RejectsWindowsRootNamesAndStreams) {
    EXPECT_FALSE(util::is_plain_filename("C:foo"));
    EXPECT_FALSE(util::is_plain_filename("C:\\foo"));
    EXPECT_FALSE(util::is_plain_filename("name:stream"));
}

}  // namespace
}  // namespace toxtunnel::test
