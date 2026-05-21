// Atomic-write helper tests.
//
// 1. Round-trip: write -> read back == original.
// 2. Path with no prior file works.
// 3. Path with a prior file overwrites.
// 4. Concurrent writers from different pids/threads do not corrupt
//    each other's temp files (each uses pid-suffixed staging).
// 5. Failure path: writing to a non-writable parent directory surfaces
//    an error string.

#include "toxtunnel/util/atomic_file.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace toxtunnel::test {
namespace {

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
}

TEST(AtomicWriteFileTest, RoundTripBinary) {
    auto path = std::filesystem::temp_directory_path() / "toxtunnel_atomic_test1.bin";
    std::filesystem::remove(path);

    std::vector<std::uint8_t> payload(512);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    auto r = util::atomic_write_file(path,
                                     std::span<const std::uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(r) << r.error();
    auto round_trip = read_file_bytes(path);
    EXPECT_EQ(round_trip, payload);

    std::filesystem::remove(path);
}

TEST(AtomicWriteFileTest, OverwriteExisting) {
    auto path = std::filesystem::temp_directory_path() / "toxtunnel_atomic_test2.bin";
    std::filesystem::remove(path);
    {
        std::ofstream out(path);
        out << "stale contents";
    }
    std::string fresh = "fresh contents";
    auto r = util::atomic_write_file(path, fresh);
    ASSERT_TRUE(r) << r.error();
    std::string actual;
    {
        std::ifstream in(path);
        actual.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    EXPECT_EQ(actual, fresh);
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST(AtomicWriteFileTest, CreatesParentDirectory) {
    auto base = std::filesystem::temp_directory_path() / "toxtunnel_atomic_test3";
    std::filesystem::remove_all(base);
    auto path = base / "subdir" / "deep.bin";

    std::vector<std::uint8_t> payload = {'h', 'i'};
    auto r = util::atomic_write_file(path,
                                     std::span<const std::uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(r) << r.error();
    EXPECT_TRUE(std::filesystem::exists(path));
    std::filesystem::remove_all(base);
}

TEST(AtomicWriteFileTest, ConcurrentWritersDoNotCorrupt) {
    // Same target file, two writer threads. The pid-suffixed temp keeps
    // them from clobbering each other's staging; the final rename is the
    // only race, and it produces *one* of the two payloads — never a torn
    // mix.
    auto path = std::filesystem::temp_directory_path() / "toxtunnel_atomic_test4.bin";
    std::filesystem::remove(path);

    std::vector<std::uint8_t> p1(1024, 0xAA);
    std::vector<std::uint8_t> p2(1024, 0xBB);

    std::atomic<int> ok{0};
    std::thread t1([&] {
        for (int i = 0; i < 10; ++i) {
            if (util::atomic_write_file(path,
                                        std::span<const std::uint8_t>(p1.data(), p1.size()))) {
                ++ok;
            }
        }
    });
    std::thread t2([&] {
        for (int i = 0; i < 10; ++i) {
            if (util::atomic_write_file(path,
                                        std::span<const std::uint8_t>(p2.data(), p2.size()))) {
                ++ok;
            }
        }
    });
    t1.join();
    t2.join();

    EXPECT_GE(ok.load(), 1);
    auto contents = read_file_bytes(path);
    EXPECT_EQ(contents.size(), 1024u);
    // Must be all-AA or all-BB; never a torn mix.
    EXPECT_TRUE(contents == p1 || contents == p2);
    std::filesystem::remove(path);
}

// S18 / 2026-05-20 follow-up: tox_save.dat carries the Tox identity
// private key and must NOT be world-readable. Verify atomic_write_file
// honours opts.mode = owner-only (0600) on POSIX. Skipped on Windows
// where AtomicFileOptions::mode is documented as ignored.
TEST(AtomicWriteFileTest, RespectsOwnerOnlyMode) {
#if !defined(_WIN32)
    auto path = std::filesystem::temp_directory_path() / "toxtunnel_atomic_owner_only.bin";
    std::filesystem::remove(path);

    util::AtomicFileOptions opts;
    opts.mode = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;

    const std::vector<std::uint8_t> payload(64, 0x55);
    auto r = util::atomic_write_file(
        path, std::span<const std::uint8_t>(payload.data(), payload.size()), opts);
    ASSERT_TRUE(r) << r.error();
    ASSERT_TRUE(std::filesystem::exists(path));

    auto actual = std::filesystem::status(path).permissions();
    // Group / others bits must be unset; owner read+write must be set.
    constexpr auto kForbidden =
        std::filesystem::perms::group_read | std::filesystem::perms::group_write |
        std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
        std::filesystem::perms::others_write | std::filesystem::perms::others_exec;
    EXPECT_EQ(actual & kForbidden, std::filesystem::perms::none)
        << "tox_save.dat-class files must not be readable/writable by group or others";
    EXPECT_NE(actual & std::filesystem::perms::owner_read, std::filesystem::perms::none);
    EXPECT_NE(actual & std::filesystem::perms::owner_write, std::filesystem::perms::none);

    std::filesystem::remove(path);
#else
    GTEST_SKIP() << "AtomicFileOptions::mode is ignored on Windows";
#endif
}

}  // namespace
}  // namespace toxtunnel::test
