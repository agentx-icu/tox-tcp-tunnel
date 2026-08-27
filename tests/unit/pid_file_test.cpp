// pid-file discovery tests.
//
// 1. write -> read round-trips the current pid.
// 2. A stale file (foreign pid) is overwritten by write and left alone by
//    remove.
// 3. read returns nullopt for missing / garbage files.
// 4. PidFileGuard writes on construction and removes on destruction.
// 5. pid_is_toxtunnel recognises the test binary only when it is named
//    toxtunnel* (it is not), and rejects impossible pids.

#include "toxtunnel/util/pid_file.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace toxtunnel::test {
namespace {

long self_pid() {
#if defined(_WIN32)
    return static_cast<long>(GetCurrentProcessId());
#else
    return static_cast<long>(::getpid());
#endif
}

std::filesystem::path fresh_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               ("toxtunnel_pidfile_" + std::string(tag) + "_" + std::to_string(self_pid()));
    std::filesystem::remove_all(dir);
    return dir;
}

TEST(PidFileTest, WriteThenReadRoundTrip) {
    const auto dir = fresh_dir("rt");
    auto r = util::write_pid_file(dir);
    ASSERT_TRUE(r.has_value()) << r.error();
    ASSERT_TRUE(std::filesystem::exists(dir / util::kPidFileName));
    auto pid = util::read_pid_file(dir);
    ASSERT_TRUE(pid.has_value());
    EXPECT_EQ(*pid, self_pid());
    util::remove_pid_file(dir);
    EXPECT_FALSE(std::filesystem::exists(dir / util::kPidFileName));
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, StaleFileIsOverwrittenButNotRemovedByForeignPid) {
    const auto dir = fresh_dir("stale");
    std::filesystem::create_directories(dir);
    {
        std::ofstream stale(dir / util::kPidFileName);
        stale << "999999999\n";
    }
    // remove() must refuse to delete a file that records someone else's pid.
    util::remove_pid_file(dir);
    EXPECT_TRUE(std::filesystem::exists(dir / util::kPidFileName));
    ASSERT_TRUE(util::write_pid_file(dir).has_value());
    EXPECT_EQ(util::read_pid_file(dir).value_or(-1), self_pid());
    util::remove_pid_file(dir);
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, ReadMissingOrGarbageReturnsNullopt) {
    const auto dir = fresh_dir("garbage");
    EXPECT_FALSE(util::read_pid_file(dir).has_value());
    EXPECT_FALSE(util::read_pid_file({}).has_value());
    std::filesystem::create_directories(dir);
    {
        std::ofstream bad(dir / util::kPidFileName);
        bad << "not-a-pid\n";
    }
    EXPECT_FALSE(util::read_pid_file(dir).has_value());
    {
        std::ofstream zero(dir / util::kPidFileName);
        zero << "0\n";
    }
    EXPECT_FALSE(util::read_pid_file(dir).has_value());
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, TrailingGarbageIsRejectedRatherThanPartiallyParsed) {
    // `123abc` must not read as pid 123: `toxtunnel reload` would then signal
    // whatever process happens to own 123.
    const auto dir = fresh_dir("garbage2");
    std::filesystem::create_directories(dir);
    for (const char* bad : {"123abc", "123 456", "12.5", "-7", "+9", " ", "0x10"}) {
        std::ofstream out(dir / util::kPidFileName, std::ios::trunc);
        out << bad;
        out.close();
        EXPECT_FALSE(util::read_pid_file(dir).has_value()) << "accepted '" << bad << "'";
    }
    // Surrounding whitespace/newline around a clean number is still fine.
    for (const char* good : {"4242", " 4242 ", "4242\n", "\n4242\n"}) {
        std::ofstream out(dir / util::kPidFileName, std::ios::trunc);
        out << good;
        out.close();
        EXPECT_EQ(util::read_pid_file(dir).value_or(-1), 4242) << "rejected '" << good << "'";
    }
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, GuardWritesAndRemoves) {
    const auto dir = fresh_dir("guard");
    {
        util::PidFileGuard guard(dir);
        ASSERT_TRUE(guard.active()) << guard.error();
        EXPECT_EQ(guard.path(), dir / util::kPidFileName);
        EXPECT_EQ(util::read_pid_file(dir).value_or(-1), self_pid());
    }
    EXPECT_FALSE(std::filesystem::exists(dir / util::kPidFileName));
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, SecondGuardOnTheSameDirIsRefused) {
    // Two daemons on one data_dir would share the Tox identity, the inspect
    // socket and known_servers.yaml. The guard is what stops that.
    const auto dir = fresh_dir("conflict");
    {
        util::PidFileGuard first(dir);
        ASSERT_TRUE(first.active()) << first.error();

        util::PidFileGuard second(dir);
        EXPECT_FALSE(second.active());
        EXPECT_TRUE(second.conflicted());
        EXPECT_EQ(second.status(), util::PidFileGuard::Status::AlreadyLocked);
        EXPECT_EQ(second.holder_pid(), self_pid()) << "the conflict message must name the holder";
        EXPECT_FALSE(second.error().empty());

        // The loser must not have disturbed the winner's pid file.
        EXPECT_EQ(util::read_pid_file(dir).value_or(-1), self_pid());
    }
    // Guards must be out of scope before removing the dir: on Windows the lock
    // file is held open (FILE_FLAG_DELETE_ON_CLOSE) for the guard's lifetime.
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, DirIsReclaimableAfterTheHolderReleases) {
    const auto dir = fresh_dir("reclaim");
    {
        util::PidFileGuard first(dir);
        ASSERT_TRUE(first.active()) << first.error();
    }
    {
        util::PidFileGuard second(dir);
        EXPECT_TRUE(second.active()) << second.error();
        EXPECT_FALSE(second.conflicted());
    }
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, StalePidFileFromAKilledPredecessorIsOverwritten) {
    // A hard kill leaves the pid file behind but releases the kernel lock, so
    // the next daemon must be able to take over rather than refuse forever.
    const auto dir = fresh_dir("stale");
    std::filesystem::create_directories(dir);
    {
        std::ofstream stale(dir / util::kPidFileName);
        stale << "999999999\n";
    }
    {
        util::PidFileGuard guard(dir);
        EXPECT_TRUE(guard.active()) << guard.error();
        EXPECT_EQ(util::read_pid_file(dir).value_or(-1), self_pid());
    }
    std::filesystem::remove_all(dir);
}

TEST(PidFileTest, GuardWithEmptyDirIsInactive) {
    util::PidFileGuard guard({});
    EXPECT_FALSE(guard.active());
    EXPECT_FALSE(guard.conflicted()) << "an unusable path is not a conflict with another daemon";
    EXPECT_EQ(guard.status(), util::PidFileGuard::Status::Failed);
    EXPECT_FALSE(guard.error().empty());
}

TEST(PidFileTest, PidIsToxtunnelRejectsImpossiblePids) {
    EXPECT_EQ(util::pid_is_toxtunnel(0), std::optional<bool>(false));
    EXPECT_EQ(util::pid_is_toxtunnel(-5), std::optional<bool>(false));
#if defined(__linux__) || defined(__APPLE__)
    // The unit-test binary is not called toxtunnel, so the check must say no
    // for our own pid rather than blindly returning true for any live process.
    auto self = util::pid_is_toxtunnel(self_pid());
    ASSERT_TRUE(self.has_value());
    EXPECT_FALSE(*self);
#endif
}

}  // namespace
}  // namespace toxtunnel::test
