// Chaos-test infrastructure smoke test.
//
// Chaos tests inject deliberate failures (network impairment, random
// kills mid-write, fuzzed protocol input) to surface bugs the
// deterministic suite cannot. The real fixtures (`chaos_netem_disconnects`,
// `chaos_save_crash`, `chaos_protocol_fuzzer`) require `CAP_NET_ADMIN`
// or fuzzing engines and run nightly under `-DTOXTUNNEL_CHAOS=ON`.
//
// This smoke test proves the harness compiles and links, exercises the
// shared `atomic_write_file` under repeated overwrite, and pins the
// "no torn writes" guarantee. Operators run the full suite via
// `ctest -L chaos`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/util/atomic_file.hpp"

namespace toxtunnel::test {
namespace {

// =============================================================================
// 1. Repeated overwrite: a thousand atomic writes alternating two distinct
//    payloads. Final read must equal exactly one of the two — never a
//    spliced mix.
// =============================================================================

TEST(ChaosSmoke, NoTornWriteUnderRepeatedOverwrite) {
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
                ("toxtunnel_chaos_smoke_" + std::to_string(unique) + ".bin");
    std::filesystem::remove(path);

    std::vector<std::uint8_t> p1(4096, 0xCC);
    std::vector<std::uint8_t> p2(4096, 0xDD);

    std::atomic<int> writes{0};
    std::thread w1([&] {
        for (int i = 0; i < 500; ++i) {
            (void)util::atomic_write_file(path,
                                          std::span<const std::uint8_t>(p1.data(), p1.size()));
            ++writes;
        }
    });
    std::thread w2([&] {
        for (int i = 0; i < 500; ++i) {
            (void)util::atomic_write_file(path,
                                          std::span<const std::uint8_t>(p2.data(), p2.size()));
            ++writes;
        }
    });
    w1.join();
    w2.join();

    EXPECT_EQ(writes.load(), 1000);

    {
        std::ifstream in(path, std::ios::binary);
        std::vector<std::uint8_t> got((std::istreambuf_iterator<char>(in)),
                                      std::istreambuf_iterator<char>());
        ASSERT_EQ(got.size(), 4096u);
        EXPECT_TRUE(got == p1 || got == p2);
    }
    std::filesystem::remove(path);
}

}  // namespace
}  // namespace toxtunnel::test
