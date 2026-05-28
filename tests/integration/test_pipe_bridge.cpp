#include <gtest/gtest.h>

#ifndef _WIN32

#include <sys/types.h>
#include <unistd.h>

#include <barrier>
#include <chrono>
#include <cstdlib>
#include <future>
#include <string>
#include <vector>

#include "toxtunnel/app/stdio_pipe_bridge.hpp"

namespace toxtunnel::integration {
namespace {

using namespace std::chrono_literals;

class PipeBridgeTest : public ::testing::Test {
   protected:
    void SetUp() override {
        ASSERT_EQ(::pipe(input_pipe_), 0);
        ASSERT_EQ(::pipe(output_pipe_), 0);
    }

    void TearDown() override {
        for (int fd : input_pipe_) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
        for (int fd : output_pipe_) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
    }

    int input_pipe_[2] = {-1, -1};
    int output_pipe_[2] = {-1, -1};
};

TEST_F(PipeBridgeTest, MovesInputToTunnelAndTunnelToOutput) {
    app::StdioPipeBridge bridge(input_pipe_[0], output_pipe_[1]);

    std::promise<std::string> tunnel_data_promise;
    auto tunnel_data = tunnel_data_promise.get_future();

    std::promise<void> input_closed_promise;
    auto input_closed = input_closed_promise.get_future();

    auto start = bridge.start(
        [&tunnel_data_promise](std::span<const uint8_t> data) {
            tunnel_data_promise.set_value(std::string(data.begin(), data.end()));
        },
        [&input_closed_promise]() { input_closed_promise.set_value(); });
    ASSERT_TRUE(start.has_value()) << start.error();

    const std::string inbound = "ssh-handshake";
    ASSERT_EQ(::write(input_pipe_[1], inbound.data(), inbound.size()),
              static_cast<ssize_t>(inbound.size()));
    ASSERT_EQ(tunnel_data.wait_for(2s), std::future_status::ready);
    EXPECT_EQ(tunnel_data.get(), inbound);

    const std::string outbound = "server-reply";
    bridge.write_output(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(outbound.data()),
                                                 outbound.size()));

    std::array<char, 64> buffer{};
    const ssize_t read_bytes = ::read(output_pipe_[0], buffer.data(), buffer.size());
    ASSERT_EQ(read_bytes, static_cast<ssize_t>(outbound.size()));
    EXPECT_EQ(std::string(buffer.data(), static_cast<std::size_t>(read_bytes)), outbound);

    ::close(input_pipe_[1]);
    input_pipe_[1] = -1;
    ASSERT_EQ(input_closed.wait_for(2s), std::future_status::ready);

    bridge.stop();
}

TEST_F(PipeBridgeTest, ConcurrentStopIsIdempotent) {
    EXPECT_EXIT(([] {
                    for (int iter = 0; iter < 64; ++iter) {
                        int input_pipe[2];
                        input_pipe[0] = -1;
                        input_pipe[1] = -1;
                        int output_pipe[2];
                        output_pipe[0] = -1;
                        output_pipe[1] = -1;
                        if (::pipe(input_pipe) != 0 || ::pipe(output_pipe) != 0) {
                            std::_Exit(2);
                        }

                        {
                            app::StdioPipeBridge bridge(input_pipe[0], output_pipe[1]);
                            auto started = bridge.start([](std::span<const uint8_t>) {}, [] {});
                            if (!started.has_value()) {
                                std::_Exit(3);
                            }

                            ::close(input_pipe[1]);
                            input_pipe[1] = -1;

                            std::barrier sync_point(3);
                            std::thread stopper_a([&] {
                                sync_point.arrive_and_wait();
                                bridge.stop();
                            });
                            std::thread stopper_b([&] {
                                sync_point.arrive_and_wait();
                                bridge.stop();
                            });
                            sync_point.arrive_and_wait();
                            stopper_a.join();
                            stopper_b.join();
                        }

                        if (input_pipe[0] >= 0) {
                            ::close(input_pipe[0]);
                        }
                        if (output_pipe[0] >= 0) {
                            ::close(output_pipe[0]);
                        }
                        if (output_pipe[1] >= 0) {
                            ::close(output_pipe[1]);
                        }
                    }
                    std::_Exit(0);
                })(),
                ::testing::ExitedWithCode(0), "");
}

}  // namespace
}  // namespace toxtunnel::integration

#endif
