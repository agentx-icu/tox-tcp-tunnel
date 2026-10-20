// Unit tests for util::ResilientFileSink (issue #47): a log file that goes
// bad mid-run must be counted, reopened or routed to the fallback — never
// silently end the log, and never throw out of the sink.

#include "toxtunnel/util/resilient_file_sink.hpp"

#include <gtest/gtest.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/logger.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/app/inspect_server.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::util {
namespace {

using namespace std::chrono_literals;

/// Scripted inner sink: records formatted lines, throws on demand.
class ScriptedSink final : public spdlog::sinks::base_sink<spdlog::details::null_mutex> {
   public:
    bool fail_log = false;
    bool fail_flush = false;
    bool throw_unknown = false;
    std::vector<std::string> lines;
    int flushes = 0;

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (fail_log) {
            if (throw_unknown) {
                throw 42;  // NOLINT: not derived from std::exception on purpose
            }
            throw spdlog::spdlog_ex("Failed writing to file", EBADF);
        }
        spdlog::memory_buf_t buf;
        formatter_->format(msg, buf);
        std::string line(buf.data(), buf.size());
        // Platform end-of-line ("\r\n" on Windows) is not what these tests
        // are about; compare payloads.
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        lines.push_back(std::move(line));
    }
    void flush_() override {
        if (fail_flush) {
            throw spdlog::spdlog_ex("Failed flush to file", EIO);
        }
        ++flushes;
    }
};

/// Hands out a fresh ScriptedSink per factory call, optionally pre-broken.
struct SinkSource {
    std::vector<std::shared_ptr<ScriptedSink>> made;
    bool next_fails_log = false;
    bool next_fails_flush = false;
    bool factory_throws = false;
    int calls = 0;

    ResilientFileSink::SinkFactory factory() {
        return [this]() -> spdlog::sink_ptr {
            ++calls;
            if (factory_throws) {
                throw spdlog::spdlog_ex("Failed opening file", EACCES);
            }
            auto s = std::make_shared<ScriptedSink>();
            s->fail_log = next_fails_log;
            s->fail_flush = next_fails_flush;
            made.push_back(s);
            return s;
        };
    }
};

struct FakeClock {
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::time_point{} + 1h};
    ResilientFileSink::Clock fn() {
        return [this] { return now; };
    }
};

class ResilientFileSinkTest : public ::testing::Test {
   protected:
    void SetUp() override { MetricsRegistry::instance().reset(); }

    std::shared_ptr<ResilientFileSink> make(bool with_fallback = true) {
        auto sink = std::make_shared<ResilientFileSink>(
            files.factory(), with_fallback ? fallbacks.factory() : ResilientFileSink::SinkFactory{},
            5s, clock.fn());
        sink->set_pattern("%v");  // raw payload, so assertions are exact
        return sink;
    }

    static void log(ResilientFileSink& sink, const std::string& text) {
        sink.log(spdlog::details::log_msg("t", spdlog::level::info, text));
    }

    static bool contains(const std::vector<std::string>& lines, const std::string& needle) {
        for (const auto& l : lines) {
            if (l.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    SinkSource files;
    SinkSource fallbacks;
    FakeClock clock;
};

TEST_F(ResilientFileSinkTest, HealthyFileReceivesRecords) {
    auto sink = make();
    log(*sink, "hello");
    ASSERT_EQ(files.made.size(), 1u);
    EXPECT_EQ(files.made[0]->lines, std::vector<std::string>{"hello"});
    EXPECT_EQ(sink->state(), LogSinkState::Ok);
    EXPECT_EQ(MetricsRegistry::instance().log_sink_errors(), 0u);
}

TEST_F(ResilientFileSinkTest, WriteFailureReopensAndRetriesTheRecord) {
    auto sink = make();
    files.made[0]->fail_log = true;
    log(*sink, "after-revoke");

    ASSERT_EQ(files.made.size(), 2u);
    const auto& fresh = files.made[1]->lines;
    ASSERT_EQ(fresh.size(), 2u);
    EXPECT_NE(fresh[0].find("log file reopened after a write failure"), std::string::npos);
    EXPECT_NE(fresh[0].find("Failed writing to file"), std::string::npos);
    EXPECT_EQ(fresh[1], "after-revoke");
    EXPECT_GE(files.made[1]->flushes, 1) << "a candidate is accepted only after a flush";
    EXPECT_EQ(sink->state(), LogSinkState::Ok);
    EXPECT_EQ(MetricsRegistry::instance().log_sink_errors(), 1u);
    EXPECT_EQ(MetricsRegistry::instance().log_records_dropped(), 0u);
    EXPECT_TRUE(fallbacks.made.empty());
}

TEST_F(ResilientFileSinkTest, FlushOnlyFailureReopensOnNextRecord) {
    auto sink = make();
    files.made[0]->fail_flush = true;
    sink->flush();
    EXPECT_EQ(MetricsRegistry::instance().log_sink_errors(), 1u);
    // The flush that failed already tried a reopen (deadline was open).
    ASSERT_EQ(files.made.size(), 2u);
    log(*sink, "next");
    EXPECT_TRUE(contains(files.made[1]->lines, "next"));
    EXPECT_EQ(sink->state(), LogSinkState::Ok);
}

TEST_F(ResilientFileSinkTest, CandidateThatOpensButCannotWriteIsDiscarded) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.next_fails_log = true;  // the reopened file is just as broken
    log(*sink, "lost-file");

    ASSERT_EQ(files.made.size(), 2u);
    EXPECT_TRUE(files.made[1]->lines.empty());
    EXPECT_EQ(sink->state(), LogSinkState::Fallback);
    ASSERT_EQ(fallbacks.made.size(), 1u);
    const auto& fb = fallbacks.made[0]->lines;
    ASSERT_EQ(fb.size(), 2u);
    EXPECT_NE(fb[0].find("log file unwritable"), std::string::npos);
    EXPECT_EQ(fb[1], "lost-file");
    EXPECT_EQ(MetricsRegistry::instance().log_sink_errors(), 2u);
    EXPECT_EQ(MetricsRegistry::instance().log_records_dropped(), 0u);
}

TEST_F(ResilientFileSinkTest, ReopenIsThrottledAndFileComesBackLater) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.factory_throws = true;
    log(*sink, "a");
    log(*sink, "b");
    log(*sink, "c");
    EXPECT_EQ(files.calls, 2) << "one construction + one reopen inside the interval";
    EXPECT_EQ(sink->state(), LogSinkState::Fallback);
    ASSERT_EQ(fallbacks.made.size(), 1u);
    EXPECT_TRUE(contains(fallbacks.made[0]->lines, "c"));

    // The condition clears; a QUIET daemon recovers through the periodic flush.
    files.factory_throws = false;
    clock.now += 6s;
    sink->flush();
    EXPECT_EQ(files.calls, 3);
    EXPECT_EQ(sink->state(), LogSinkState::Ok);
    log(*sink, "back");
    EXPECT_TRUE(contains(files.made.back()->lines, "back"));
}

TEST_F(ResilientFileSinkTest, NoFallbackCountsDroppedRecords) {
    auto sink = make(/*with_fallback=*/false);
    files.made[0]->fail_log = true;
    files.factory_throws = true;
    log(*sink, "x");
    log(*sink, "y");
    EXPECT_EQ(sink->state(), LogSinkState::Failed);
    EXPECT_EQ(MetricsRegistry::instance().log_records_dropped(), 2u);
}

TEST_F(ResilientFileSinkTest, ThrowingFallbackNeverEscapes) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.factory_throws = true;
    fallbacks.factory_throws = true;
    EXPECT_NO_THROW(log(*sink, "x"));
    EXPECT_NO_THROW(log(*sink, "y"));
    EXPECT_EQ(fallbacks.calls, 1) << "a fallback that cannot be built is not retried per record";
    EXPECT_EQ(sink->state(), LogSinkState::Failed);
    EXPECT_EQ(MetricsRegistry::instance().log_records_dropped(), 2u);
}

TEST_F(ResilientFileSinkTest, UnknownExceptionTypeNeverEscapes) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.made[0]->throw_unknown = true;
    EXPECT_NO_THROW(log(*sink, "x"));
    EXPECT_TRUE(contains(files.made.back()->lines, "unknown exception"));
}

TEST_F(ResilientFileSinkTest, FormatterSurvivesReopen) {
    auto sink = make();
    sink->set_pattern("[%n] %v");
    files.made[0]->fail_log = true;
    log(*sink, "fmt");
    ASSERT_EQ(files.made.size(), 2u);
    EXPECT_EQ(files.made[1]->lines.back(), "[t] fmt");
}

TEST_F(ResilientFileSinkTest, CandidateThatCannotFlushIsDiscarded) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.next_fails_flush = true;  // opens and writes, but the flush fails
    log(*sink, "x");
    EXPECT_EQ(sink->state(), LogSinkState::Fallback);
    ASSERT_EQ(fallbacks.made.size(), 1u);
    EXPECT_TRUE(contains(fallbacks.made[0]->lines, "x"));
}

TEST_F(ResilientFileSinkTest, FallbackDeliveryFailureCountsADrop) {
    auto sink = make();
    files.made[0]->fail_log = true;
    files.factory_throws = true;
    fallbacks.next_fails_log = true;
    EXPECT_NO_THROW(log(*sink, "x"));
    EXPECT_EQ(MetricsRegistry::instance().log_records_dropped(), 1u);
}

TEST_F(ResilientFileSinkTest, InitialOpenFailureStillPropagates) {
    files.factory_throws = true;
    EXPECT_THROW(make(), spdlog::spdlog_ex);
}

TEST_F(ResilientFileSinkTest, FlushOnlyOutageAnnouncesTheFallbackWithoutARecord) {
    auto sink = make();
    files.made[0]->fail_flush = true;
    files.factory_throws = true;
    sink->flush();
    EXPECT_EQ(sink->state(), LogSinkState::Fallback);
    ASSERT_EQ(fallbacks.made.size(), 1u);
    ASSERT_EQ(fallbacks.made[0]->lines.size(), 1u);
    EXPECT_NE(fallbacks.made[0]->lines[0].find("log file unwritable"), std::string::npos);
}

TEST_F(ResilientFileSinkTest, ThrowingClockNeverEscapes) {
    bool clock_throws = false;
    auto sink = std::make_shared<ResilientFileSink>(files.factory(), fallbacks.factory(), 5s,
                                                    [&]() -> std::chrono::steady_clock::time_point {
                                                        if (clock_throws) {
                                                            throw 7;  // NOLINT: deliberately odd
                                                        }
                                                        return clock.now;
                                                    });
    files.made[0]->fail_log = true;
    clock_throws = true;
    EXPECT_NO_THROW(log(*sink, "x"));
    EXPECT_NO_THROW(sink->flush());
}

TEST_F(ResilientFileSinkTest, ConcurrentLogAndFlushStaySafe) {
    auto sink = make();
    std::atomic<bool> stop{false};
    std::atomic<int> flushes{0};
    std::thread flusher([&] {
        while (!stop.load()) {
            sink->flush();
            flushes.fetch_add(1);
        }
    });
    std::thread reader([&] {
        while (!stop.load()) {
            (void)sink->state();
        }
    });
    // Make sure the flusher is really interleaving before the writes start.
    while (flushes.load() < 10) {
        std::this_thread::yield();
    }
    for (int i = 0; i < 2000; ++i) {
        EXPECT_NO_THROW(log(*sink, "r" + std::to_string(i)));
    }
    stop = true;
    flusher.join();
    reader.join();
    EXPECT_GE(flushes.load(), 10);
}

TEST(ResilientFileSinkMetricsTest, CountersAreRenderedAndReset) {
    auto& m = MetricsRegistry::instance();
    m.reset();
    m.inc_log_sink_errors();
    m.inc_log_records_dropped();
    const auto text = m.render();
    EXPECT_NE(text.find("toxtunnel_log_sink_errors_total 1"), std::string::npos);
    EXPECT_NE(text.find("toxtunnel_log_records_dropped_total 1"), std::string::npos);
    m.reset();
    EXPECT_EQ(m.log_sink_errors(), 0u);
    EXPECT_EQ(m.log_records_dropped(), 0u);
}

TEST(ResilientFileSinkLoggerTest, FileSinkStateAndInspectFields) {
    namespace fs = std::filesystem;
    const auto path = fs::temp_directory_path() /
                      ("tt-resilient-" +
                       std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + ".log");
    Logger::init("toxtunnel");
    EXPECT_FALSE(Logger::file_sink_state().has_value());
    EXPECT_FALSE(app::current_log_sink_status().has_value());

    app::InspectProviders providers;
    providers.log_sink = &app::current_log_sink_status;
    EXPECT_EQ(app::InspectServer::render_status_json(providers).find("log_sink_state"),
              std::string::npos)
        << "omitted while no file sink is configured";

    Logger::add_file_sink(path.string());
    ASSERT_TRUE(Logger::file_sink_state().has_value());
    EXPECT_EQ(*Logger::file_sink_state(), LogSinkState::Ok);
    const auto json = app::InspectServer::render_status_json(providers);
    EXPECT_NE(json.find("\"log_sink_state\":\"ok\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"log_sink_errors\":"), std::string::npos) << json;

    // The custom error handler survives the add_file_sink() rebuild: a report
    // to it is counted instead of only printed.
    MetricsRegistry::instance().reset();
    Logger::get()->info(fmt::runtime("{bad format"), 1);  // malformed on purpose
    EXPECT_GE(MetricsRegistry::instance().log_sink_errors(), 1u);

    Logger::init("toxtunnel");  // drop the file sink again for later tests
    std::error_code ec;
    fs::remove(path, ec);
}

}  // namespace
}  // namespace toxtunnel::util
