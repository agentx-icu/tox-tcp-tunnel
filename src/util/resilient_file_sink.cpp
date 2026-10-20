#include "toxtunnel/util/resilient_file_sink.hpp"

#include <exception>
#include <utility>

#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::util {

namespace {

/// Text of the in-flight exception, for the recovery notices. Called only
/// from inside a catch block.
std::string current_exception_text() {
    try {
        throw;
    } catch (const std::exception& e) {
        return e.what();
    } catch (...) {
        return "unknown exception";
    }
}

}  // namespace

const char* to_string(LogSinkState state) noexcept {
    switch (state) {
        case LogSinkState::Ok:
            return "ok";
        case LogSinkState::Fallback:
            return "fallback";
        case LogSinkState::Failed:
            return "failed";
    }
    return "unknown";
}

ResilientFileSink::ResilientFileSink(SinkFactory primary, SinkFactory fallback,
                                     std::chrono::milliseconds retry_interval, Clock clock)
    : primary_factory_(std::move(primary)),
      fallback_factory_(std::move(fallback)),
      retry_interval_(retry_interval),
      clock_(std::move(clock)) {
    // Deliberately unguarded: a log file that cannot be opened at startup
    // keeps failing startup, as it did before this wrapper existed.
    primary_ = primary_factory_();
    primary_->set_formatter(formatter_->clone());
}

void ResilientFileSink::sink_it_(const spdlog::details::log_msg& msg) {
    // The whole hook is the exception boundary: spdlog rethrows anything not
    // derived from std::exception, which on its periodic flush thread would
    // terminate the process.
    try {
        deliver(msg);
    } catch (...) {
        MetricsRegistry::instance().inc_log_sink_errors();
        MetricsRegistry::instance().inc_log_records_dropped();
    }
}

void ResilientFileSink::flush_() {
    try {
        flush_impl();
    } catch (...) {
        MetricsRegistry::instance().inc_log_sink_errors();
    }
}

void ResilientFileSink::deliver(const spdlog::details::log_msg& msg) {
    if (!primary_) {
        maybe_reopen(msg.logger_name);
    }
    if (primary_) {
        try {
            primary_->log(msg);
            return;
        } catch (...) {
            note_failure();
        }
        // The write that just failed gets one more chance on a fresh file —
        // the common case (a revoked or replaced descriptor) reopens fine.
        maybe_reopen(msg.logger_name);
        if (primary_) {
            try {
                primary_->log(msg);
                return;
            } catch (...) {
                note_failure();
            }
        }
    }
    if (!deliver_fallback(&msg)) {
        MetricsRegistry::instance().inc_log_records_dropped();
    }
}

void ResilientFileSink::flush_impl() {
    if (primary_) {
        try {
            primary_->flush();
        } catch (...) {
            // Whatever the stdio buffer held is gone or will be duplicated;
            // there is no record here to retry.
            note_failure();
        }
    }
    if (!primary_) {
        // The periodic flush (spdlog::flush_every) is what brings a QUIET
        // daemon's log file back: without it recovery would wait for the next
        // record, which may be hours away. Likewise the outage is announced on
        // the fallback now, not whenever the next record happens to arrive.
        maybe_reopen(spdlog::string_view_t("toxtunnel"));
        if (!primary_) {
            (void)deliver_fallback(nullptr);
        }
    }
    if (fallback_) {
        try {
            fallback_->flush();
        } catch (...) {
            MetricsRegistry::instance().inc_log_sink_errors();
        }
    }
}

void ResilientFileSink::set_pattern_(const std::string& pattern) {
    // Routes through set_formatter_ below, which propagates the clones.
    base_sink<std::mutex>::set_pattern_(pattern);
}

void ResilientFileSink::set_formatter_(std::unique_ptr<spdlog::formatter> sink_formatter) {
    // `formatter_` is the canonical copy: every sink created later (a
    // reopened file, the lazily built fallback) is given a clone of it, so a
    // pattern set once at startup survives any number of reopens.
    formatter_ = std::move(sink_formatter);
    for (auto* sink : {&primary_, &fallback_}) {
        if (*sink) {
            try {
                (*sink)->set_formatter(formatter_->clone());
            } catch (...) {
                MetricsRegistry::instance().inc_log_sink_errors();
            }
        }
    }
}

void ResilientFileSink::note_failure() noexcept {
    MetricsRegistry::instance().inc_log_sink_errors();
    remember_error();
    primary_.reset();
    publish_state();
}

void ResilientFileSink::remember_error() noexcept {
    // Called only from inside a catch block. Copying the text can itself
    // throw (bad_alloc); the notices then just say less.
    try {
        last_error_ = current_exception_text();
    } catch (...) {
        last_error_.clear();
    }
}

void ResilientFileSink::maybe_reopen(spdlog::string_view_t logger_name) {
    spdlog::sink_ptr candidate;
    try {
        const auto now = clock_();
        if (now < next_retry_) {
            return;
        }
        next_retry_ = now + retry_interval_;

        candidate = primary_factory_();
        candidate->set_formatter(formatter_->clone());
        // Opening proves nothing about writing (the original fd opened fine
        // too). The candidate is only accepted once a line is on disk.
        const std::string notice = "log file reopened after a write failure (" + last_error_ +
                                   "); records logged in between may be missing, or duplicated";
        candidate->log(spdlog::details::log_msg(logger_name, spdlog::level::warn, notice));
        candidate->flush();
    } catch (...) {
        MetricsRegistry::instance().inc_log_sink_errors();
        remember_error();
        publish_state();
        return;
    }
    primary_ = std::move(candidate);
    fallback_announced_ = false;
    publish_state();
}

bool ResilientFileSink::deliver_fallback(const spdlog::details::log_msg* msg) {
    if (!fallback_ && fallback_factory_) {
        try {
            fallback_ = fallback_factory_();
            if (fallback_) {
                fallback_->set_formatter(formatter_->clone());
            }
        } catch (...) {
            // A fallback that cannot even be built will not be built on the
            // next record either; stop paying for the attempt.
            MetricsRegistry::instance().inc_log_sink_errors();
            fallback_.reset();
            fallback_factory_ = nullptr;
        }
    }
    publish_state();
    if (!fallback_) {
        return false;
    }
    try {
        if (!fallback_announced_) {
            fallback_announced_ = true;
            const std::string notice = "log file unwritable (" + last_error_ +
                                       "); routing the log here until it can be reopened";
            fallback_->log(spdlog::details::log_msg(
                msg != nullptr ? msg->logger_name : spdlog::string_view_t("toxtunnel"),
                spdlog::level::err, notice));
        }
        if (msg != nullptr) {
            fallback_->log(*msg);
        }
        return true;
    } catch (...) {
        MetricsRegistry::instance().inc_log_sink_errors();
        return false;
    }
}

void ResilientFileSink::publish_state() noexcept {
    LogSinkState state = LogSinkState::Ok;
    if (!primary_) {
        state = fallback_ ? LogSinkState::Fallback : LogSinkState::Failed;
    }
    state_.store(state, std::memory_order_release);
}

}  // namespace toxtunnel::util
