#pragma once

#include <cstdlib>
#include <exception>
#include <typeinfo>

#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::util {

// One shared fatal diagnostic boundary for every place that pumps an asio
// io_context (issue #24 slice 3): asio's run()/poll_one() has no catch of its
// own, so an exception escaping a completion handler unwinds out of the pump
// and today reaches std::terminate with no diagnostics. Handler-local RAII
// repair guards are the correctness layer that makes such escapes rare; this
// is the containment layer — it names the exception, bumps a metric, and
// aborts (systemd / launchd restarts, the same pattern the Tox-thread watchdog
// relies on).
//
// Catch-and-continue was rejected: several completion handlers do essential
// work (rearming reads/accepts, fulfilling a reload promise) after a callback,
// so silently continuing could wedge the daemon while it still looks healthy.
//
// Everything here is best-effort noexcept: a throwing logger or metric must
// not preempt the unconditional abort().
template <typename Fn>
void run_with_fatal_boundary(const char* context, Fn&& pump) noexcept {
    try {
        pump();
    } catch (const std::exception& e) {
        try {
            MetricsRegistry::instance().inc_worker_aborts();
        } catch (...) {
        }
        try {
            Logger::error(
                "{}: unhandled exception [{}] escaped a completion handler ({}); aborting", context,
                typeid(e).name(), e.what());
        } catch (...) {
        }
        std::abort();
    } catch (...) {
        try {
            MetricsRegistry::instance().inc_worker_aborts();
        } catch (...) {
        }
        try {
            Logger::error(
                "{}: unhandled non-standard exception escaped a completion handler; "
                "aborting",
                context);
        } catch (...) {
        }
        std::abort();
    }
}

}  // namespace toxtunnel::util
