#pragma once

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace toxtunnel::util {

// ---------------------------------------------------------------------------
// MetricsRegistry
// ---------------------------------------------------------------------------

/// Thread-safe Prometheus-compatible metrics registry.
///
/// Holds the counters, gauges, and a single summary (tox iterate lag) that
/// the /metrics HTTP endpoint exposes. The hot inc/dec paths are lock-free
/// atomics; the labelled counter/gauge maps (e.g. tunnels_active{role=...})
/// are protected by a mutex but only touched on tunnel open/close — never
/// on the per-frame fast path.
///
/// Use `MetricsRegistry::instance()` for the global registry the
/// application wires its counters into. Each public method is safe to call
/// concurrently from any thread.
class MetricsRegistry {
   public:
    /// Return the process-wide singleton registry.
    static MetricsRegistry& instance();

    /// Reset all counters/gauges/observations. For tests only.
    void reset();

    // -----------------------------------------------------------------
    // Build info
    // -----------------------------------------------------------------

    /// Record the build version + git sha exposed as a `toxtunnel_build_info`
    /// gauge fixed at 1. Calling this multiple times overwrites the labels.
    void set_build_info(std::string_view version, std::string_view git_sha);

    // -----------------------------------------------------------------
    // Tunnel lifecycle counters / gauges
    // -----------------------------------------------------------------

    enum class Role : uint8_t { Server, Client };
    enum class OpenResult : uint8_t { Ok, Denied, Failed };
    enum class CloseReason : uint8_t { Local, Remote, Timeout, Error };

    /// Increment `toxtunnel_tunnels_active{role=...}`.
    void inc_tunnels_active(Role role);
    /// Decrement `toxtunnel_tunnels_active{role=...}`. Saturates at zero
    /// so a paired-up close after a force-stop cannot underflow.
    void dec_tunnels_active(Role role);
    /// Increment `toxtunnel_tunnels_opened_total{result=...}`.
    void inc_tunnels_opened(OpenResult result);
    /// Increment `toxtunnel_tunnels_closed_total{reason=...}`.
    void inc_tunnels_closed(CloseReason reason);

    // -----------------------------------------------------------------
    // Bytes counters
    // -----------------------------------------------------------------

    /// Add to `toxtunnel_bytes_in_total` (bytes received from Tox peer).
    void add_bytes_in(std::size_t n);
    /// Add to `toxtunnel_bytes_out_total` (bytes sent to Tox peer).
    void add_bytes_out(std::size_t n);

    // -----------------------------------------------------------------
    // Friends gauge
    // -----------------------------------------------------------------

    /// Set the absolute count of online friends. Callers compute the delta
    /// from their own state; the registry only stores the latest value.
    void set_friends_online(std::size_t n);

    // -----------------------------------------------------------------
    // Tox iterate lag summary
    // -----------------------------------------------------------------

    /// Record a single tox_iterate elapsed-time observation (ms).
    void observe_iterate_lag_ms(double ms);

    // -----------------------------------------------------------------
    // Outbound zero-copy counters (Wave B)
    // -----------------------------------------------------------------

    /// Increment `toxtunnel_outbound_buffer_allocs_total` — counts every
    /// `OwnedFrameBuffer` allocated for an outbound TUNNEL_DATA frame.
    void inc_outbound_buffer_allocs();
    /// Increment `toxtunnel_outbound_buffer_reuse_total` — counts every time
    /// a write was appended to the active outbound buffer without allocating
    /// a new one (true in-place coalescing).
    void inc_outbound_buffer_reuse();
    /// Increment `toxtunnel_outbound_buffer_overflow_total` — counts every
    /// time a push would have overflowed the active buffer and forced an
    /// early flush.
    void inc_outbound_buffer_overflow();

    [[nodiscard]] std::uint64_t outbound_buffer_allocs() const;
    [[nodiscard]] std::uint64_t outbound_buffer_reuse() const;
    [[nodiscard]] std::uint64_t outbound_buffer_overflow() const;

    // -----------------------------------------------------------------
    // Adaptive coalescer / BDP flow control telemetry (v0.4)
    // -----------------------------------------------------------------

    /// Increment the cumulative count of adaptive policy transitions. A
    /// transition is committed whenever a tunnel moves from one
    /// CoalescePolicy to another (e.g. Batch -> Bypass).
    void inc_coalesce_policy_transitions();

    /// Record an RTT observation (microseconds) used for the per-tunnel BDP
    /// estimator. Exposed as a summary so operators can chart median/tail.
    void observe_tunnel_rtt_us(std::int64_t rtt_us);

    /// Record the current target send window (bytes) for a tunnel. Sampled
    /// when an RTT/bandwidth update recomputes the window.
    void observe_tunnel_send_window_bytes(std::int64_t bytes);

    /// Record the current EWMA bandwidth estimate (bytes/sec).
    void observe_tunnel_bandwidth_bps(std::int64_t bps);

    [[nodiscard]] std::uint64_t coalesce_policy_transitions() const;

    // -----------------------------------------------------------------
    // Per-friend rate limiting (anti-DoS)
    // -----------------------------------------------------------------

    /// Increment the cumulative number of TUNNEL_OPEN frames rejected by
    /// the per-friend rate limiter. We do not surface per-friend labels —
    /// the friend public key has unbounded cardinality so the global counter
    /// is the safe Prometheus-exportable view. Per-friend detail is
    /// available via the inspect IPC.
    void inc_rate_limit_open_rejected();

    /// Increment the count of TUNNEL_DATA bytes-bucket exhaustion events.
    void inc_rate_limit_bytes_throttled();

    [[nodiscard]] std::uint64_t rate_limit_open_rejected() const;
    [[nodiscard]] std::uint64_t rate_limit_bytes_throttled() const;

    // -----------------------------------------------------------------
    // Tox-thread watchdog
    // -----------------------------------------------------------------

    /// Set the current `tox_iterate` lag gauge (milliseconds). Reported on
    /// every watchdog tick so dashboards can alert on "rising lag" before
    /// "hard wedge".
    void set_tox_iterate_lag_ms(std::int64_t ms);
    [[nodiscard]] std::int64_t tox_iterate_lag_ms() const;

    /// Increment the cumulative abort counter. The watchdog also persists a
    /// monotonic count in `<data_dir>/abort_count` so the value survives
    /// restarts; this counter resets at process start (it is the in-process
    /// view).
    void inc_watchdog_aborts();
    [[nodiscard]] std::uint64_t watchdog_aborts() const;

    // -----------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------

    /// Render every metric in Prometheus text format 0.0.4.
    /// Output ends with a trailing newline as required by the spec.
    [[nodiscard]] std::string render() const;

    // -----------------------------------------------------------------
    // Read accessors (for tests / introspection)
    // -----------------------------------------------------------------

    [[nodiscard]] std::uint64_t tunnels_active(Role role) const;
    [[nodiscard]] std::uint64_t tunnels_opened(OpenResult result) const;
    [[nodiscard]] std::uint64_t tunnels_closed(CloseReason reason) const;
    [[nodiscard]] std::uint64_t bytes_in() const;
    [[nodiscard]] std::uint64_t bytes_out() const;
    [[nodiscard]] std::uint64_t friends_online() const;

   private:
    MetricsRegistry() = default;

    // Labelled counters/gauges. Indices map to enum values so we avoid
    // any hashing in the hot path.
    std::atomic<std::int64_t> tunnels_active_[2]{};
    std::atomic<std::uint64_t> tunnels_opened_[3]{};
    std::atomic<std::uint64_t> tunnels_closed_[4]{};

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> friends_online_{0};

    // Iterate-lag summary: sum + count + max give Prometheus enough to
    // chart average + tail; full quantile estimation isn't worth the
    // memory + CAS cost on the Tox-thread hot path.
    std::atomic<std::uint64_t> iterate_lag_count_{0};
    std::atomic<double> iterate_lag_sum_ms_{0.0};
    std::atomic<double> iterate_lag_max_ms_{0.0};

    // Outbound zero-copy counters (Wave B).
    std::atomic<std::uint64_t> outbound_buffer_allocs_{0};
    std::atomic<std::uint64_t> outbound_buffer_reuse_{0};
    std::atomic<std::uint64_t> outbound_buffer_overflow_{0};

    // Adaptive coalescer + BDP summaries.
    std::atomic<std::uint64_t> coalesce_policy_transitions_{0};
    std::atomic<std::uint64_t> tunnel_rtt_count_{0};
    std::atomic<std::int64_t> tunnel_rtt_sum_us_{0};
    std::atomic<std::int64_t> tunnel_rtt_max_us_{0};
    std::atomic<std::uint64_t> tunnel_send_window_count_{0};
    std::atomic<std::int64_t> tunnel_send_window_sum_bytes_{0};
    std::atomic<std::int64_t> tunnel_send_window_max_bytes_{0};
    std::atomic<std::uint64_t> tunnel_bandwidth_count_{0};
    std::atomic<std::int64_t> tunnel_bandwidth_sum_bps_{0};
    std::atomic<std::int64_t> tunnel_bandwidth_max_bps_{0};

    // Per-friend rate limiting.
    std::atomic<std::uint64_t> rate_limit_open_rejected_{0};
    std::atomic<std::uint64_t> rate_limit_bytes_throttled_{0};

    // Tox-thread watchdog.
    std::atomic<std::int64_t> tox_iterate_lag_ms_{0};
    std::atomic<std::uint64_t> watchdog_aborts_{0};

    mutable std::mutex labels_mutex_;
    std::string build_version_;
    std::string build_git_sha_;
};

// ---------------------------------------------------------------------------
// MetricsServer
// ---------------------------------------------------------------------------

/// Minimal HTTP server that serves a single Prometheus /metrics endpoint.
///
/// Built on top of an existing asio::io_context — we never spawn extra
/// threads. The acceptor is single-shot (one connection at a time is fine
/// for a scrape endpoint; Prometheus polls in series and the response is
/// small enough that even busy clusters complete a request in well under
/// the scrape interval).
///
/// Requests must be `GET <configured path>` or the server responds with
/// `404 Not Found`. Anything other than HTTP/1.x GET on a recognised path
/// becomes 404 too — we intentionally keep the parsing surface tiny.
class MetricsServer {
   public:
    /// Construct against an io_context. The registry pointer must outlive
    /// the server.
    MetricsServer(asio::io_context& io_ctx, MetricsRegistry& registry);
    ~MetricsServer();

    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;
    MetricsServer(MetricsServer&&) = delete;
    MetricsServer& operator=(MetricsServer&&) = delete;

    /// Bind + start accepting on `host:port`. `host` may be a numeric
    /// address ("127.0.0.1") or "0.0.0.0". Returns an empty optional on
    /// success, or an error message describing the failure (port in use,
    /// bad host, ...). The server is started in the supplied io_context's
    /// executor — the caller is responsible for running that context.
    ///
    /// `metrics_path` is the URL path (e.g. "/metrics") that returns the
    /// rendered registry; anything else returns 404.
    [[nodiscard]] std::string start(std::string_view listen_spec, std::string_view metrics_path);

    /// Stop accepting and close the listening socket. Safe to call from
    /// any thread; idempotent.
    void stop();

    /// Return the bound local port, or 0 if not started. Useful for tests
    /// that bind to port 0 and then need to know which ephemeral port the
    /// kernel assigned.
    [[nodiscard]] std::uint16_t local_port() const noexcept;

   private:
    void do_accept();

    asio::io_context& io_ctx_;
    MetricsRegistry& registry_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::string metrics_path_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint16_t> bound_port_{0};
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse "host:port" into its components. Returns false if the spec is
/// malformed or the port is out of range. IPv6 bracketed form
/// ("[::1]:9100") is supported.
[[nodiscard]] bool parse_listen_spec(std::string_view spec, std::string& host_out,
                                     std::uint16_t& port_out);

/// Escape a Prometheus label value per spec 0.0.4: backslash, double quote,
/// and newline are escaped; everything else is passed through.
[[nodiscard]] std::string escape_label_value(std::string_view value);

}  // namespace toxtunnel::util
