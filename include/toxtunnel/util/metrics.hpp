#pragma once

#include <asio.hpp>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace toxtunnel::util {

// ---------------------------------------------------------------------------
// Metric kinds
// ---------------------------------------------------------------------------

/// Prometheus text-format metric kinds we support.
enum class MetricType : uint8_t {
    Counter,  ///< monotonically increasing sample
    Gauge,    ///< instantaneous sample, may go up or down
    Summary,  ///< running count + sum + max (no quantiles)
};

/// One {label, value} pair attached to a metric series.
struct Label {
    std::string name;
    std::string value;

    bool operator<(const Label& other) const {
        if (name != other.name) {
            return name < other.name;
        }
        return value < other.value;
    }
};

using Labels = std::vector<Label>;

// ---------------------------------------------------------------------------
// Series storage
// ---------------------------------------------------------------------------

/// Numeric storage for counter / gauge series.
///
/// Backed by std::atomic<uint64_t> holding bit-cast double — counters bump from
/// many I/O threads, so the read path must be lock-free.
class Sample {
   public:
    Sample() noexcept = default;
    Sample(const Sample&) = delete;
    Sample& operator=(const Sample&) = delete;

    void inc(double v = 1.0) noexcept;
    void set(double v) noexcept;
    [[nodiscard]] double value() const noexcept;

   private:
    std::atomic<uint64_t> bits_{0};
};

/// Backing storage for summary (count + sum + max).
class SummarySample {
   public:
    void observe(double v) noexcept;
    [[nodiscard]] uint64_t count() const noexcept;
    [[nodiscard]] double sum() const noexcept;
    [[nodiscard]] double max() const noexcept;

   private:
    std::atomic<uint64_t> count_{0};
    std::atomic<uint64_t> sum_bits_{0};
    std::atomic<uint64_t> max_bits_{0};
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A thread-safe registry of named metrics with optional labels.
///
/// Designed for the single-process toxtunnel daemon: metric families are
/// registered once at startup (via the helper accessors below) and from then
/// on series are cheaply incremented from any thread.
///
/// Render output follows the Prometheus exposition format 0.0.4: one HELP and
/// one TYPE line per family, then one sample line per series.
class MetricsRegistry {
   public:
    MetricsRegistry();
    ~MetricsRegistry() = default;

    MetricsRegistry(const MetricsRegistry&) = delete;
    MetricsRegistry& operator=(const MetricsRegistry&) = delete;

    /// Register a metric family. Idempotent — repeat calls with the same name
    /// are no-ops as long as type/help match. Returns false on type/help mismatch.
    bool register_family(std::string name, MetricType type, std::string help);

    /// Increment a counter series. Creates the series the first time it is
    /// seen. Returns false if the family doesn't exist or isn't a counter.
    bool counter_inc(std::string_view name, const Labels& labels, double v = 1.0);

    /// Set a gauge series.
    bool gauge_set(std::string_view name, const Labels& labels, double v);

    /// Increment a gauge by a delta.
    bool gauge_inc(std::string_view name, const Labels& labels, double v = 1.0);

    /// Observe one sample on a summary series.
    bool summary_observe(std::string_view name, const Labels& labels, double v);

    /// Read counter value (mostly for tests).
    [[nodiscard]] double counter_value(std::string_view name, const Labels& labels) const;

    /// Read gauge value (mostly for tests).
    [[nodiscard]] double gauge_value(std::string_view name, const Labels& labels) const;

    /// Render the registry to Prometheus text exposition format 0.0.4.
    [[nodiscard]] std::string render() const;

   private:
    struct Family {
        std::string name;
        MetricType type;
        std::string help;
        std::map<Labels, std::unique_ptr<Sample>> samples;
        std::map<Labels, std::unique_ptr<SummarySample>> summaries;
    };

    Family* find_family(std::string_view name);
    [[nodiscard]] const Family* find_family(std::string_view name) const;

    mutable std::shared_mutex mutex_;
    std::map<std::string, Family, std::less<>> families_;
};

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

/// Tiny asio-based HTTP server that exposes a single GET endpoint and serves
/// the rendered text from a MetricsRegistry. Any other method / path returns
/// 404. Designed for trusted operator networks, not for the public internet.
class MetricsServer {
   public:
    MetricsServer(asio::io_context& io, MetricsRegistry& registry, std::string listen_addr,
                  std::string path);

    /// Bind the listening socket and start accepting. Returns an error string
    /// on bind / parse failure, empty string on success.
    [[nodiscard]] std::string start();

    /// Stop accepting and tear down the listener.
    void stop();

    [[nodiscard]] uint16_t bound_port() const;

    /// Parse "host:port" into (host, port). host may be a bare IP or a name.
    /// Returns false if the spec is malformed.
    static bool parse_listen(std::string_view spec, std::string& host_out, uint16_t& port_out);

   private:
    void do_accept();
    void handle_connection(std::shared_ptr<asio::ip::tcp::socket> socket);

    asio::io_context& io_;
    MetricsRegistry& registry_;
    std::string listen_addr_;
    std::string path_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    uint16_t bound_port_{0};
};

}  // namespace toxtunnel::util
