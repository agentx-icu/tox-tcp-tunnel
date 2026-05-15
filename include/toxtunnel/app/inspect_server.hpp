#pragma once

#include <asio.hpp>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "toxtunnel/tunnel/tunnel_manager.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::app {

// Forward declaration to keep the public header free of platform headers.
class InspectSession;

/// Provider callback signatures decouple the inspect server from the
/// surrounding TunnelServer/TunnelClient. The server holds no live pointers
/// into the managers — it asks for snapshots only when a client connects.
struct InspectProviders {
    /// Returns "server" or "client" — the daemon mode label included in
    /// /status replies.
    std::function<std::string()> mode;

    /// Returns the toxtunnel build version string.
    std::function<std::string()> version;

    /// Returns how many friends are currently online (>= 0).
    std::function<std::size_t()> friends_online;

    /// Returns the friend public-key prefix (first ~8 hex chars) for a given
    /// snapshot tunnel — supplied opaquely so the inspect server does not
    /// need to know the per-friend grouping. May return an empty string.
    std::function<std::string(uint16_t tunnel_id)> friend_pk_prefix;

    /// Returns a combined snapshot of every active tunnel across managers.
    std::function<tunnel::ManagerSnapshot()> snapshot;
};

/// Local-only IPC server exposing read-only daemon state.
///
/// POSIX: an AF_UNIX SOCK_STREAM at `<data_dir>/toxtunnel.sock`, chmod 0600,
/// so only the daemon's UID can connect. A stale socket left by a previous
/// process is detected and unlinked at bind time — refusing to start on
/// EADDRINUSE would brick the daemon on a crash-restart cycle.
///
/// Windows: a per-pid named pipe `\\.\pipe\toxtunnel-<pid>` with a
/// current-user DACL. Per-pid naming is deliberate: it sidesteps the cleanup
/// race that bites Unix sockets (the previous instance's pipe vanishes when
/// the process exits) and keeps multiple daemons on one host from colliding.
///
/// The wire protocol is single-shot to keep the implementation small and
/// to make it trivially safe to serve from the IO pool:
///   client writes:  "GET /tunnels\n"  or  "GET /status\n"
///   server writes:  one JSON document followed by EOF (and closes).
/// Anything else gets a short JSON error and a close.
class InspectServer {
   public:
    InspectServer();
    ~InspectServer();

    InspectServer(const InspectServer&) = delete;
    InspectServer& operator=(const InspectServer&) = delete;
    InspectServer(InspectServer&&) = delete;
    InspectServer& operator=(InspectServer&&) = delete;

    /// Start listening on the platform-appropriate local IPC endpoint.
    ///
    /// @param io_ctx     The io_context to run async accept on.
    /// @param data_dir   Directory used to derive the POSIX socket path.
    ///                   Ignored on Windows (named pipe name is pid-based).
    /// @param providers  Snapshot/state callbacks invoked per-request.
    [[nodiscard]] util::Expected<void, std::string> start(asio::io_context& io_ctx,
                                                          const std::filesystem::path& data_dir,
                                                          InspectProviders providers);

    /// Stop accepting and unlink the POSIX socket file. Idempotent.
    void stop();

    /// Endpoint path or pipe name, for logging and tests. Empty until start().
    [[nodiscard]] const std::string& endpoint() const noexcept { return endpoint_; }

    /// Build the JSON document for one of the two supported requests.
    /// Exposed for testing — keeps the snapshot-shape contract assertable
    /// without touching real sockets.
    [[nodiscard]] static std::string render_tunnels_json(const InspectProviders& providers);
    [[nodiscard]] static std::string render_status_json(const InspectProviders& providers);

    /// Render one well-formed JSON error reply. Public for tests.
    [[nodiscard]] static std::string render_error_json(std::string_view message);

   private:
    void do_accept();
    void handle_session(std::shared_ptr<InspectSession> session);

    asio::io_context* io_ctx_{nullptr};
    InspectProviders providers_{};
    std::string endpoint_;

#ifdef _WIN32
    // Named-pipe handling lives in the .cpp; the pump runs on a dedicated
    // thread because asio's stream_handle does not wrap a pipe HANDLE
    // portably on Windows without iocp setup that we do not currently use.
    std::atomic<bool> running_{false};
    std::thread pipe_thread_;
#else
    std::unique_ptr<asio::local::stream_protocol::acceptor> acceptor_;
    std::atomic<bool> running_{false};
#endif

    mutable std::mutex mutex_;
};

}  // namespace toxtunnel::app
