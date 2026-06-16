#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "toxtunnel/tox/bootstrap_source.hpp"
#include "toxtunnel/tox/tox_ptr.hpp"
#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tox {

class ToxWatchdog;  // forward declaration

// ---------------------------------------------------------------------------
// Callback signatures
// ---------------------------------------------------------------------------

/// Called when a friend request is received.
///
/// @param public_key  The 32-byte public key of the requester.
/// @param message     The message attached to the request.
using FriendRequestCallback =
    std::function<void(const PublicKeyArray& public_key, std::string_view message)>;

/// Called when a friend's connection status changes.
///
/// @param friend_number  The friend number.
/// @param connected      True if the friend came online, false if they went offline.
using FriendConnectionCallback = std::function<void(uint32_t friend_number, bool connected)>;

/// Called when a lossless packet is received from a friend.
///
/// @param friend_number  The friend number who sent the data.
/// @param data           Pointer to the received data.
/// @param length         Number of bytes received.
using FriendLosslessPacketCallback =
    std::function<void(uint32_t friend_number, const uint8_t* data, std::size_t length)>;

/// Called when a lossy packet is received from a friend.
///
/// @param friend_number  The friend number who sent the data.
/// @param data           Pointer to the received data.
/// @param length         Number of bytes received.
using FriendLossyPacketCallback =
    std::function<void(uint32_t friend_number, const uint8_t* data, std::size_t length)>;

/// Called when a text message is received from a friend.
///
/// @param friend_number  The friend number who sent the message.
/// @param message        The text message.
using FriendMessageCallback = std::function<void(uint32_t friend_number, std::string_view message)>;

/// Called when this node's own connection status to the DHT changes.
///
/// @param connected  True if connected to the DHT, false otherwise.
using SelfConnectionCallback = std::function<void(bool connected)>;

// ---------------------------------------------------------------------------
// ToxAdapter configuration
// ---------------------------------------------------------------------------

/// Configuration for initializing ToxAdapter.
struct ToxAdapterConfig {
    /// Directory for storing Tox save data.
    std::filesystem::path data_dir;

    /// Filename of the Tox save file within data_dir (default: "tox_save.dat").
    std::string save_filename = "tox_save.dat";

    /// Whether to enable UDP.
    bool udp_enabled = true;

    /// Whether to enable IPv6.
    bool ipv6_enabled = false;

    /// Whether to enable toxcore local discovery.
    bool local_discovery_enabled = false;

    /// Local TCP relay port (0 = disabled).
    uint16_t tcp_port = 0;

    /// Proxy type (0=none, 1=HTTP, 2=SOCKS5).
    uint8_t proxy_type = 0;

    /// Proxy host, used when proxy_type != 0.
    std::string proxy_host;

    /// Proxy port, used when proxy_type != 0.
    uint16_t proxy_port = 0;

    /// Bootstrap nodes to connect to.
    std::vector<BootstrapNode> bootstrap_nodes;

    /// Bootstrap policy to use when no explicit nodes are provided.
    BootstrapMode bootstrap_mode = BootstrapMode::Auto;

    /// Name to set on the Tox instance (visible to friends).
    std::string name = "toxtunnel";

    /// Status message to set on the Tox instance.
    std::string status_message = "toxtunnel node";
};

// ---------------------------------------------------------------------------
// Friend connection state
// ---------------------------------------------------------------------------

/// Represents the connection state of a friend.
enum class FriendState : uint8_t {
    None,  ///< No established connection.
    TCP,   ///< Connected via TCP relay.
    UDP,   ///< Connected directly via UDP.
};

/// Information about a known friend.
struct FriendInfo {
    uint32_t friend_number = 0;
    PublicKeyArray public_key{};
    FriendState state = FriendState::None;
};

// ---------------------------------------------------------------------------
// ToxAdapter
// ---------------------------------------------------------------------------

/// High-level API for interacting with the Tox network.
///
/// ToxAdapter manages a Tox instance on a dedicated thread.  Every public
/// method that calls a `tox_*` function is routed onto that thread via
/// run_on_tox_thread(), because toxcore is not merely non-reentrant: it
/// requires all of its calls to originate from the single thread that drives
/// `tox_iterate`.  Calls made from a toxcore callback (which already runs on
/// the iterate thread) execute inline to avoid self-deadlock.
///
/// Typical usage:
/// @code
///   ToxAdapterConfig config;
///   config.data_dir = "/var/lib/toxtunnel";
///   config.bootstrap_nodes = { ... };
///
///   ToxAdapter adapter;
///   auto result = adapter.initialize(config);
///   if (!result) { ... handle error ... }
///
///   adapter.set_on_friend_request([](auto& pk, auto msg) { ... });
///   adapter.set_on_friend_connection([](auto fn, bool c) { ... });
///
///   adapter.start();        // spawn the iteration thread
///   adapter.bootstrap();    // connect to the DHT
///
///   auto address = adapter.get_address();
///   Logger::info("My Tox ID: {}", address.to_hex());
///
///   // ... later ...
///   adapter.stop();
/// @endcode
class ToxAdapter {
   public:
    [[nodiscard]] static util::Expected<std::string, std::string> get_tox_id_only(
        const std::filesystem::path& data_dir);

    ToxAdapter();
    ~ToxAdapter();

    // Non-copyable, non-movable (owns a thread).
    ToxAdapter(const ToxAdapter&) = delete;
    ToxAdapter& operator=(const ToxAdapter&) = delete;
    ToxAdapter(ToxAdapter&&) = delete;
    ToxAdapter& operator=(ToxAdapter&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Initialize the Tox instance with the given configuration.
    ///
    /// If a save file exists in `config.data_dir`, it is loaded; otherwise
    /// a new identity is created and persisted.
    ///
    /// @return An empty Expected on success, or an error description string
    ///         on failure.
    [[nodiscard]] util::Expected<void, std::string> initialize(const ToxAdapterConfig& config);

    /// Start the Tox iteration thread.
    ///
    /// @pre initialize() has been called successfully.
    /// @return true if the thread was started, false if already running or
    ///         not initialized.
    bool start();

    /// Stop the Tox iteration thread and save state.
    ///
    /// Blocks until the thread has joined.  Safe to call if not running.
    void stop();

    /// Attach a Tox-thread watchdog. Heartbeat is bumped after every
    /// successful return from `tox_iterate`. Pass nullptr to detach.
    void set_watchdog(class toxtunnel::tox::ToxWatchdog* watchdog) {
        watchdog_.store(watchdog, std::memory_order_release);
    }

    /// Return true if the iteration thread is running.
    [[nodiscard]] bool is_running() const noexcept;

    // -----------------------------------------------------------------
    // Network operations
    // -----------------------------------------------------------------

    /// Bootstrap to the DHT by connecting to the configured bootstrap nodes.
    ///
    /// @return The number of nodes that were successfully contacted.
    [[nodiscard]] std::size_t bootstrap();

    /// Resolve bootstrap nodes for a config without touching a live Tox instance.
    [[nodiscard]] static util::Expected<std::vector<BootstrapNode>, std::string>
    resolve_bootstrap_nodes_for_config(const ToxAdapterConfig& config,
                                       BootstrapSource::Fetcher fetcher = {});

    /// Add a single bootstrap node at runtime and attempt to connect.
    ///
    /// @return true if the bootstrap attempt succeeded, false otherwise.
    [[nodiscard]] bool add_bootstrap_node(const BootstrapNode& node);

    // -----------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------

    /// Return this node's own Tox address (38 bytes).
    ///
    /// @pre initialize() has been called successfully.
    [[nodiscard]] ToxId get_address() const;

    /// Return this node's own public key (32 bytes).
    ///
    /// @pre initialize() has been called successfully.
    [[nodiscard]] PublicKeyArray get_public_key() const;

    /// Return this node's current nospam value.
    [[nodiscard]] uint32_t get_nospam() const;

    /// Set a new nospam value.
    void set_nospam(uint32_t nospam);

    // -----------------------------------------------------------------
    // Friend management
    // -----------------------------------------------------------------

    /// Add a friend by their full Tox ID and attach a message.
    ///
    /// @return The friend number on success, or an error string.
    [[nodiscard]] util::Expected<uint32_t, std::string> add_friend(
        const ToxId& tox_id, std::string_view message = "toxtunnel");

    /// Add a friend by their full Tox ID without sending a friend request.
    ///
    /// Use this when you have already exchanged friend requests out-of-band.
    ///
    /// @return The friend number on success, or an error string.
    [[nodiscard]] util::Expected<uint32_t, std::string> add_friend_norequest(
        const PublicKeyArray& public_key);

    /// Remove a friend.
    ///
    /// @return true if the friend was removed, false if not found.
    bool remove_friend(uint32_t friend_number);

    /// Check whether a given friend number is currently connected.
    [[nodiscard]] bool is_friend_connected(uint32_t friend_number) const;

    /// Get the connection state of a friend.
    [[nodiscard]] FriendState get_friend_connection_status(uint32_t friend_number) const;

    /// Get the public key for a given friend number.
    [[nodiscard]] util::Expected<PublicKeyArray, std::string> get_friend_public_key(
        uint32_t friend_number) const;

    /// Get the friend number for a given public key.
    [[nodiscard]] util::Expected<uint32_t, std::string> friend_by_public_key(
        const PublicKeyArray& public_key) const;

    /// Return the list of all known friend numbers.
    [[nodiscard]] std::vector<uint32_t> get_friend_list() const;

    /// Return information about all known friends.
    [[nodiscard]] std::vector<FriendInfo> get_friend_info_list() const;

    // -----------------------------------------------------------------
    // Data transfer
    // -----------------------------------------------------------------

    /// Outcome of a lossless send attempt — split into retryable backpressure
    /// vs. permanent failure so callers can decide whether to park the frame
    /// in a retry queue (SENDQ pressure clears in milliseconds) or drop it
    /// outright (peer disconnected, frame malformed, etc.).
    enum class LosslessSendOutcome : std::uint8_t {
        Sent,           ///< Accepted by toxcore.
        SendqFull,      ///< TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ — transient.
        PermanentFail,  ///< Any other error: not connected, invalid, too long.
    };

    /// Typed variant of `send_lossless_packet` that distinguishes transient
    /// backpressure from permanent failure. Prefer this for control-frame
    /// paths that may want to queue-and-retry the SENDQ-full case but bail
    /// out (and surface the failure to the caller) for permanent errors.
    [[nodiscard]] LosslessSendOutcome send_lossless_packet_typed(uint32_t friend_number,
                                                                 const uint8_t* data,
                                                                 std::size_t length);

    /// Send a custom lossless packet to a friend.
    ///
    /// The first byte of `data` must be in the range [160, 191].
    ///
    /// @return true on success, false on any failure (transient or permanent
    ///         — for the distinction use `send_lossless_packet_typed`).
    [[nodiscard]] bool send_lossless_packet(uint32_t friend_number, const uint8_t* data,
                                            std::size_t length);

    /// Convenience overload accepting a vector.
    [[nodiscard]] bool send_lossless_packet(uint32_t friend_number,
                                            const std::vector<uint8_t>& data);

    /// Send a custom lossy packet to a friend.
    ///
    /// The first byte of `data` must be in the range [200, 254].
    ///
    /// @return true on success, false on failure.
    [[nodiscard]] bool send_lossy_packet(uint32_t friend_number, const uint8_t* data,
                                         std::size_t length);

    /// Send a text message to a friend.
    ///
    /// @return The message ID on success, or an error string.
    [[nodiscard]] util::Expected<uint32_t, std::string> send_message(uint32_t friend_number,
                                                                     std::string_view message);

    // -----------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------

    /// Register a callback for incoming friend requests.
    void set_on_friend_request(FriendRequestCallback cb);

    /// Register a callback for friend connection status changes.
    void set_on_friend_connection(FriendConnectionCallback cb);

    /// Register a callback for incoming lossless packets.
    void set_on_lossless_packet(FriendLosslessPacketCallback cb);

    /// Register a callback for incoming lossy packets.
    void set_on_lossy_packet(FriendLossyPacketCallback cb);

    /// Register a callback for incoming text messages.
    void set_on_friend_message(FriendMessageCallback cb);

    /// Register a callback for self connection status changes.
    void set_on_self_connection(SelfConnectionCallback cb);

    // -----------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------

    /// Return true if connected to the Tox DHT.
    [[nodiscard]] bool is_connected() const noexcept;

    /// Return the current iteration interval in milliseconds (as reported
    /// by tox_iteration_interval).
    [[nodiscard]] uint32_t iteration_interval() const;

    /// Manually save the Tox state to disk.
    ///
    /// This is also done automatically on stop().
    ///
    /// @return true on success, false on I/O failure.
    bool save() const;

    // -----------------------------------------------------------------
    // Testing hooks
    // -----------------------------------------------------------------

    /// Queue a friend request event without invoking toxcore.
    void enqueue_friend_request_for_test(const PublicKeyArray& public_key,
                                         std::string_view message);

    /// Drain queued callback events. Intended for tests.
    void dispatch_pending_events_for_test();

   private:
    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Execute @p fn on the dedicated Tox thread and return its result.
    ///
    /// toxcore is not thread-safe and additionally requires that every
    /// `tox_*` call originate from the same thread that drives
    /// `tox_iterate`. This helper enforces that invariant for the public
    /// API:
    ///   * If the caller is already running on the Tox thread (e.g. a
    ///     toxcore callback dispatched from `run_loop` re-enters a public
    ///     method), @p fn is executed inline — re-posting and then waiting
    ///     on the same thread would self-deadlock.
    ///   * If the iterate thread is not running, @p fn runs inline on the
    ///     caller (single-threaded init / shutdown paths). The Tox mutex
    ///     still serialises against any in-flight iterate.
    ///   * Otherwise @p fn is posted to the Tox thread and the caller
    ///     blocks on a future until it has executed.
    template <typename Fn>
    std::invoke_result_t<Fn> run_on_tox_thread(Fn&& fn);

    /// True if the calling thread is the dedicated Tox iterate thread.
    [[nodiscard]] bool on_tox_thread() const noexcept;

    /// Drain and execute tasks posted via run_on_tox_thread(). Runs on the
    /// Tox thread from within run_loop().
    void process_tox_tasks();

    /// The tox_iterate loop executed on the dedicated thread.
    void run_loop();

    /// Register all toxcore callbacks on the Tox instance.
    void register_callbacks();

    /// Load save data from disk.
    ///
    /// @return The loaded bytes, or an empty vector if no file exists.
    [[nodiscard]] std::vector<uint8_t> load_save_data() const;

    /// Write current Tox state to disk.
    ///
    /// Routes onto the Tox thread and acquires tox_mutex_ before reading the
    /// save data out of the Tox instance.
    [[nodiscard]] bool write_save_data() const;

    /// Write current Tox state to disk, assuming the caller is already on the
    /// Tox thread and already holds tox_mutex_. Used by public methods that
    /// mutate the friend list and want to persist atomically within the same
    /// critical section.
    [[nodiscard]] bool write_save_data_locked() const;

    /// Return the full path to the save file.
    [[nodiscard]] std::filesystem::path save_file_path() const;

    /// Drain queued callback events outside toxcore locks.
    void dispatch_pending_events();

    template <typename Event>
    void enqueue_event(Event&& event);

    // -----------------------------------------------------------------
    // Static toxcore callback trampolines
    // -----------------------------------------------------------------

    static void on_friend_request_cb(Tox* tox, const uint8_t* public_key, const uint8_t* message,
                                     size_t length, void* user_data);

    static void on_friend_connection_status_cb(Tox* tox, uint32_t friend_number,
                                               TOX_CONNECTION connection_status, void* user_data);

    static void on_friend_lossless_packet_cb(Tox* tox, uint32_t friend_number, const uint8_t* data,
                                             size_t length, void* user_data);

    static void on_friend_lossy_packet_cb(Tox* tox, uint32_t friend_number, const uint8_t* data,
                                          size_t length, void* user_data);

    static void on_friend_message_cb(Tox* tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                                     const uint8_t* message, size_t length, void* user_data);

    static void on_self_connection_status_cb(Tox* tox, TOX_CONNECTION connection_status,
                                             void* user_data);

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    /// The Tox instance (owned).
    ToxPtr tox_{nullptr};

    /// Configuration snapshot taken at initialize().
    ToxAdapterConfig config_;

    /// Guards access to the Tox instance for thread-safe public methods.
    mutable std::mutex tox_mutex_;

    /// Dedicated thread running tox_iterate().
    std::thread iterate_thread_;

    /// Identifier of the iterate thread, published once run_loop() starts so
    /// run_on_tox_thread() can detect re-entrant calls and run them inline.
    /// `iterate_thread_id_valid_` gates reads until the id is set.
    std::thread::id iterate_thread_id_{};
    std::atomic<bool> iterate_thread_id_valid_{false};

    /// Queue of toxcore work items posted from other threads, executed on the
    /// iterate thread inside run_loop(). Each task carries its own result
    /// plumbing (captured promise), so this stores type-erased closures.
    std::deque<std::function<void()>> tox_tasks_;
    std::mutex tox_tasks_mutex_;

    /// Flag signalling the iterate thread to stop.
    std::atomic<bool> running_{false};

    /// Optional watchdog observer. Not owned. When set, the iterate loop
    /// bumps the watchdog's heartbeat after every successful tox_iterate
    /// return so the main-thread observer can detect a wedge.
    std::atomic<class toxtunnel::tox::ToxWatchdog*> watchdog_{nullptr};

    /// Wakeup primitive that lets the iterate loop sleep for up to
    /// tox_iteration_interval() ms but exit early when there is new data to
    /// send or when stop() is called. Critical for interactive latency: idle
    /// iteration intervals run ~50ms, so a fresh outbound packet without this
    /// could sit waiting in toxcore's queue for that long before being pushed.
    mutable std::mutex wake_mutex_;
    std::condition_variable wake_cv_;

    /// Whether initialize() has been called successfully.
    std::atomic<bool> initialized_{false};

    /// Whether the node is currently connected to the DHT.
    std::atomic<bool> connected_{false};

    struct FriendRequestEvent {
        PublicKeyArray public_key{};
        std::string message;
    };

    struct FriendConnectionEvent {
        uint32_t friend_number = 0;
        bool connected = false;
    };

    struct FriendLosslessPacketEvent {
        uint32_t friend_number = 0;
        std::vector<uint8_t> data;
    };

    struct FriendLossyPacketEvent {
        uint32_t friend_number = 0;
        std::vector<uint8_t> data;
    };

    struct FriendMessageEvent {
        uint32_t friend_number = 0;
        std::string message;
    };

    struct SelfConnectionEvent {
        bool connected = false;
    };

    using CallbackEvent =
        std::variant<FriendRequestEvent, FriendConnectionEvent, FriendLosslessPacketEvent,
                     FriendLossyPacketEvent, FriendMessageEvent, SelfConnectionEvent>;

    mutable std::mutex event_mutex_;
    std::vector<CallbackEvent> pending_events_;

    // Callback storage (guarded by callback_mutex_).
    mutable std::mutex callback_mutex_;
    FriendRequestCallback on_friend_request_;
    FriendConnectionCallback on_friend_connection_;
    FriendLosslessPacketCallback on_lossless_packet_;
    FriendLossyPacketCallback on_lossy_packet_;
    FriendMessageCallback on_friend_message_;
    SelfConnectionCallback on_self_connection_;
};

template <typename Event>
void ToxAdapter::enqueue_event(Event&& event) {
    std::lock_guard<std::mutex> lock(event_mutex_);
    pending_events_.emplace_back(std::forward<Event>(event));
}

template <typename Fn>
std::invoke_result_t<Fn> ToxAdapter::run_on_tox_thread(Fn&& fn) {
    using Result = std::invoke_result_t<Fn>;

    // Fast / re-entrant path: already on the Tox thread, or no iterate thread
    // is running yet (init/shutdown). Run inline. tox_mutex_ inside fn (held
    // by the individual callers) serialises against an in-flight iterate.
    if (on_tox_thread() || !running_.load(std::memory_order_acquire)) {
        return std::forward<Fn>(fn)();
    }

    // Cross-thread path: post the work and block until the Tox thread runs it.
    {
        std::unique_lock<std::mutex> lock(tox_tasks_mutex_);
        // Re-check running_ under the queue lock. stop() flips running_ to
        // false and then drains the queue under this same lock, so observing
        // running_ == true here guarantees our task will be picked up by
        // either run_loop() or stop()'s post-join drain; observing false means
        // the thread is gone and we must run inline to avoid a stuck future.
        if (running_.load(std::memory_order_acquire)) {
            // The promise is held by a shared_ptr so the closure remains
            // copy-constructible: tox_tasks_ is a std::function queue, which
            // requires copyable callables (a moved-in std::promise would make
            // the lambda move-only and fail to compile).
            auto promise = std::make_shared<std::promise<Result>>();
            std::future<Result> future = promise->get_future();
            tox_tasks_.emplace_back([fn = std::forward<Fn>(fn), promise]() mutable {
                try {
                    if constexpr (std::is_void_v<Result>) {
                        fn();
                        promise->set_value();
                    } else {
                        promise->set_value(fn());
                    }
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            });
            lock.unlock();
            // Wake the iterate loop so the task is picked up without waiting
            // for the next idle tick.
            wake_cv_.notify_one();
            return future.get();
        }
    }

    // Thread stopped between the outer check and acquiring the lock; run inline.
    return std::forward<Fn>(fn)();
}

}  // namespace toxtunnel::tox
