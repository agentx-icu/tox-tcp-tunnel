#pragma once

#include <toxcore/tox.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <variant>
#include <vector>

#include "toxtunnel/tox/bootstrap_source.hpp"
#include "toxtunnel/tox/types.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tox {

// ---------------------------------------------------------------------------
// Tox instance RAII deleter
// ---------------------------------------------------------------------------

/// Custom deleter for Tox pointer, used with std::unique_ptr.
struct ToxDeleter {
    void operator()(Tox* tox) const noexcept;
};

/// Owning smart pointer for a Tox instance.
using ToxPtr = std::unique_ptr<Tox, ToxDeleter>;

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
/// ToxAdapter manages a Tox instance on a dedicated thread.  All toxcore
/// calls are serialized through this thread to satisfy the library's single-
/// threaded requirement.
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

    /// Send a custom lossless packet to a friend.
    ///
    /// The first byte of `data` must be in the range [160, 191].
    ///
    /// @return true on success, false on failure.
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

    /// The tox_iterate loop executed on the dedicated thread.
    void run_loop();

    /// Register all toxcore callbacks on the Tox instance.
    void register_callbacks();

    /// Load save data from disk.
    ///
    /// @return The loaded bytes, or an empty vector if no file exists.
    [[nodiscard]] std::vector<uint8_t> load_save_data() const;

    /// Write current Tox state to disk.
    [[nodiscard]] bool write_save_data() const;

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

    /// Flag signalling the iterate thread to stop.
    std::atomic<bool> running_{false};

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

}  // namespace toxtunnel::tox
