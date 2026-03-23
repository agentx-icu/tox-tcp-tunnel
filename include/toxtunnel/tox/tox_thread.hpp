#pragma once

#include <toxcore/tox.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "toxtunnel/tox/tox_save.hpp"
#include "toxtunnel/tox/types.hpp"

namespace toxtunnel::tox {

// ---------------------------------------------------------------------------
// Command -- cross-thread command for the Tox event-loop thread
// ---------------------------------------------------------------------------

/// Represents a command that can be posted from any thread and will be
/// executed on the Tox thread (the only thread allowed to call toxcore).
///
/// The result promise is fulfilled by the Tox thread once the command
/// has been processed.
struct Command {
    enum class Type {
        GetToxId,   ///< Retrieve the local Tox address.
        AddFriend,  ///< Send a friend request.
        SendData,   ///< Send a lossless custom packet.
        Shutdown,   ///< Gracefully terminate the event loop.
    };

    Type type;

    /// Opaque payload whose layout depends on @p type.
    std::vector<uint8_t> data;

    /// Promise fulfilled by the Tox thread.  The byte vector is the
    /// result payload (also type-dependent).
    std::promise<std::vector<uint8_t>> result;
};

// ---------------------------------------------------------------------------
// EventQueue -- thread-safe event queue (Tox-thread -> other threads)
// ---------------------------------------------------------------------------

/// Thread-safe queue into which the Tox thread pushes events and from
/// which the application drains them.
///
/// The current implementation uses a mutex-guarded std::queue.  The
/// interface is designed so that a lock-free implementation can be
/// swapped in later without changing callers.
class EventQueue {
   public:
    struct Event {
        enum class Type {
            FriendRequest,       ///< Incoming friend request.
            FriendConnected,     ///< A friend came online.
            FriendDisconnected,  ///< A friend went offline.
            FriendMessage,       ///< Text message from a friend.
            DataReceived,        ///< Lossless custom packet from a friend.
        };

        Type type;
        uint32_t friend_number{0};
        std::vector<uint8_t> data;    ///< Message text or packet payload.
        PublicKeyArray public_key{};  ///< Set for FriendRequest events.
    };

    /// Push an event (called from Tox callbacks, which run on the Tox thread).
    void push(Event event);

    /// Non-blocking pop.  Returns true and fills @p event on success.
    bool try_pop(Event& event);

    /// Current queue depth.
    [[nodiscard]] std::size_t size() const;

   private:
    mutable std::mutex mutex_;
    std::queue<Event> queue_;
};

// ---------------------------------------------------------------------------
// ToxThread -- dedicated thread for the toxcore event loop
// ---------------------------------------------------------------------------

/// Manages a dedicated thread that owns a Tox instance.
///
/// All toxcore API calls are serialised on this thread because the
/// library is not thread-safe.  Other threads communicate with the Tox
/// thread via a command queue; the Tox thread publishes events back via
/// an EventQueue.
///
/// Typical usage:
/// @code
///   ToxThread::Config cfg;
///   cfg.data_dir   = "/var/lib/toxtunnel";
///   cfg.udp_enabled = true;
///
///   ToxThread tox(cfg);
///   tox.set_friend_request_handler([](const PublicKeyArray& pk, std::string_view msg) {
///       // ...
///   });
///   tox.start();
///   // ... application runs ...
///   tox.stop();
/// @endcode
class ToxThread {
   public:
    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    struct Config {
        /// Directory where the Tox save-data file is stored / loaded.
        std::filesystem::path data_dir;

        /// Filename of the save file within @p data_dir.
        std::string save_filename = "tox_save.dat";

        /// Enable UDP transport.
        bool udp_enabled = true;

        /// Port for the Tox TCP relay (0 = disabled).
        uint16_t tcp_relay_port = 0;

        /// DHT bootstrap nodes.
        std::vector<BootstrapNode> bootstrap_nodes;
    };

    // -----------------------------------------------------------------
    // Construction / destruction
    // -----------------------------------------------------------------

    explicit ToxThread(const Config& config);
    ~ToxThread();

    // Non-copyable, non-movable (owns a thread).
    ToxThread(const ToxThread&) = delete;
    ToxThread& operator=(const ToxThread&) = delete;
    ToxThread(ToxThread&&) = delete;
    ToxThread& operator=(ToxThread&&) = delete;

    // -----------------------------------------------------------------
    // Thread lifecycle
    // -----------------------------------------------------------------

    /// Create the Tox instance and start the event-loop thread.
    ///
    /// @throws std::runtime_error if the Tox instance cannot be created.
    void start();

    /// Signal the thread to stop, join it, and save Tox data.
    void stop();

    /// Return true if the event-loop thread is currently running.
    [[nodiscard]] bool is_running() const noexcept { return running_.load(); }

    // -----------------------------------------------------------------
    // Commands (thread-safe -- may be called from any thread)
    // -----------------------------------------------------------------

    /// Retrieve the local Tox address (38 bytes) asynchronously.
    std::future<ToxId> get_tox_id();

    /// Send a friend request.
    std::future<void> add_friend(const ToxId& id, const std::string& message);

    /// Send raw data to a friend via lossless custom packets.
    std::future<void> send_data(uint32_t friend_number, const std::vector<uint8_t>& data);

    // -----------------------------------------------------------------
    // Event handler registration (set before calling start())
    // -----------------------------------------------------------------

    /// Called when a friend request is received.
    using FriendRequestHandler =
        std::function<void(const PublicKeyArray& public_key, std::string_view message)>;

    /// Called when a friend's connection status changes.
    using FriendConnectionHandler = std::function<void(uint32_t friend_number, bool connected)>;

    /// Called when a text message is received from a friend.
    using FriendMessageHandler =
        std::function<void(uint32_t friend_number, std::string_view message)>;

    /// Called when a lossless custom packet is received from a friend.
    using DataReceivedHandler =
        std::function<void(uint32_t friend_number, const uint8_t* data, std::size_t length)>;

    void set_friend_request_handler(FriendRequestHandler handler);
    void set_friend_connection_handler(FriendConnectionHandler handler);
    void set_friend_message_handler(FriendMessageHandler handler);
    void set_data_received_handler(DataReceivedHandler handler);

   private:
    // -----------------------------------------------------------------
    // Internal methods (all run on the Tox thread unless noted)
    // -----------------------------------------------------------------

    /// Main loop: iterate toxcore, process commands and events.
    void run_loop();

    /// Allocate and configure the Tox instance.
    void init_tox();

    /// Bootstrap the DHT from the configured nodes.
    void bootstrap();

    /// Persist Tox state to disk via the tox_save helpers.
    void save_state();

    /// Return the full path to the save file.
    [[nodiscard]] std::filesystem::path save_file_path() const;

    /// Drain the command queue and execute each command on the Tox thread.
    void process_commands();

    /// Drain the event queue and dispatch to registered handlers.
    void process_events();

    // -----------------------------------------------------------------
    // Static toxcore callbacks
    // -----------------------------------------------------------------

    static void on_friend_request(Tox* tox, const uint8_t* public_key, const uint8_t* message,
                                  size_t length, void* user_data);

    static void on_friend_connection_status(Tox* tox, uint32_t friend_number, TOX_CONNECTION status,
                                            void* user_data);

    static void on_friend_message(Tox* tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                                  const uint8_t* message, size_t length, void* user_data);

    static void on_friend_lossless_packet(Tox* tox, uint32_t friend_number, const uint8_t* data,
                                          size_t length, void* user_data);

    // -----------------------------------------------------------------
    // Data members
    // -----------------------------------------------------------------

    Config config_;

    /// The Tox instance (owned).  Uses ToxPtr from tox_save.hpp.
    ToxPtr tox_{nullptr};

    /// Tox event-loop thread.
    std::thread thread_;

    /// True while run_loop() should keep iterating.
    std::atomic<bool> running_{false};

    /// Outbound event queue (Tox callbacks -> application handlers).
    EventQueue event_queue_;

    /// Inbound command queue (application threads -> Tox thread).
    std::queue<Command> command_queue_;
    std::mutex command_mutex_;
    std::condition_variable command_cv_;

    /// Registered event handlers.
    FriendRequestHandler friend_request_handler_;
    FriendConnectionHandler friend_connection_handler_;
    FriendMessageHandler friend_message_handler_;
    DataReceivedHandler data_received_handler_;
};

}  // namespace toxtunnel::tox
