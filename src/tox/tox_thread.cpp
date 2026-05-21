#include "toxtunnel/tox/tox_thread.hpp"

#include <chrono>
#include <cstring>
#include <stdexcept>

#include "toxtunnel/tox/tox_watchdog.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"

namespace toxtunnel::tox {

// ===========================================================================
// EventQueue
// ===========================================================================

void EventQueue::push(Event event) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(event));
}

bool EventQueue::try_pop(Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        return false;
    }
    event = std::move(queue_.front());
    queue_.pop();
    return true;
}

std::size_t EventQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

// ===========================================================================
// ToxThread -- construction / destruction
// ===========================================================================

ToxThread::ToxThread(const Config& config) : config_(config) {}

ToxThread::~ToxThread() {
    stop();
}

// ===========================================================================
// Thread lifecycle
// ===========================================================================

void ToxThread::start() {
    if (running_.exchange(true)) {
        return;  // Already running.
    }

    // S30 (2026-05-20 follow-up): init_tox can throw on
    // tox_options_new / tox_new failure. The previous code left
    // `running_ = true` in that case, so a later `is_running()` lied
    // (no thread had been started), `stop()` was a no-op (joinable
    // returned false), and any caller waiting on a posted command's
    // future would block forever — the queue's draining loop never
    // existed. Roll the flag back and rethrow so callers see the real
    // failure.
    try {
        init_tox();
    } catch (...) {
        running_.store(false);
        throw;
    }
    thread_ = std::thread([this]() { run_loop(); });
}

void ToxThread::stop() {
    if (!running_.exchange(false)) {
        return;  // Not running.
    }

    // Wake the thread if it is sleeping on the condition variable.
    command_cv_.notify_one();

    if (thread_.joinable()) {
        thread_.join();
    }

    // S24 / H-14 (2026-05-20 review): the loop can exit with commands
    // still sitting in the queue — e.g. a caller posted SendData and
    // was waiting on its future when stop() flipped running_ to false
    // and the loop bailed out before draining. Leaving those promises
    // unfulfilled deadlocks any caller blocked on future::get(). Fail
    // them explicitly with empty result vectors so callers unwind
    // cleanly. Empty result matches the existing "operation failed"
    // convention used elsewhere in process_commands (see e.g. the
    // short-data guards in AddFriend / SendData).
    std::queue<Command> leftover;
    {
        std::lock_guard<std::mutex> lock(command_mutex_);
        std::swap(leftover, command_queue_);
    }
    while (!leftover.empty()) {
        try {
            leftover.front().result.set_value({});
        } catch (const std::future_error&) {
            // Promise already satisfied or abandoned; nothing to do.
        }
        leftover.pop();
    }

    save_state();
}

// ===========================================================================
// Tox initialisation
// ===========================================================================

void ToxThread::init_tox() {
    auto save_path = save_file_path();

    // Use the existing tox_save helper to create-or-load a Tox instance.
    // We build custom Tox_Options to pass our configuration through.
    TOX_ERR_OPTIONS_NEW opts_err;
    Tox_Options* options = tox_options_new(&opts_err);
    if (!options) {
        throw std::runtime_error("Failed to allocate Tox_Options");
    }

    tox_options_set_udp_enabled(options, config_.udp_enabled);
    tox_options_set_tcp_port(options, config_.tcp_relay_port);

    auto result = create_or_load_tox(save_path, options);
    tox_options_free(options);

    if (!result.has_value()) {
        throw std::runtime_error("Failed to create Tox instance: " + result.error());
    }

    tox_ = std::move(result.value());

    // Register toxcore callbacks.
    tox_callback_friend_request(tox_.get(), on_friend_request);
    tox_callback_friend_connection_status(tox_.get(), on_friend_connection_status);
    tox_callback_friend_message(tox_.get(), on_friend_message);
    tox_callback_friend_lossless_packet(tox_.get(), on_friend_lossless_packet);

    util::Logger::info("Tox instance initialized");

    bootstrap();
}

void ToxThread::bootstrap() {
    for (const auto& node : config_.bootstrap_nodes) {
        TOX_ERR_BOOTSTRAP err;
        bool ok =
            tox_bootstrap(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(), &err);

        if (ok && err == TOX_ERR_BOOTSTRAP_OK) {
            util::Logger::debug("Bootstrapped to {}:{}", node.ip, node.port);
        } else {
            util::Logger::warn("Failed to bootstrap to {}:{} (error {})", node.ip, node.port,
                               static_cast<int>(err));
        }
    }
}

// ===========================================================================
// Save-data persistence
// ===========================================================================

void ToxThread::save_state() {
    if (!tox_) {
        return;
    }

    auto result = save_tox_data(tox_.get(), save_file_path());
    if (!result.has_value()) {
        util::Logger::error("Failed to save Tox state: {}", result.error());
    }
}

std::filesystem::path ToxThread::save_file_path() const {
    return config_.data_dir / config_.save_filename;
}

// ===========================================================================
// Event loop
// ===========================================================================

void ToxThread::run_loop() {
    util::Logger::info("Tox event-loop thread started");

    while (running_.load()) {
        // 1. Let toxcore process network events and invoke our callbacks.
        //    The `this` pointer is passed as user_data so that the static
        //    callback trampolines can reach the ToxThread instance.
        const auto iterate_start = std::chrono::steady_clock::now();
        tox_iterate(tox_.get(), this);
        // The watchdog heartbeat is the *first* line after the iterate
        // returns so a hang inside `tox_iterate` is detected by the
        // main-thread observer; a stall before this line will trip the
        // configured deadline.
        if (auto* wd = watchdog_.load(std::memory_order_acquire)) {
            wd->heartbeat();
        }
        const auto iterate_end = std::chrono::steady_clock::now();
        util::MetricsRegistry::instance().observe_iterate_lag_ms(
            std::chrono::duration<double, std::milli>(iterate_end - iterate_start).count());

        // 2. Dispatch commands queued from other threads.
        process_commands();

        // 3. Dispatch events (from callbacks) to registered handlers.
        process_events();

        // 4. Sleep for toxcore's recommended interval before iterating
        // again — but wake early if another thread posts a command or
        // requests shutdown. Previously this used a plain `sleep_for`,
        // which ignored `command_cv_` entirely: notifications from
        // command-posting paths (and from `stop()`) were dropped, so
        // Shutdown could sit on the queue for ~50 ms and outbound data
        // had the same worst-case latency.
        const uint32_t interval_ms = tox_iteration_interval(tox_.get());
        std::unique_lock<std::mutex> lock(command_mutex_);
        command_cv_.wait_for(lock, std::chrono::milliseconds(interval_ms),
                             [this]() { return !command_queue_.empty() || !running_.load(); });
    }

    util::Logger::info("Tox event-loop thread stopped");
}

// ===========================================================================
// Command processing
// ===========================================================================

void ToxThread::process_commands() {
    // Swap out the queue under the lock to minimise contention.
    std::queue<Command> local_queue;
    {
        std::lock_guard<std::mutex> lock(command_mutex_);
        std::swap(local_queue, command_queue_);
    }

    while (!local_queue.empty()) {
        Command cmd = std::move(local_queue.front());
        local_queue.pop();

        switch (cmd.type) {
            // ---------------------------------------------------------
            // GetToxId
            // ---------------------------------------------------------
            case Command::Type::GetToxId: {
                std::vector<uint8_t> id_bytes(tox_address_size());
                tox_self_get_address(tox_.get(), id_bytes.data());
                cmd.result.set_value(std::move(id_bytes));
                break;
            }

            // ---------------------------------------------------------
            // AddFriend
            // Layout: [kToxIdBytes of ToxId bytes][message bytes...]
            // ---------------------------------------------------------
            case Command::Type::AddFriend: {
                if (cmd.data.size() < kToxIdBytes) {
                    cmd.result.set_value({});  // Empty = error.
                    break;
                }

                const uint8_t* id_ptr = cmd.data.data();
                const uint8_t* msg_ptr = cmd.data.data() + kToxIdBytes;
                std::size_t msg_len = cmd.data.size() - kToxIdBytes;

                TOX_ERR_FRIEND_ADD add_err;
                uint32_t friend_num =
                    tox_friend_add(tox_.get(), id_ptr, msg_ptr, msg_len, &add_err);

                if (add_err == TOX_ERR_FRIEND_ADD_OK) {
                    util::Logger::info("Added friend #{}", friend_num);
                    save_state();
                } else {
                    util::Logger::warn("Failed to add friend (error {})",
                                       static_cast<int>(add_err));
                }

                // Return friend number (4 bytes LE) on success, or empty on error.
                std::vector<uint8_t> result_data;
                if (add_err == TOX_ERR_FRIEND_ADD_OK) {
                    result_data.resize(sizeof(uint32_t));
                    std::memcpy(result_data.data(), &friend_num, sizeof(friend_num));
                }
                cmd.result.set_value(std::move(result_data));
                break;
            }

            // ---------------------------------------------------------
            // SendData
            // Layout: [4 bytes friend_number LE][payload bytes...]
            // ---------------------------------------------------------
            case Command::Type::SendData: {
                if (cmd.data.size() < sizeof(uint32_t)) {
                    cmd.result.set_value({});
                    break;
                }

                uint32_t friend_number = 0;
                std::memcpy(&friend_number, cmd.data.data(), sizeof(friend_number));

                const uint8_t* payload = cmd.data.data() + sizeof(uint32_t);
                std::size_t payload_len = cmd.data.size() - sizeof(uint32_t);

                TOX_ERR_FRIEND_CUSTOM_PACKET pkt_err;
                bool ok = tox_friend_send_lossless_packet(tox_.get(), friend_number, payload,
                                                          payload_len, &pkt_err);

                if (!ok) {
                    util::Logger::warn("Failed to send lossless packet to friend #{} (error {})",
                                       friend_number, static_cast<int>(pkt_err));
                }

                cmd.result.set_value({});
                break;
            }

            // ---------------------------------------------------------
            // Shutdown
            // ---------------------------------------------------------
            case Command::Type::Shutdown:
                running_.store(false);
                cmd.result.set_value({});
                break;
        }
    }
}

// ===========================================================================
// Event dispatching
// ===========================================================================

void ToxThread::process_events() {
    EventQueue::Event event;

    while (event_queue_.try_pop(event)) {
        switch (event.type) {
            case EventQueue::Event::Type::FriendRequest:
                if (friend_request_handler_) {
                    std::string_view message(reinterpret_cast<const char*>(event.data.data()),
                                             event.data.size());
                    friend_request_handler_(event.public_key, message);
                }
                break;

            case EventQueue::Event::Type::FriendConnected:
                if (friend_connection_handler_) {
                    friend_connection_handler_(event.friend_number, true);
                }
                break;

            case EventQueue::Event::Type::FriendDisconnected:
                if (friend_connection_handler_) {
                    friend_connection_handler_(event.friend_number, false);
                }
                break;

            case EventQueue::Event::Type::FriendMessage:
                if (friend_message_handler_) {
                    std::string_view message(reinterpret_cast<const char*>(event.data.data()),
                                             event.data.size());
                    friend_message_handler_(event.friend_number, message);
                }
                break;

            case EventQueue::Event::Type::DataReceived:
                if (data_received_handler_) {
                    data_received_handler_(event.friend_number, event.data.data(),
                                           event.data.size());
                }
                break;
        }
    }
}

// ===========================================================================
// Static toxcore callbacks
// ===========================================================================

void ToxThread::on_friend_request(Tox* /*tox*/, const uint8_t* public_key, const uint8_t* message,
                                  size_t length, void* user_data) {
    auto* self = static_cast<ToxThread*>(user_data);

    EventQueue::Event event;
    event.type = EventQueue::Event::Type::FriendRequest;
    std::copy_n(public_key, kPublicKeyBytes, event.public_key.begin());
    event.data.assign(message, message + length);

    self->event_queue_.push(std::move(event));
}

void ToxThread::on_friend_connection_status(Tox* /*tox*/, uint32_t friend_number,
                                            TOX_CONNECTION status, void* user_data) {
    auto* self = static_cast<ToxThread*>(user_data);

    EventQueue::Event event;
    event.type = (status != TOX_CONNECTION_NONE) ? EventQueue::Event::Type::FriendConnected
                                                 : EventQueue::Event::Type::FriendDisconnected;
    event.friend_number = friend_number;

    self->event_queue_.push(std::move(event));
}

void ToxThread::on_friend_message(Tox* /*tox*/, uint32_t friend_number, TOX_MESSAGE_TYPE /*type*/,
                                  const uint8_t* message, size_t length, void* user_data) {
    auto* self = static_cast<ToxThread*>(user_data);

    EventQueue::Event event;
    event.type = EventQueue::Event::Type::FriendMessage;
    event.friend_number = friend_number;
    event.data.assign(message, message + length);

    self->event_queue_.push(std::move(event));
}

void ToxThread::on_friend_lossless_packet(Tox* /*tox*/, uint32_t friend_number, const uint8_t* data,
                                          size_t length, void* user_data) {
    auto* self = static_cast<ToxThread*>(user_data);

    EventQueue::Event event;
    event.type = EventQueue::Event::Type::DataReceived;
    event.friend_number = friend_number;
    event.data.assign(data, data + length);

    self->event_queue_.push(std::move(event));
}

// ===========================================================================
// Event handler registration
// ===========================================================================

void ToxThread::set_friend_request_handler(FriendRequestHandler handler) {
    friend_request_handler_ = std::move(handler);
}

void ToxThread::set_friend_connection_handler(FriendConnectionHandler handler) {
    friend_connection_handler_ = std::move(handler);
}

void ToxThread::set_friend_message_handler(FriendMessageHandler handler) {
    friend_message_handler_ = std::move(handler);
}

void ToxThread::set_data_received_handler(DataReceivedHandler handler) {
    data_received_handler_ = std::move(handler);
}

void ToxThread::set_watchdog(class ToxWatchdog* watchdog) {
    watchdog_.store(watchdog, std::memory_order_release);
}

// ===========================================================================
// Commands -- public thread-safe API
// ===========================================================================

std::future<ToxId> ToxThread::get_tox_id() {
    Command cmd;
    cmd.type = Command::Type::GetToxId;

    auto future = cmd.result.get_future();

    {
        std::lock_guard<std::mutex> lock(command_mutex_);
        command_queue_.push(std::move(cmd));
    }
    command_cv_.notify_one();

    // Wrap the raw-bytes future into a ToxId future.
    return std::async(std::launch::deferred, [f = std::move(future)]() mutable -> ToxId {
        std::vector<uint8_t> bytes = f.get();
        if (bytes.size() == kToxIdBytes) {
            ToxIdArray arr{};
            std::copy_n(bytes.data(), kToxIdBytes, arr.begin());
            return ToxId::from_bytes_unchecked(arr);
        }
        // Should not happen if toxcore is behaving.
        ToxIdArray empty{};
        return ToxId::from_bytes_unchecked(empty);
    });
}

std::future<void> ToxThread::add_friend(const ToxId& id, const std::string& message) {
    Command cmd;
    cmd.type = Command::Type::AddFriend;

    // Pack the full Tox ID bytes followed by the UTF-8 message.
    const auto& id_bytes = id.bytes();
    cmd.data.reserve(id_bytes.size() + message.size());
    cmd.data.insert(cmd.data.end(), id_bytes.begin(), id_bytes.end());
    cmd.data.insert(cmd.data.end(), message.begin(), message.end());

    auto future = cmd.result.get_future();

    {
        std::lock_guard<std::mutex> lock(command_mutex_);
        command_queue_.push(std::move(cmd));
    }
    command_cv_.notify_one();

    return std::async(std::launch::deferred, [f = std::move(future)]() mutable {
        f.get();  // Block until the Tox thread fulfils the promise.
    });
}

std::future<void> ToxThread::send_data(uint32_t friend_number, const std::vector<uint8_t>& data) {
    Command cmd;
    cmd.type = Command::Type::SendData;

    // Pack: [4 bytes friend_number LE] [payload bytes...]
    cmd.data.resize(sizeof(uint32_t) + data.size());
    std::memcpy(cmd.data.data(), &friend_number, sizeof(friend_number));
    std::copy(data.begin(), data.end(),
              cmd.data.begin() + static_cast<std::ptrdiff_t>(sizeof(uint32_t)));

    auto future = cmd.result.get_future();

    {
        std::lock_guard<std::mutex> lock(command_mutex_);
        command_queue_.push(std::move(cmd));
    }
    command_cv_.notify_one();

    return std::async(std::launch::deferred, [f = std::move(future)]() mutable { f.get(); });
}

}  // namespace toxtunnel::tox
