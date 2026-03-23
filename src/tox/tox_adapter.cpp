#include "toxtunnel/tox/tox_adapter.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <thread>

#include "toxtunnel/tox/bootstrap_source.hpp"
#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tox {

// ===========================================================================
// ToxDeleter
// ===========================================================================

void ToxDeleter::operator()(Tox* tox) const noexcept {
    if (tox) {
        tox_kill(tox);
    }
}

// ===========================================================================
// Helpers (anonymous namespace)
// ===========================================================================

namespace {

/// Map a TOX_CONNECTION value to our FriendState enum.
FriendState connection_to_state(TOX_CONNECTION conn) {
    switch (conn) {
        case TOX_CONNECTION_TCP:
            return FriendState::TCP;
        case TOX_CONNECTION_UDP:
            return FriendState::UDP;
        default:
            return FriendState::None;
    }
}

/// Translate a TOX_ERR_FRIEND_ADD code into a human-readable string.
std::string friend_add_error_string(TOX_ERR_FRIEND_ADD err) {
    switch (err) {
        case TOX_ERR_FRIEND_ADD_NULL:
            return "null argument";
        case TOX_ERR_FRIEND_ADD_TOO_LONG:
            return "message too long";
        case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
            return "no message provided";
        case TOX_ERR_FRIEND_ADD_OWN_KEY:
            return "cannot add own key as friend";
        case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
            return "friend request already sent";
        case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
            return "bad checksum in Tox ID";
        case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
            return "friend already added but with a different nospam";
        case TOX_ERR_FRIEND_ADD_MALLOC:
            return "memory allocation failed";
        default:
            return "unknown error (" + std::to_string(static_cast<int>(err)) + ")";
    }
}

}  // anonymous namespace

// ===========================================================================
// ToxAdapter - Construction / Destruction
// ===========================================================================

ToxAdapter::ToxAdapter() = default;

ToxAdapter::~ToxAdapter() {
    stop();
}

// ===========================================================================
// Lifecycle
// ===========================================================================

util::Expected<void, std::string> ToxAdapter::initialize(const ToxAdapterConfig& config) {
    if (initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter is already initialized"));
    }

    config_ = config;

    // Ensure the data directory exists.
    if (!config_.data_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(config_.data_dir, ec);
        if (ec) {
            return util::unexpected(std::string("failed to create data directory '") +
                                    config_.data_dir.string() + "': " + ec.message());
        }
    }

    // Prepare Tox options.
    TOX_ERR_OPTIONS_NEW opt_err;
    struct Tox_Options* opts = tox_options_new(&opt_err);
    if (!opts) {
        return util::unexpected(std::string("failed to allocate Tox options"));
    }

    tox_options_set_udp_enabled(opts, config_.udp_enabled);
    tox_options_set_ipv6_enabled(opts, config_.ipv6_enabled);
    tox_options_set_local_discovery_enabled(opts, config_.local_discovery_enabled);

    if (config_.tcp_port != 0) {
        tox_options_set_tcp_port(opts, config_.tcp_port);
    }

    // Proxy settings.
    if (config_.proxy_type == 1) {
        tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_HTTP);
        tox_options_set_proxy_host(opts, config_.proxy_host.c_str());
        tox_options_set_proxy_port(opts, config_.proxy_port);
    } else if (config_.proxy_type == 2) {
        tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
        tox_options_set_proxy_host(opts, config_.proxy_host.c_str());
        tox_options_set_proxy_port(opts, config_.proxy_port);
    }

    // Try to load existing save data.
    std::vector<uint8_t> save_data = load_save_data();
    if (!save_data.empty()) {
        tox_options_set_savedata_type(opts, TOX_SAVEDATA_TYPE_TOX_SAVE);
        tox_options_set_savedata_data(opts, save_data.data(), save_data.size());
        util::Logger::info("Loaded Tox save data ({} bytes)", save_data.size());
    } else {
        tox_options_set_savedata_type(opts, TOX_SAVEDATA_TYPE_NONE);
        util::Logger::info("No existing save data found; creating new Tox identity");
    }

    // Create the Tox instance.
    TOX_ERR_NEW new_err;
    Tox* raw_tox = tox_new(opts, &new_err);
    tox_options_free(opts);

    if (!raw_tox) {
        std::string msg = "failed to create Tox instance: ";
        switch (new_err) {
            case TOX_ERR_NEW_NULL:
                msg += "null argument";
                break;
            case TOX_ERR_NEW_MALLOC:
                msg += "memory allocation failed";
                break;
            case TOX_ERR_NEW_PORT_ALLOC:
                msg += "could not bind to port";
                break;
            case TOX_ERR_NEW_PROXY_BAD_TYPE:
                msg += "bad proxy type";
                break;
            case TOX_ERR_NEW_PROXY_BAD_HOST:
                msg += "bad proxy host";
                break;
            case TOX_ERR_NEW_PROXY_BAD_PORT:
                msg += "bad proxy port";
                break;
            case TOX_ERR_NEW_PROXY_NOT_FOUND:
                msg += "proxy not found";
                break;
            case TOX_ERR_NEW_LOAD_ENCRYPTED:
                msg += "save data is encrypted (not supported)";
                break;
            case TOX_ERR_NEW_LOAD_BAD_FORMAT:
                msg += "save data has bad format";
                break;
            default:
                msg += "unknown error (" + std::to_string(static_cast<int>(new_err)) + ")";
                break;
        }
        return util::unexpected(msg);
    }

    tox_.reset(raw_tox);

    // Set name and status message.
    if (!config_.name.empty()) {
        TOX_ERR_SET_INFO err;
        tox_self_set_name(tox_.get(), reinterpret_cast<const uint8_t*>(config_.name.data()),
                          config_.name.size(), &err);
        if (err != TOX_ERR_SET_INFO_OK) {
            util::Logger::warn("Failed to set Tox name");
        }
    }

    if (!config_.status_message.empty()) {
        TOX_ERR_SET_INFO err;
        tox_self_set_status_message(tox_.get(),
                                    reinterpret_cast<const uint8_t*>(config_.status_message.data()),
                                    config_.status_message.size(), &err);
        if (err != TOX_ERR_SET_INFO_OK) {
            util::Logger::warn("Failed to set Tox status message");
        }
    }

    // Register toxcore callbacks.
    register_callbacks();

    // Persist the (possibly new) identity.
    (void)write_save_data();

    initialized_.store(true);

    auto addr = get_address();
    util::Logger::info("Tox initialized. Address: {}", addr.to_hex());

    return {};  // success (void)
}

bool ToxAdapter::start() {
    if (!initialized_.load()) {
        util::Logger::error("Cannot start ToxAdapter: not initialized");
        return false;
    }
    if (running_.load()) {
        util::Logger::warn("ToxAdapter iteration thread is already running");
        return false;
    }

    running_.store(true);
    iterate_thread_ = std::thread(&ToxAdapter::run_loop, this);
    util::Logger::info("Tox iteration thread started");
    return true;
}

void ToxAdapter::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    if (iterate_thread_.joinable()) {
        iterate_thread_.join();
    }

    // Persist state.
    if (initialized_.load()) {
        (void)write_save_data();
        util::Logger::info("Tox state saved on shutdown");
    }
}

bool ToxAdapter::is_running() const noexcept {
    return running_.load();
}

// ===========================================================================
// Network operations
// ===========================================================================

util::Expected<std::vector<BootstrapNode>, std::string>
ToxAdapter::resolve_bootstrap_nodes_for_config(const ToxAdapterConfig& config,
                                               BootstrapSource::Fetcher fetcher) {
    return BootstrapSource::resolve_bootstrap_nodes(config.bootstrap_nodes, config.bootstrap_mode,
                                                    config.data_dir, std::move(fetcher));
}

std::size_t ToxAdapter::bootstrap() {
    if (!initialized_.load()) {
        util::Logger::error("Cannot bootstrap: ToxAdapter not initialized");
        return 0;
    }

    std::vector<BootstrapNode> bootstrap_nodes;
    auto resolved = resolve_bootstrap_nodes_for_config(config_);
    if (resolved) {
        bootstrap_nodes = resolved.value();
        if (config_.bootstrap_mode == BootstrapMode::Lan && bootstrap_nodes.empty()) {
            util::Logger::info("LAN bootstrap mode enabled; relying on local discovery");
        } else if (config_.bootstrap_mode == BootstrapMode::Auto &&
                   config_.bootstrap_nodes.empty()) {
            util::Logger::info("Loaded {} bootstrap node(s) from {}", bootstrap_nodes.size(),
                               std::string(BootstrapSource::kDefaultNodesUrl));
        }
    } else if (config_.bootstrap_mode == BootstrapMode::Lan) {
        util::Logger::info("LAN bootstrap mode enabled but bootstrap resolution returned: {}",
                           resolved.error());
    } else {
        util::Logger::warn("No bootstrap nodes configured and default discovery failed: {}",
                           resolved.error());
    }

    std::size_t success_count = 0;
    std::lock_guard<std::mutex> lock(tox_mutex_);

    for (const auto& node : bootstrap_nodes) {
        TOX_ERR_BOOTSTRAP err;
        bool ok =
            tox_bootstrap(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(), &err);

        if (ok && err == TOX_ERR_BOOTSTRAP_OK) {
            ++success_count;
            util::Logger::debug("Bootstrap success: {}:{}", node.ip, node.port);
        } else {
            util::Logger::warn("Bootstrap failed for {}:{} (error {})", node.ip, node.port,
                               static_cast<int>(err));
        }

        // Also add as TCP relay for TCP-only connections.
        TOX_ERR_BOOTSTRAP relay_err;
        tox_add_tcp_relay(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(),
                          &relay_err);

        if (relay_err != TOX_ERR_BOOTSTRAP_OK) {
            util::Logger::debug("TCP relay add failed for {}:{} (error {})", node.ip, node.port,
                                static_cast<int>(relay_err));
        }
    }

    util::Logger::info("Bootstrap complete: {}/{} nodes contacted", success_count,
                       bootstrap_nodes.size());
    return success_count;
}

bool ToxAdapter::add_bootstrap_node(const BootstrapNode& node) {
    if (!initialized_.load()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_BOOTSTRAP err;
    bool ok = tox_bootstrap(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(), &err);

    if (ok && err == TOX_ERR_BOOTSTRAP_OK) {
        // Also add as TCP relay.
        TOX_ERR_BOOTSTRAP relay_err;
        tox_add_tcp_relay(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(),
                          &relay_err);
        return true;
    }

    return false;
}

// ===========================================================================
// Identity
// ===========================================================================

ToxId ToxAdapter::get_address() const {
    std::lock_guard<std::mutex> lock(tox_mutex_);
    ToxIdArray addr{};
    tox_self_get_address(tox_.get(), addr.data());
    return ToxId::from_bytes_unchecked(addr);
}

PublicKeyArray ToxAdapter::get_public_key() const {
    std::lock_guard<std::mutex> lock(tox_mutex_);
    PublicKeyArray pk{};
    tox_self_get_public_key(tox_.get(), pk.data());
    return pk;
}

uint32_t ToxAdapter::get_nospam() const {
    std::lock_guard<std::mutex> lock(tox_mutex_);
    return tox_self_get_nospam(tox_.get());
}

void ToxAdapter::set_nospam(uint32_t nospam) {
    std::lock_guard<std::mutex> lock(tox_mutex_);
    tox_self_set_nospam(tox_.get(), nospam);
}

// ===========================================================================
// Friend management
// ===========================================================================

util::Expected<uint32_t, std::string> ToxAdapter::add_friend(const ToxId& tox_id,
                                                             std::string_view message) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_ADD err;
    uint32_t friend_number =
        tox_friend_add(tox_.get(), tox_id.bytes().data(),
                       reinterpret_cast<const uint8_t*>(message.data()), message.size(), &err);

    if (err != TOX_ERR_FRIEND_ADD_OK) {
        return util::unexpected(std::string("failed to add friend: ") +
                                friend_add_error_string(err));
    }

    // Persist the updated friend list.
    (void)write_save_data();

    util::Logger::info("Friend added: number={}, id={}", friend_number,
                       tox_id.public_key_hex().substr(0, 16) + "...");
    return friend_number;
}

util::Expected<uint32_t, std::string> ToxAdapter::add_friend_norequest(
    const PublicKeyArray& public_key) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_ADD err;
    uint32_t friend_number = tox_friend_add_norequest(tox_.get(), public_key.data(), &err);

    if (err != TOX_ERR_FRIEND_ADD_OK) {
        return util::unexpected(std::string("failed to add friend (norequest): ") +
                                friend_add_error_string(err));
    }

    (void)write_save_data();

    util::Logger::info("Friend added (norequest): number={}", friend_number);
    return friend_number;
}

bool ToxAdapter::remove_friend(uint32_t friend_number) {
    if (!initialized_.load()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_DELETE err;
    bool ok = tox_friend_delete(tox_.get(), friend_number, &err);

    if (ok && err == TOX_ERR_FRIEND_DELETE_OK) {
        (void)write_save_data();
        util::Logger::info("Friend removed: number={}", friend_number);
        return true;
    }

    util::Logger::warn("Failed to remove friend {}: error {}", friend_number,
                       static_cast<int>(err));
    return false;
}

bool ToxAdapter::is_friend_connected(uint32_t friend_number) const {
    return get_friend_connection_status(friend_number) != FriendState::None;
}

FriendState ToxAdapter::get_friend_connection_status(uint32_t friend_number) const {
    if (!initialized_.load()) {
        return FriendState::None;
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_QUERY err;
    TOX_CONNECTION conn = tox_friend_get_connection_status(tox_.get(), friend_number, &err);

    if (err != TOX_ERR_FRIEND_QUERY_OK) {
        return FriendState::None;
    }

    return connection_to_state(conn);
}

util::Expected<PublicKeyArray, std::string> ToxAdapter::get_friend_public_key(
    uint32_t friend_number) const {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    PublicKeyArray pk{};
    TOX_ERR_FRIEND_GET_PUBLIC_KEY err;
    bool ok = tox_friend_get_public_key(tox_.get(), friend_number, pk.data(), &err);

    if (!ok || err != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) {
        return util::unexpected(std::string("failed to get public key for friend ") +
                                std::to_string(friend_number));
    }

    return pk;
}

util::Expected<uint32_t, std::string> ToxAdapter::friend_by_public_key(
    const PublicKeyArray& public_key) const {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_BY_PUBLIC_KEY err;
    uint32_t friend_number = tox_friend_by_public_key(tox_.get(), public_key.data(), &err);

    if (err != TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
        return util::unexpected(std::string("friend not found for given public key"));
    }

    return friend_number;
}

std::vector<uint32_t> ToxAdapter::get_friend_list() const {
    if (!initialized_.load()) {
        return {};
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    std::size_t count = tox_self_get_friend_list_size(tox_.get());
    std::vector<uint32_t> list(count);
    if (count > 0) {
        tox_self_get_friend_list(tox_.get(), list.data());
    }
    return list;
}

std::vector<FriendInfo> ToxAdapter::get_friend_info_list() const {
    if (!initialized_.load()) {
        return {};
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    std::size_t count = tox_self_get_friend_list_size(tox_.get());
    std::vector<uint32_t> numbers(count);
    if (count > 0) {
        tox_self_get_friend_list(tox_.get(), numbers.data());
    }

    std::vector<FriendInfo> infos;
    infos.reserve(count);

    for (uint32_t fn : numbers) {
        FriendInfo info;
        info.friend_number = fn;

        TOX_ERR_FRIEND_GET_PUBLIC_KEY pk_err;
        tox_friend_get_public_key(tox_.get(), fn, info.public_key.data(), &pk_err);

        TOX_ERR_FRIEND_QUERY q_err;
        TOX_CONNECTION conn = tox_friend_get_connection_status(tox_.get(), fn, &q_err);
        info.state =
            (q_err == TOX_ERR_FRIEND_QUERY_OK) ? connection_to_state(conn) : FriendState::None;

        infos.push_back(info);
    }

    return infos;
}

// ===========================================================================
// Data transfer
// ===========================================================================

bool ToxAdapter::send_lossless_packet(uint32_t friend_number, const uint8_t* data,
                                      std::size_t length) {
    if (!initialized_.load() || !data || length == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_CUSTOM_PACKET err;
    bool ok = tox_friend_send_lossless_packet(tox_.get(), friend_number, data, length, &err);

    if (!ok || err != TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
        util::Logger::debug("Send lossless packet failed for friend {}: error {}", friend_number,
                            static_cast<int>(err));
        return false;
    }

    return true;
}

bool ToxAdapter::send_lossless_packet(uint32_t friend_number, const std::vector<uint8_t>& data) {
    return send_lossless_packet(friend_number, data.data(), data.size());
}

bool ToxAdapter::send_lossy_packet(uint32_t friend_number, const uint8_t* data,
                                   std::size_t length) {
    if (!initialized_.load() || !data || length == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_CUSTOM_PACKET err;
    bool ok = tox_friend_send_lossy_packet(tox_.get(), friend_number, data, length, &err);

    if (!ok || err != TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
        util::Logger::debug("Send lossy packet failed for friend {}: error {}", friend_number,
                            static_cast<int>(err));
        return false;
    }

    return true;
}

util::Expected<uint32_t, std::string> ToxAdapter::send_message(uint32_t friend_number,
                                                               std::string_view message) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    std::lock_guard<std::mutex> lock(tox_mutex_);

    TOX_ERR_FRIEND_SEND_MESSAGE err;
    uint32_t msg_id = tox_friend_send_message(tox_.get(), friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                              reinterpret_cast<const uint8_t*>(message.data()),
                                              message.size(), &err);

    if (err != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
        std::string reason;
        switch (err) {
            case TOX_ERR_FRIEND_SEND_MESSAGE_NULL:
                reason = "null argument";
                break;
            case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND:
                reason = "friend not found";
                break;
            case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED:
                reason = "friend not connected";
                break;
            case TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ:
                reason = "send queue allocation failed";
                break;
            case TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG:
                reason = "message too long";
                break;
            case TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY:
                reason = "message is empty";
                break;
            default:
                reason = "unknown error (" + std::to_string(static_cast<int>(err)) + ")";
                break;
        }
        return util::unexpected(std::string("failed to send message: ") + reason);
    }

    return msg_id;
}

// ===========================================================================
// Callbacks
// ===========================================================================

void ToxAdapter::set_on_friend_request(FriendRequestCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_friend_request_ = std::move(cb);
}

void ToxAdapter::set_on_friend_connection(FriendConnectionCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_friend_connection_ = std::move(cb);
}

void ToxAdapter::set_on_lossless_packet(FriendLosslessPacketCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_lossless_packet_ = std::move(cb);
}

void ToxAdapter::set_on_lossy_packet(FriendLossyPacketCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_lossy_packet_ = std::move(cb);
}

void ToxAdapter::set_on_friend_message(FriendMessageCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_friend_message_ = std::move(cb);
}

void ToxAdapter::set_on_self_connection(SelfConnectionCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    on_self_connection_ = std::move(cb);
}

// ===========================================================================
// Status
// ===========================================================================

bool ToxAdapter::is_connected() const noexcept {
    return connected_.load();
}

uint32_t ToxAdapter::iteration_interval() const {
    if (!initialized_.load()) {
        return 50;  // sensible default
    }
    std::lock_guard<std::mutex> lock(tox_mutex_);
    return tox_iteration_interval(tox_.get());
}

bool ToxAdapter::save() const {
    if (!initialized_.load()) {
        return false;
    }
    return write_save_data();
}

void ToxAdapter::enqueue_friend_request_for_test(const PublicKeyArray& public_key,
                                                 std::string_view message) {
    enqueue_event(FriendRequestEvent{public_key, std::string(message)});
}

void ToxAdapter::dispatch_pending_events_for_test() {
    dispatch_pending_events();
}

// ===========================================================================
// Internal: iterate loop
// ===========================================================================

void ToxAdapter::run_loop() {
    util::Logger::debug("Tox iterate loop started");

    while (running_.load()) {
        uint32_t interval;
        {
            std::lock_guard<std::mutex> lock(tox_mutex_);
            tox_iterate(tox_.get(), this);
            interval = tox_iteration_interval(tox_.get());
        }

        dispatch_pending_events();

        // Sleep for the interval recommended by toxcore.
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    }

    util::Logger::debug("Tox iterate loop stopped");
}

// ===========================================================================
// Internal: register callbacks
// ===========================================================================

void ToxAdapter::register_callbacks() {
    tox_callback_friend_request(tox_.get(), on_friend_request_cb);
    tox_callback_friend_connection_status(tox_.get(), on_friend_connection_status_cb);
    tox_callback_friend_lossless_packet(tox_.get(), on_friend_lossless_packet_cb);
    tox_callback_friend_lossy_packet(tox_.get(), on_friend_lossy_packet_cb);
    tox_callback_friend_message(tox_.get(), on_friend_message_cb);
    tox_callback_self_connection_status(tox_.get(), on_self_connection_status_cb);
}

void ToxAdapter::dispatch_pending_events() {
    std::vector<CallbackEvent> events;
    {
        std::lock_guard<std::mutex> lock(event_mutex_);
        if (pending_events_.empty()) {
            return;
        }
        events.swap(pending_events_);
    }

    for (auto& event : events) {
        std::visit(
            [this](auto&& current) {
                using Event = std::decay_t<decltype(current)>;

                if constexpr (std::is_same_v<Event, FriendRequestEvent>) {
                    FriendRequestCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_friend_request_;
                    }
                    if (cb) {
                        cb(current.public_key, current.message);
                    }
                } else if constexpr (std::is_same_v<Event, FriendConnectionEvent>) {
                    FriendConnectionCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_friend_connection_;
                    }
                    if (cb) {
                        cb(current.friend_number, current.connected);
                    }
                } else if constexpr (std::is_same_v<Event, FriendLosslessPacketEvent>) {
                    FriendLosslessPacketCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_lossless_packet_;
                    }
                    if (cb) {
                        cb(current.friend_number, current.data.data(), current.data.size());
                    }
                } else if constexpr (std::is_same_v<Event, FriendLossyPacketEvent>) {
                    FriendLossyPacketCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_lossy_packet_;
                    }
                    if (cb) {
                        cb(current.friend_number, current.data.data(), current.data.size());
                    }
                } else if constexpr (std::is_same_v<Event, FriendMessageEvent>) {
                    FriendMessageCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_friend_message_;
                    }
                    if (cb) {
                        cb(current.friend_number, current.message);
                    }
                } else if constexpr (std::is_same_v<Event, SelfConnectionEvent>) {
                    SelfConnectionCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        cb = on_self_connection_;
                    }
                    if (cb) {
                        cb(current.connected);
                    }
                }
            },
            event);
    }
}

// ===========================================================================
// Internal: save/load
// ===========================================================================

std::vector<uint8_t> ToxAdapter::load_save_data() const {
    auto path = save_file_path();
    if (path.empty() || !std::filesystem::exists(path)) {
        return {};
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        util::Logger::warn("Could not open save file: {}", path.string());
        return {};
    }

    auto size = file.tellg();
    if (size <= 0) {
        return {};
    }

    std::vector<uint8_t> data(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

    if (!file) {
        util::Logger::warn("Failed to read save file: {}", path.string());
        return {};
    }

    return data;
}

bool ToxAdapter::write_save_data() const {
    auto path = save_file_path();
    if (path.empty()) {
        return false;
    }

    std::size_t save_size = tox_get_savedata_size(tox_.get());
    std::vector<uint8_t> data(save_size);
    tox_get_savedata(tox_.get(), data.data());

    // Write to a temporary file and rename for atomicity.
    auto tmp_path = path;
    tmp_path += ".tmp";

    std::ofstream file(tmp_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        util::Logger::error("Could not open save file for writing: {}", tmp_path.string());
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    file.close();

    if (!file) {
        util::Logger::error("Failed to write save data to: {}", tmp_path.string());
        return false;
    }

    // Atomic rename.
    std::error_code ec;
    std::filesystem::rename(tmp_path, path, ec);
    if (ec) {
        util::Logger::error("Failed to rename save file: {}", ec.message());
        // Try to clean up the temp file.
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    util::Logger::trace("Tox state saved to {} ({} bytes)", path.string(), save_size);
    return true;
}

std::filesystem::path ToxAdapter::save_file_path() const {
    if (config_.data_dir.empty()) {
        return {};
    }
    return config_.data_dir / config_.save_filename;
}

// ===========================================================================
// Static callback trampolines
// ===========================================================================

void ToxAdapter::on_friend_request_cb(Tox* /*tox*/, const uint8_t* public_key,
                                      const uint8_t* message, size_t length, void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);

    PublicKeyArray pk{};
    std::memcpy(pk.data(), public_key, kPublicKeyBytes);

    std::string_view msg(reinterpret_cast<const char*>(message), length);

    util::Logger::info("Friend request received from {}",
                       bytes_to_hex(pk.data(), pk.size()).substr(0, 16) + "...");
    self->enqueue_event(FriendRequestEvent{pk, std::string(msg)});
}

void ToxAdapter::on_friend_connection_status_cb(Tox* /*tox*/, uint32_t friend_number,
                                                TOX_CONNECTION connection_status, void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);
    bool connected = (connection_status != TOX_CONNECTION_NONE);

    util::Logger::info("Friend {} connection status: {}", friend_number,
                       connected ? "connected" : "disconnected");
    self->enqueue_event(FriendConnectionEvent{friend_number, connected});
}

void ToxAdapter::on_friend_lossless_packet_cb(Tox* /*tox*/, uint32_t friend_number,
                                              const uint8_t* data, size_t length, void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);

    util::Logger::trace("Lossless packet from friend {}: {} bytes", friend_number, length);
    self->enqueue_event(
        FriendLosslessPacketEvent{friend_number, std::vector<uint8_t>(data, data + length)});
}

void ToxAdapter::on_friend_lossy_packet_cb(Tox* /*tox*/, uint32_t friend_number,
                                           const uint8_t* data, size_t length, void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);

    util::Logger::trace("Lossy packet from friend {}: {} bytes", friend_number, length);
    self->enqueue_event(
        FriendLossyPacketEvent{friend_number, std::vector<uint8_t>(data, data + length)});
}

void ToxAdapter::on_friend_message_cb(Tox* /*tox*/, uint32_t friend_number,
                                      TOX_MESSAGE_TYPE /*type*/, const uint8_t* message,
                                      size_t length, void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);

    std::string_view msg(reinterpret_cast<const char*>(message), length);

    util::Logger::debug("Message from friend {}: '{}'", friend_number, msg);
    self->enqueue_event(FriendMessageEvent{friend_number, std::string(msg)});
}

void ToxAdapter::on_self_connection_status_cb(Tox* /*tox*/, TOX_CONNECTION connection_status,
                                              void* user_data) {
    auto* self = static_cast<ToxAdapter*>(user_data);
    bool connected = (connection_status != TOX_CONNECTION_NONE);
    self->connected_.store(connected);

    const char* type_str = "none";
    if (connection_status == TOX_CONNECTION_TCP) {
        type_str = "TCP";
    } else if (connection_status == TOX_CONNECTION_UDP) {
        type_str = "UDP";
    }

    util::Logger::info("Self connection status: {} ({})", connected ? "connected" : "disconnected",
                       type_str);
    self->enqueue_event(SelfConnectionEvent{connected});
}

}  // namespace toxtunnel::tox
