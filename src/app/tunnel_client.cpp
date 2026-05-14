#include "toxtunnel/app/tunnel_client.hpp"

#include <cstdio>
#include <span>

#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/system_info.hpp"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace toxtunnel::app {

// -------------------------------------------------------------------------
// Construction / Destruction
// -------------------------------------------------------------------------

TunnelClient::TunnelClient() = default;

TunnelClient::~TunnelClient() {
    if (running_) {
        stop();
    }
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

util::Expected<void, std::string> TunnelClient::initialize(const Config& config) {
    if (!config.is_client()) {
        return util::unexpected(std::string("Configuration is not in client mode"));
    }

    if (!config.client.has_value()) {
        return util::unexpected(std::string("Missing client configuration"));
    }

    config_ = config;
    const auto& client_cfg = config.client_config();
    const auto tox_cfg = config.effective_tox_config();

    // Create IoContext
    io_ctx_ = std::make_unique<core::IoContext>();

    // Create ToxAdapter and configure it
    tox_adapter_ = std::make_unique<tox::ToxAdapter>();

    tox::ToxAdapterConfig tox_config;
    tox_config.data_dir = config.data_dir;
    tox_config.udp_enabled = tox_cfg.udp_enabled;
    tox_config.bootstrap_mode = tox_cfg.bootstrap_mode;
    tox_config.local_discovery_enabled = tox_cfg.bootstrap_mode == BootstrapMode::Lan;
    tox_config.name = "toxtunnel-client";
    tox_config.status_message = "toxtunnel client node";
    for (const auto& node_cfg : tox_cfg.bootstrap_nodes) {
        auto node_result = node_cfg.to_bootstrap_node();
        if (node_result) {
            tox_config.bootstrap_nodes.push_back(std::move(node_result.value()));
        } else {
            util::Logger::warn("Skipping invalid bootstrap node {}: {}", node_cfg.address,
                               node_result.error());
        }
    }

    auto init_result = tox_adapter_->initialize(tox_config);
    if (!init_result) {
        return util::unexpected(std::string("Failed to initialize ToxAdapter: ") +
                                init_result.error());
    }

    // Parse server Tox ID and add as friend
    auto tox_id_result = tox::ToxId::from_hex(client_cfg.server_id);
    if (!tox_id_result) {
        return util::unexpected(std::string("Invalid server Tox ID: ") + tox_id_result.error());
    }

    // Key the known_servers registry off the canonical hex form. ToxId::to_hex()
    // already returns uppercase, matching KnownServersStore's internal normalization.
    server_tox_id_hex_ = tox_id_result.value().to_hex();

    // Open the persistent known-servers registry alongside tox_save.dat.
    known_servers_ = std::make_unique<KnownServersStore>(config.data_dir);
    if (auto& err = known_servers_->last_load_error(); err.has_value()) {
        util::Logger::warn("known_servers.yaml: {} (continuing with empty registry)", *err);
    }

    auto peer_public_key = tox_id_result.value().public_key();
    auto friend_result = tox_adapter_->add_friend(tox_id_result.value(), "toxtunnel client");
    if (!friend_result) {
        auto existing_friend = tox_adapter_->friend_by_public_key(peer_public_key);
        if (existing_friend) {
            server_friend_number_ = existing_friend.value();
        } else {
            // The friend may already exist; try adding by public key without request
            auto noreq_result = tox_adapter_->add_friend_norequest(peer_public_key);
            if (!noreq_result) {
                return util::unexpected(std::string("Failed to add server as friend: ") +
                                        noreq_result.error());
            }
            server_friend_number_ = noreq_result.value();
        }
    } else {
        server_friend_number_ = friend_result.value();
    }

    util::Logger::info("Server friend added with friend number {}", server_friend_number_);

    // Create TunnelManager
    tunnel_mgr_ = std::make_unique<tunnel::TunnelManager>(io_ctx_->get_io_context());

    // Set up callbacks and handlers
    setup_tox_callbacks();
    setup_tunnel_manager();

    // Create TCP listeners for each forwarding rule
    create_listeners(client_cfg.forwards);

    return {};
}

void TunnelClient::start() {
    if (running_) {
        util::Logger::warn("TunnelClient is already running");
        return;
    }

    running_ = true;

    // Start IoContext thread pool
    io_ctx_->run();

    // Start ToxAdapter iteration thread
    tox_adapter_->start();

    // Bootstrap DHT
    auto bootstrapped = tox_adapter_->bootstrap();
    util::Logger::info("Bootstrapped to {} DHT nodes", bootstrapped);

    // Log our Tox ID
    auto address = tox_adapter_->get_address();
    util::Logger::info("Client Tox ID: {}", address.to_hex());

    schedule_info_refresh();

    if (is_pipe_mode()) {
        util::Logger::info("Client running in stdio pipe mode");
        if (server_online_) {
            io_ctx_->post([this] { start_pipe_mode(); });
        }
    } else {
        // Start all TCP listeners
        for (std::size_t i = 0; i < listeners_.size(); ++i) {
            const auto& rule = forward_rules_[i];
            auto& listener = listeners_[i];

            listener->start_accept([this, &rule](std::shared_ptr<core::TcpConnection> conn) {
                on_tcp_connection_accepted(std::move(conn), rule);
            });

            util::Logger::info("Listening on local port {} -> {}:{}", rule.local_port,
                               rule.remote_host, rule.remote_port);
        }
    }
}

void TunnelClient::stop() {
    if (!running_) {
        return;
    }

    util::Logger::info("Stopping TunnelClient...");

    if (info_refresh_timer_) {
        info_refresh_timer_->cancel();
        info_refresh_timer_.reset();
    }

    // Stop all TCP listeners
    for (auto& listener : listeners_) {
        listener->stop();
    }

    if (pipe_bridge_) {
        pipe_bridge_->stop();
        pipe_bridge_.reset();
    }

    // Close all tunnels
    tunnel_mgr_->close_all();

    // Stop ToxAdapter
    tox_adapter_->stop();

    // Stop IoContext
    io_ctx_->stop();

    running_ = false;
    stop_cv_.notify_all();

    util::Logger::info("TunnelClient stopped");
}

bool TunnelClient::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void TunnelClient::wait_until_stopped() {
    std::unique_lock<std::mutex> lock(stop_mutex_);
    stop_cv_.wait(lock, [this] { return !running_.load(std::memory_order_acquire); });
}

// -------------------------------------------------------------------------
// Accessors
// -------------------------------------------------------------------------

std::string TunnelClient::get_tox_address() const {
    return tox_adapter_->get_address().to_hex();
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

void TunnelClient::setup_tox_callbacks() {
    // Friend connection status changes
    tox_adapter_->set_on_friend_connection([this](uint32_t friend_number, bool connected) {
        if (friend_number == server_friend_number_) {
            server_online_ = connected;
            if (connected) {
                util::Logger::info("Server friend {} is now online", friend_number);
                record_server_connection();
                send_info_request();
                if (is_pipe_mode() && running_) {
                    io_ctx_->post([this] { start_pipe_mode(); });
                }
            } else {
                util::Logger::warn("Server friend {} went offline", friend_number);
                info_request_sent_.store(false);
                if (is_pipe_mode() && running_) {
                    request_stop();
                }
            }
        }
    });

    // Lossless packet handler: deserialize and route to TunnelManager
    tox_adapter_->set_on_lossless_packet([this](uint32_t friend_number, const uint8_t* data,
                                                std::size_t length) {
        if (friend_number != server_friend_number_) {
            util::Logger::warn("Received lossless packet from unexpected friend {}", friend_number);
            return;
        }

        if (length < 2) {
            util::Logger::warn("Lossless packet too short ({} bytes)", length);
            return;
        }

        // Skip byte 0 (lossless packet prefix byte), deserialize from byte 1
        auto frame_data = std::span<const uint8_t>(data + 1, length - 1);
        auto frame_result = tunnel::ProtocolFrame::deserialize(frame_data);
        if (!frame_result) {
            util::Logger::error("Failed to deserialize ProtocolFrame from lossless packet");
            return;
        }

        // INFO_REPLY is a per-friend control frame outside the per-tunnel
        // routing. Intercept it before route_frame so TunnelManager doesn't
        // log a "no tunnel for id 0" warning.
        if (frame_result.value().type() == tunnel::FrameType::INFO_REPLY) {
            record_server_info(frame_result.value().as_info_reply_yaml());
            return;
        }

        tunnel_mgr_->route_frame(frame_result.value());
    });

    // Self connection status (DHT connectivity)
    tox_adapter_->set_on_self_connection([](bool connected) {
        if (connected) {
            util::Logger::info("Connected to Tox DHT");
        } else {
            util::Logger::warn("Disconnected from Tox DHT");
        }
    });
}

void TunnelClient::setup_tunnel_manager() {
    // Send handler: serialize frame, prepend the lossless prefix, send via ToxAdapter.
    tunnel_mgr_->set_send_handler([this](const std::vector<uint8_t>& frame_data) -> bool {
        std::vector<uint8_t> packet;
        packet.reserve(1 + frame_data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), frame_data.begin(), frame_data.end());

        return tox_adapter_->send_lossless_packet(server_friend_number_, packet.data(),
                                                  packet.size());
    });

    // Tunnel closed callback
    tunnel_mgr_->set_on_tunnel_closed(
        [](uint16_t tunnel_id) { util::Logger::debug("Tunnel {} closed", tunnel_id); });
}

void TunnelClient::create_listeners(const std::vector<ForwardRule>& forwards) {
    forward_rules_ = forwards;
    listeners_.reserve(forwards.size());

    for (const auto& rule : forwards) {
        auto listener =
            std::make_unique<core::TcpListener>(io_ctx_->get_io_context(), rule.local_port);
        listeners_.push_back(std::move(listener));
    }
}

bool TunnelClient::is_pipe_mode() const noexcept {
    return config_.client.has_value() && config_.client->pipe_target.has_value();
}

void TunnelClient::start_pipe_mode() {
    if (!is_pipe_mode() || !server_online_) {
        return;
    }

    bool expected = false;
    if (!pipe_mode_started_.compare_exchange_strong(expected, true)) {
        return;
    }

    const auto& target = *config_.client->pipe_target;

#ifdef _WIN32
    util::Logger::error("Pipe mode is not implemented on Windows");
    request_stop();
    return;
#else
    pipe_bridge_ = std::make_unique<StdioPipeBridge>(STDIN_FILENO, STDOUT_FILENO);
#endif

    const uint16_t tunnel_id = tunnel_mgr_->allocate_tunnel_id();
    auto tunnel = std::make_unique<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                                       server_friend_number_);
    auto* tunnel_raw = tunnel.get();

    tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        std::vector<uint8_t> frame_data(data.begin(), data.end());
        std::vector<uint8_t> packet;
        packet.reserve(1 + frame_data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), frame_data.begin(), frame_data.end());
        (void)tox_adapter_->send_lossless_packet(server_friend_number_, packet.data(),
                                                 packet.size());
    });

    tunnel->set_on_data_for_tcp([this](std::span<const uint8_t> data) {
        if (pipe_bridge_) {
            pipe_bridge_->write_output(data);
        }
    });

    tunnel->set_on_state_change([this, tunnel_raw, tunnel_id](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected) {
            auto start_result = pipe_bridge_->start(
                [tunnel_raw](std::span<const uint8_t> data) {
                    tunnel_raw->on_tcp_data_received(data.data(), data.size());
                },
                [tunnel_raw]() { tunnel_raw->close(); });
            if (!start_result) {
                util::Logger::error("Failed to start stdio pipe bridge for tunnel {}: {}",
                                    tunnel_id, start_result.error());
                tunnel_raw->close();
                request_stop();
            }
        } else if (new_state == tunnel::Tunnel::State::Error) {
            if (pipe_bridge_) {
                pipe_bridge_->stop();
            }
            request_stop();
        }
    });

    auto* tunnel_mgr_ptr = tunnel_mgr_.get();
    tunnel->set_on_close([this, tunnel_mgr_ptr, tunnel_id]() {
        if (pipe_bridge_) {
            pipe_bridge_->stop();
            pipe_bridge_.reset();
        }
        pipe_mode_started_ = false;
        tunnel_mgr_ptr->remove_tunnel(tunnel_id);
        request_stop();
    });

    tunnel_mgr_->add_tunnel(tunnel_id, std::move(tunnel));

    if (!tunnel_raw->open(target.remote_host, target.remote_port)) {
        util::Logger::error("Failed to open pipe-mode tunnel {} to {}:{}", tunnel_id,
                            target.remote_host, target.remote_port);
        tunnel_mgr_->remove_tunnel(tunnel_id);
        pipe_bridge_.reset();
        pipe_mode_started_ = false;
        request_stop();
        return;
    }

    util::Logger::info("Pipe mode opening tunnel {} -> {}:{}", tunnel_id, target.remote_host,
                       target.remote_port);
}

void TunnelClient::request_stop() {
    // Use io_ctx_ to post the stop operation, avoiding detached threads.
    // This ensures stop() runs on the I/O thread pool and any exceptions
    // are handled within the asio context.
    if (io_ctx_ && running_.load()) {
        io_ctx_->post([this] {
            if (running_.load()) {
                stop();
            }
        });
    }
}

void TunnelClient::on_tcp_connection_accepted(std::shared_ptr<core::TcpConnection> conn,
                                              const ForwardRule& rule) {
    if (!server_online_) {
        util::Logger::warn("TCP connection accepted on port {} but server is offline, closing",
                           rule.local_port);
        conn->close();
        return;
    }

    // Allocate a tunnel ID and create the tunnel
    uint16_t tunnel_id = tunnel_mgr_->allocate_tunnel_id();
    util::Logger::debug("New TCP connection on port {}, creating tunnel {} -> {}:{}",
                        rule.local_port, tunnel_id, rule.remote_host, rule.remote_port);

    auto tunnel = std::make_unique<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                                       server_friend_number_);

    // Set the TCP connection on the tunnel
    tunnel->set_tcp_connection(conn);

    // Wire callback: when TunnelImpl wants to send data to Tox, serialize and
    // send via the TunnelManager's send handler
    tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        std::vector<uint8_t> frame_data(data.begin(), data.end());

        std::vector<uint8_t> packet;
        packet.reserve(1 + frame_data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), frame_data.begin(), frame_data.end());

        (void)tox_adapter_->send_lossless_packet(server_friend_number_, packet.data(),
                                                 packet.size());
    });

    // Wire callback: when data arrives from Tox for this tunnel, write to TCP
    tunnel->set_on_data_for_tcp(
        [conn](std::span<const uint8_t> data) { conn->write(data.data(), data.size()); });

    // Wire state change: when Connected (ACK received), start TCP read loop
    tunnel->set_on_state_change([conn, tunnel_id](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected) {
            util::Logger::debug("Tunnel {} connected, starting TCP read", tunnel_id);
            conn->start_read();
        } else if (new_state == tunnel::Tunnel::State::Closed ||
                   new_state == tunnel::Tunnel::State::Error) {
            util::Logger::debug("Tunnel {} state: {}", tunnel_id, to_string(new_state));
            conn->close();
        }
    });

    // Wire tunnel close callback
    auto* tunnel_mgr_ptr = tunnel_mgr_.get();
    tunnel->set_on_close([tunnel_mgr_ptr, tunnel_id]() {
        util::Logger::debug("Tunnel {} on_close, removing from manager", tunnel_id);
        tunnel_mgr_ptr->remove_tunnel(tunnel_id);
    });

    // Wire TCP data callback: forward received TCP data to tunnel
    auto* tunnel_raw = tunnel.get();
    conn->set_on_data([tunnel_raw](const uint8_t* data, std::size_t length) {
        tunnel_raw->on_tcp_data_received(data, length);
    });

    // Wire TCP disconnect: close the tunnel
    conn->set_on_disconnect([tunnel_raw](const std::error_code& /*ec*/) { tunnel_raw->close(); });

    // Initiate tunnel opening: sends TUNNEL_OPEN frame to server
    bool opened = tunnel->open(rule.remote_host, rule.remote_port);
    if (!opened) {
        util::Logger::error("Failed to open tunnel {} to {}:{}", tunnel_id, rule.remote_host,
                            rule.remote_port);
        conn->close();
        return;
    }

    // Add tunnel to manager (transfers ownership)
    tunnel_mgr_->add_tunnel(tunnel_id, std::move(tunnel));

    util::Logger::debug("Tunnel {} created and TUNNEL_OPEN sent to {}:{}", tunnel_id,
                        rule.remote_host, rule.remote_port);
}

// ---------------------------------------------------------------------------
// Known-servers registry helpers
// ---------------------------------------------------------------------------

namespace {

KnownConnectionType to_known_connection_type(tox::FriendState state) {
    switch (state) {
        case tox::FriendState::UDP:
            return KnownConnectionType::Udp;
        case tox::FriendState::TCP:
            return KnownConnectionType::Tcp;
        case tox::FriendState::None:
        default:
            return KnownConnectionType::None;
    }
}

}  // namespace

void TunnelClient::schedule_info_refresh() {
    if (!io_ctx_ || !running_.load())
        return;

    if (!info_refresh_timer_) {
        info_refresh_timer_ = std::make_unique<asio::steady_timer>(io_ctx_->get_io_context());
    }
    info_refresh_timer_->expires_after(kInfoRefreshInterval);
    info_refresh_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec || !running_.load()) {
            // Timer was cancelled (stop()) or client is shutting down.
            return;
        }
        if (server_online_.load()) {
            // Reset the per-session de-dupe flag so send_info_request()'s
            // compare_exchange_strong succeeds, then re-issue.
            info_request_sent_.store(false);
            send_info_request();
        }
        // Re-arm even if the server is offline; we'll just no-op until it
        // comes back, and reconnect itself triggers a fresh send via the
        // friend-online callback.
        schedule_info_refresh();
    });
}

void TunnelClient::send_info_request() {
    bool expected = false;
    if (!info_request_sent_.compare_exchange_strong(expected, true)) {
        return;
    }
    auto frame = tunnel::ProtocolFrame::make_info_request();
    auto wire = frame.serialize();
    std::vector<uint8_t> packet;
    packet.reserve(1 + wire.size());
    packet.push_back(tunnel::kLosslessPacketByte);
    packet.insert(packet.end(), wire.begin(), wire.end());
    const bool sent =
        tox_adapter_->send_lossless_packet(server_friend_number_, packet.data(), packet.size());
    if (!sent) {
        // The server may legitimately not implement INFO_REQUEST yet, or the
        // send queue may be full; either way let the next online transition
        // try again.
        info_request_sent_.store(false);
        util::Logger::debug("INFO_REQUEST send failed (will retry on next reconnect)");
    } else {
        util::Logger::debug("INFO_REQUEST sent to friend {}", server_friend_number_);
    }
}

void TunnelClient::record_server_connection() {
    if (!known_servers_ || server_tox_id_hex_.empty())
        return;
    const auto state = tox_adapter_->get_friend_connection_status(server_friend_number_);
    const auto type = to_known_connection_type(state);
    if (!known_servers_->record_connection(server_tox_id_hex_, type)) {
        util::Logger::warn("known_servers: record_connection rejected tox_id");
        return;
    }
    if (auto save = known_servers_->save(); !save) {
        util::Logger::warn("known_servers: failed to save: {}", save.error());
    }
}

void TunnelClient::record_server_info(std::string_view yaml_payload) {
    if (!known_servers_ || server_tox_id_hex_.empty())
        return;

    const auto snap = util::snapshot_from_yaml(yaml_payload);
    KnownServerInfo info;
    info.hostname = snap.hostname;
    info.os = snap.os;
    info.os_version = snap.os_version;
    info.arch = snap.arch;
    info.uptime_seconds = snap.uptime_seconds;
    info.toxtunnel_version = snap.toxtunnel_version;
    info.reported_at = iso8601_utc_now();

    util::Logger::info(
        "Server disclosed system info ({} bytes): hostname={} os={} arch={} version={}",
        yaml_payload.size(), info.hostname.value_or("(undisclosed)"),
        info.os.value_or("(undisclosed)"), info.arch.value_or("(undisclosed)"),
        info.toxtunnel_version.value_or("(undisclosed)"));

    if (!known_servers_->record_info(server_tox_id_hex_, info)) {
        util::Logger::warn("known_servers: record_info rejected tox_id");
        return;
    }
    if (auto save = known_servers_->save(); !save) {
        util::Logger::warn("known_servers: failed to save: {}", save.error());
    }
}

}  // namespace toxtunnel::app
