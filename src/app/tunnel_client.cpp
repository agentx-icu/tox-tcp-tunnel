#include "toxtunnel/app/tunnel_client.hpp"

#include <cstdio>
#include <span>

#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/config_reload.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
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

    // Build the inbound-dispatch strand on the IO pool's executor so all
    // inbound lossless-packet handlers run serialized, preserving the
    // on-the-wire order toxcore already guarantees. Without it, an ACK
    // and a DATA frame arriving back-to-back can be picked up by different
    // worker threads and processed out of order — the DATA lands while the
    // tunnel is still Connecting and gets silently dropped.
    inbound_strand_.emplace(asio::make_strand(io_ctx_->get_io_context().get_executor()));

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

    // Open the persistent known-servers registry alongside tox_save.dat.
    known_servers_ = std::make_unique<KnownServersStore>(config.data_dir);
    if (auto& err = known_servers_->last_load_error(); err.has_value()) {
        util::Logger::warn("known_servers.yaml: {} (continuing with empty registry)", *err);
    }

    // Resolve every configured server ID (primary + fallbacks) into a Tox
    // friend. We add every endpoint upfront so toxcore can start probing all
    // of them concurrently; the failover state machine then picks the active
    // one at runtime.
    const auto all_ids = client_cfg.all_server_ids();
    if (all_ids.empty()) {
        return util::unexpected(std::string("No server IDs configured"));
    }

    endpoints_.clear();
    endpoints_.reserve(all_ids.size());
    for (std::size_t i = 0; i < all_ids.size(); ++i) {
        const auto& id_str = all_ids[i];
        auto parse_result = tox::ToxId::from_hex(id_str);
        if (!parse_result) {
            return util::unexpected(std::string("Invalid Tox ID at position ") + std::to_string(i) +
                                    ": " + parse_result.error());
        }
        ClientServerEndpoint ep;
        ep.tox_id_hex = parse_result.value().to_hex();

        auto peer_public_key = parse_result.value().public_key();
        auto friend_result = tox_adapter_->add_friend(parse_result.value(), "toxtunnel client");
        if (!friend_result) {
            auto existing_friend = tox_adapter_->friend_by_public_key(peer_public_key);
            if (existing_friend) {
                ep.friend_number = existing_friend.value();
            } else {
                auto noreq_result = tox_adapter_->add_friend_norequest(peer_public_key);
                if (!noreq_result) {
                    return util::unexpected(std::string("Failed to add server as friend (") +
                                            ep.tox_id_hex.substr(0, 12) +
                                            "...): " + noreq_result.error());
                }
                ep.friend_number = noreq_result.value();
            }
        } else {
            ep.friend_number = friend_result.value();
        }

        if (i == 0) {
            util::Logger::info("Primary server friend added with friend number {} ({}...)",
                               ep.friend_number, ep.tox_id_hex.substr(0, 12));
        } else {
            util::Logger::info("Fallback server #{} friend added with friend number {} ({}...)", i,
                               ep.friend_number, ep.tox_id_hex.substr(0, 12));
        }
        endpoints_.push_back(std::move(ep));
    }

    // Seed offline_since on every endpoint so the failover timer has a
    // baseline to count against — without this, an endpoint that has never
    // come online has offline_since == 0 and the state machine would treat
    // it as "newly observed offline" forever.
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto& ep : endpoints_) {
            ep.offline_since = now;
        }
    }

    // Start with the primary as the active endpoint. The failover state
    // machine may promote a fallback later if the primary stays offline.
    active_index_ = 0;
    server_friend_number_.store(endpoints_[0].friend_number, std::memory_order_release);
    server_tox_id_hex_ = endpoints_[0].tox_id_hex;

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

    // Start the Prometheus /metrics HTTP server if the operator opted in.
    if (config_.metrics.enabled) {
        util::MetricsRegistry::instance().set_build_info(TOXTUNNEL_VERSION, "");
        metrics_server_ = std::make_unique<util::MetricsServer>(io_ctx_->get_io_context(),
                                                                util::MetricsRegistry::instance());
        auto err = metrics_server_->start(config_.metrics.listen, config_.metrics.path);
        if (!err.empty()) {
            util::Logger::warn("Metrics endpoint disabled: {}", err);
            metrics_server_.reset();
        }
    }

    // Start ToxAdapter iteration thread
    tox_adapter_->start();

    // Bootstrap DHT
    auto bootstrapped = tox_adapter_->bootstrap();
    util::Logger::info("Bootstrapped to {} DHT nodes", bootstrapped);

    // Log our Tox ID
    auto address = tox_adapter_->get_address();
    util::Logger::info("Client Tox ID: {}", address.to_hex());

    // Stand up the local inspect IPC before listeners come up. Failing to
    // bind only disables introspection — the client still proceeds.
    if (config_.inspect.enabled) {
        inspect_server_ = std::make_unique<InspectServer>();
        InspectProviders providers;
        providers.mode = [] { return std::string("client"); };
        providers.version = [] { return std::string(TOXTUNNEL_VERSION); };
        providers.friends_online = [this]() -> std::size_t {
            return server_online_.load(std::memory_order_acquire) ? 1u : 0u;
        };
        providers.friend_pk_prefix = [this](uint16_t /*tunnel_id*/) -> std::string {
            // Client mode talks to exactly one server, so every tunnel maps
            // to that single peer; ignore tunnel_id and return the prefix
            // directly.
            return server_tox_id_hex_.size() > 8 ? server_tox_id_hex_.substr(0, 8)
                                                 : server_tox_id_hex_;
        };
        providers.snapshot = [this]() -> tunnel::ManagerSnapshot {
            if (!tunnel_mgr_) {
                return {};
            }
            return tunnel_mgr_->snapshot();
        };
        auto inspect_ok = inspect_server_->start(io_ctx_->get_io_context(), config_.data_dir,
                                                 std::move(providers));
        if (!inspect_ok) {
            util::Logger::warn("Inspect IPC disabled: {}", inspect_ok.error());
            inspect_server_.reset();
        }
    }

    schedule_info_refresh();
    schedule_failover_tick();

    if (config_.client.has_value() && config_.client->socks5.enabled) {
        std::string s5_host;
        uint16_t s5_port = 0;
        if (util::parse_listen_spec(config_.client->socks5.listen, s5_host, s5_port)) {
            socks5_listener_ = std::make_unique<Socks5Listener>();
            auto err = socks5_listener_->start(
                io_ctx_->get_io_context(), s5_host, s5_port,
                [this](std::shared_ptr<core::TcpConnection> conn, std::string host, uint16_t port,
                       std::vector<uint8_t> initial_payload, std::function<void(bool)> reply_cb) {
                    open_socks5_tunnel(std::move(conn), std::move(host), port,
                                       std::move(initial_payload), std::move(reply_cb));
                });
            if (!err.empty()) {
                util::Logger::warn("SOCKS5 listener disabled: {}", err);
                socks5_listener_.reset();
            } else {
                util::Logger::info("SOCKS5 / HTTP CONNECT listener on {}:{}", s5_host, s5_port);
            }
        } else {
            util::Logger::warn("SOCKS5 listener disabled: invalid listen spec '{}'",
                               config_.client->socks5.listen);
        }
    }

    if (is_pipe_mode()) {
        util::Logger::info("Client running in stdio pipe mode");
        if (server_online_) {
            io_ctx_->post([this] { start_pipe_mode(); });
        }
    } else {
        // Start all TCP listeners. Capture `rule` by value: SIGHUP reload may
        // mutate `forward_rules_` (add/remove listeners) and a reference
        // capture into a vector that gets resized would dangle.
        for (std::size_t i = 0; i < listeners_.size(); ++i) {
            const auto rule = forward_rules_[i];
            auto& listener = listeners_[i];

            listener->start_accept([this, rule](std::shared_ptr<core::TcpConnection> conn) {
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

    if (inspect_server_) {
        inspect_server_->stop();
        inspect_server_.reset();
    }

    if (info_refresh_timer_) {
        info_refresh_timer_->cancel();
        info_refresh_timer_.reset();
    }

    if (failover_timer_) {
        failover_timer_->cancel();
        failover_timer_.reset();
    }

    if (socks5_listener_) {
        socks5_listener_->stop();
        socks5_listener_.reset();
    }

    // Stop all TCP listeners
    for (auto& listener : listeners_) {
        listener->stop();
    }

    if (pipe_bridge_) {
        pipe_bridge_->stop();
        pipe_bridge_.reset();
    }

    if (metrics_server_) {
        metrics_server_->stop();
        metrics_server_.reset();
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

util::Expected<void, std::string> TunnelClient::reload(const Config& new_config) {
    if (auto check = util::check_reloadable(config_, new_config); !check) {
        return util::make_unexpected(check.error());
    }

    const auto& new_client = new_config.client.value();
    const auto diff = util::diff_forwards(forward_rules_, new_client.forwards);

    if (is_pipe_mode()) {
        if (!diff.empty()) {
            return util::make_unexpected(std::string(
                "client is in pipe mode; forwards cannot be reloaded (restart to switch modes)"));
        }
    } else if (!diff.empty()) {
        for (const auto& removed : diff.removed) {
            for (std::size_t i = 0; i < forward_rules_.size();) {
                if (forward_rules_[i] == removed) {
                    listeners_[i]->stop();
                    listeners_.erase(listeners_.begin() + static_cast<std::ptrdiff_t>(i));
                    forward_rules_.erase(forward_rules_.begin() + static_cast<std::ptrdiff_t>(i));
                    util::Logger::info("Stopped listener on local port {} -> {}:{}",
                                       removed.local_port, removed.remote_host,
                                       removed.remote_port);
                } else {
                    ++i;
                }
            }
        }

        for (const auto& added : diff.added) {
            auto listener =
                std::make_unique<core::TcpListener>(io_ctx_->get_io_context(), added.local_port);
            const auto rule = added;
            listener->start_accept([this, rule](std::shared_ptr<core::TcpConnection> conn) {
                on_tcp_connection_accepted(std::move(conn), rule);
            });
            listeners_.push_back(std::move(listener));
            forward_rules_.push_back(added);
            util::Logger::info("Started listener on local port {} -> {}:{}", added.local_port,
                               added.remote_host, added.remote_port);
        }
    }

    if (config_.logging.level != new_config.logging.level) {
        util::Logger::set_level(new_config.logging.level);
    }

    config_ = new_config;
    util::Logger::info("config reloaded (forwards: +{} -{})", diff.added.size(),
                       diff.removed.size());
    return {};
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
    // Friend connection status changes. We track per-endpoint online/offline
    // timestamps; the failover state machine tick consumes them.
    tox_adapter_->set_on_friend_connection([this](uint32_t friend_number, bool connected) {
        const auto now = std::chrono::steady_clock::now();
        std::size_t hit_index = endpoints_.size();
        bool is_active = false;
        {
            std::lock_guard<std::mutex> lock(endpoints_mutex_);
            for (std::size_t i = 0; i < endpoints_.size(); ++i) {
                if (endpoints_[i].friend_number == friend_number) {
                    hit_index = i;
                    break;
                }
            }
            if (hit_index == endpoints_.size()) {
                return;  // Not one of our configured servers.
            }
            auto& ep = endpoints_[hit_index];
            if (connected && !ep.online) {
                ep.online_since = now;
            }
            if (!connected && ep.online) {
                ep.offline_since = now;
            }
            ep.online = connected;
            is_active = (hit_index == active_index_);
            if (is_active) {
                server_online_.store(connected, std::memory_order_release);
                util::MetricsRegistry::instance().set_friends_online(connected ? 1 : 0);
            }
        }

        if (is_active) {
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
        } else {
            // Non-active endpoint state change — informational only; the
            // failover state machine tick will decide whether to switch.
            util::Logger::debug("Fallback server friend {} is now {}", friend_number,
                                connected ? "online" : "offline");
        }
    });

    // Lossless packet handler: deserialize and route to TunnelManager.
    //
    // The lambda fires on the ToxAdapter iterate thread. Cheap pre-filtering
    // (friend match, min length) happens there; the actual deserialize + route
    // work is posted onto the IO pool so toxcore can keep iterating without
    // waiting on our frame handlers (whose tail eventually calls
    // TcpConnection::write — itself another post). Costs one extra vector
    // copy of the inbound packet.
    tox_adapter_->set_on_lossless_packet([this](uint32_t friend_number, const uint8_t* data,
                                                std::size_t length) {
        if (friend_number != server_friend_number_.load(std::memory_order_acquire)) {
            // Could be a stale packet from a freshly-demoted fallback, or
            // genuinely an unexpected friend. Either way, ignore.
            util::Logger::debug("Received lossless packet from non-active friend {} (active is {})",
                                friend_number,
                                server_friend_number_.load(std::memory_order_acquire));
            return;
        }
        if (length < 2) {
            util::Logger::warn("Lossless packet too short ({} bytes)", length);
            return;
        }

        std::vector<uint8_t> packet(data, data + length);
        asio::post(*inbound_strand_, [this, packet = std::move(packet)]() {
            // Skip byte 0 (lossless packet prefix byte), deserialize from byte 1.
            auto frame_data = std::span<const uint8_t>(packet.data() + 1, packet.size() - 1);
            auto frame_result = tunnel::ProtocolFrame::deserialize(frame_data);
            if (!frame_result) {
                util::Logger::error("Failed to deserialize ProtocolFrame from lossless packet");
                return;
            }

            // INFO_REPLY is a per-friend control frame outside the per-tunnel
            // routing. Intercept it before route_frame so TunnelManager
            // doesn't log a "no tunnel for id 0" warning.
            if (frame_result.value().type() == tunnel::FrameType::INFO_REPLY) {
                record_server_info(frame_result.value().as_info_reply_yaml());
                return;
            }

            tunnel_mgr_->route_frame(frame_result.value());
        });
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

        return tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), packet.data(), packet.size());
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

void TunnelClient::apply_coalesce_and_flow_control(tunnel::TunnelImpl& tunnel) {
    tunnel::CoalesceMode coalesce_mode = tunnel::CoalesceMode::Fixed;
    (void)tunnel::parse_coalesce_mode(config_.tunnel.coalesce_mode, coalesce_mode);
    tunnel.set_coalesce_mode(coalesce_mode);

    tunnel::BdpFlowControl::Config fc;
    fc.mode = tunnel::FlowControlMode::Fixed;
    (void)tunnel::parse_flow_control_mode(config_.flow_control.mode, fc.mode);
    fc.min_window_bytes = static_cast<std::int64_t>(config_.flow_control.send_window_min_bytes);
    fc.max_window_bytes = static_cast<std::int64_t>(config_.flow_control.send_window_max_bytes);
    fc.safety_factor_x100 = static_cast<std::int64_t>(config_.flow_control.safety_factor_x100);
    fc.fixed_window_bytes = static_cast<std::int64_t>(config_.flow_control.fixed_window_bytes);
    tunnel.configure_flow_control(fc);
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
    auto tunnel =
        std::make_unique<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);
    auto* tunnel_raw = tunnel.get();

    tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        std::vector<uint8_t> packet;
        packet.reserve(1 + data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), data.begin(), data.end());
        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), packet.data(), packet.size());
    });

    // Wave B zero-copy outbound: the OwnedFrameBuffer already carries the
    // lossless prefix + 5-byte tunnel header in its reserved prefix, so we
    // hand `wire_view()` straight to toxcore with zero further copies.
    tunnel->set_on_send_to_tox_owned([this](tunnel::OwnedFrameBuffer buf) {
        const auto wire = buf.wire_view();
        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), wire.data(), wire.size());
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

    auto tunnel =
        std::make_unique<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);

    // Set the TCP connection on the tunnel
    tunnel->set_tcp_connection(conn);

    // Wire callback: when TunnelImpl wants to send data to Tox, prepend the
    // lossless packet prefix and forward to ToxAdapter. The frame is already
    // serialized — no need to round-trip through deserialize / re-serialize.
    tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        std::vector<uint8_t> packet;
        packet.reserve(1 + data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), data.begin(), data.end());

        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), packet.data(), packet.size());
    });

    // Wave B zero-copy outbound for TUNNEL_DATA frames.
    tunnel->set_on_send_to_tox_owned([this](tunnel::OwnedFrameBuffer buf) {
        const auto wire = buf.wire_view();
        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), wire.data(), wire.size());
    });

    // Wire callback: when data arrives from Tox for this tunnel, write to TCP.
    // Prefer the zero-copy owned-buffer route so the payload buffer
    // allocated during `ProtocolFrame::deserialize` is handed straight to
    // the TCP write queue without an intermediate `vector<uint8_t>` copy.
    tunnel->set_on_data_for_tcp_owned(
        [conn](core::OwnedBufferView buf) { conn->write(std::move(buf)); });
    tunnel->set_on_data_for_tcp(
        [conn](std::span<const uint8_t> data) { conn->write(data.data(), data.size()); });

    // Wire state change: when Connected (ACK received), start TCP read loop.
    // Latch the open + active-gauge bookkeeping so the same tunnel can't
    // be double-counted across the Connecting -> Connected -> Closed flow.
    auto open_counted = std::make_shared<std::atomic<bool>>(false);
    auto active_dec_latch = std::make_shared<std::atomic<bool>>(false);
    tunnel->set_on_state_change(
        [conn, tunnel_id, open_counted, active_dec_latch](tunnel::Tunnel::State new_state) {
            if (new_state == tunnel::Tunnel::State::Connected) {
                util::Logger::debug("Tunnel {} connected, starting TCP read", tunnel_id);
                conn->start_read();
                if (!open_counted->exchange(true)) {
                    util::MetricsRegistry::instance().inc_tunnels_opened(
                        util::MetricsRegistry::OpenResult::Ok);
                    util::MetricsRegistry::instance().inc_tunnels_active(
                        util::MetricsRegistry::Role::Client);
                }
            } else if (new_state == tunnel::Tunnel::State::Closed ||
                       new_state == tunnel::Tunnel::State::Error) {
                util::Logger::debug("Tunnel {} state: {}", tunnel_id, to_string(new_state));
                conn->close();
                if (open_counted->load(std::memory_order_acquire) &&
                    !active_dec_latch->exchange(true)) {
                    util::MetricsRegistry::instance().dec_tunnels_active(
                        util::MetricsRegistry::Role::Client);
                }
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

void TunnelClient::open_socks5_tunnel(std::shared_ptr<core::TcpConnection> conn, std::string host,
                                      uint16_t port, std::vector<uint8_t> initial_payload,
                                      std::function<void(bool)> on_tunnel_state) {
    if (!server_online_) {
        util::Logger::warn("SOCKS5 destination {}:{} requested but server is offline", host, port);
        on_tunnel_state(false);
        conn->close();
        return;
    }

    const uint16_t tunnel_id = tunnel_mgr_->allocate_tunnel_id();
    util::Logger::debug("SOCKS5 destination {}:{} -> tunnel {}", host, port, tunnel_id);

    auto tunnel =
        std::make_unique<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);
    tunnel->set_tcp_connection(conn);

    tunnel->set_on_send_to_tox([this](std::span<const uint8_t> data) {
        std::vector<uint8_t> packet;
        packet.reserve(1 + data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), data.begin(), data.end());
        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), packet.data(), packet.size());
    });

    // Wave B zero-copy outbound for TUNNEL_DATA frames.
    tunnel->set_on_send_to_tox_owned([this](tunnel::OwnedFrameBuffer buf) {
        const auto wire = buf.wire_view();
        (void)tox_adapter_->send_lossless_packet(
            server_friend_number_.load(std::memory_order_acquire), wire.data(), wire.size());
    });

    tunnel->set_on_data_for_tcp(
        [conn](std::span<const uint8_t> data) { conn->write(data.data(), data.size()); });

    auto* tunnel_raw = tunnel.get();

    // The reply gate latch ensures the listener's reply callback is invoked
    // exactly once across all possible state transitions of this tunnel.
    auto reply_sent = std::make_shared<std::atomic<bool>>(false);
    auto open_counted = std::make_shared<std::atomic<bool>>(false);
    auto active_dec_latch = std::make_shared<std::atomic<bool>>(false);
    auto reply_cb = std::make_shared<std::function<void(bool)>>(std::move(on_tunnel_state));
    // Wrap initial_payload in a shared_ptr so the state-change lambda can drain
    // it exactly once. Bytes that arrived past the SOCKS/CONNECT handshake go
    // upstream BEFORE we start_read so the tunnel sees them in original order.
    auto initial_payload_holder =
        std::make_shared<std::vector<uint8_t>>(std::move(initial_payload));
    tunnel->set_on_state_change([conn, tunnel_id, tunnel_raw, reply_sent, open_counted,
                                 active_dec_latch, reply_cb,
                                 initial_payload_holder](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected) {
            if (!reply_sent->exchange(true)) {
                (*reply_cb)(true);
            }
            if (!initial_payload_holder->empty()) {
                tunnel_raw->on_tcp_data_received(initial_payload_holder->data(),
                                                 initial_payload_holder->size());
                initial_payload_holder->clear();
            }
            util::Logger::debug("SOCKS5 tunnel {} connected, starting TCP read", tunnel_id);
            conn->start_read();
            if (!open_counted->exchange(true)) {
                util::MetricsRegistry::instance().inc_tunnels_opened(
                    util::MetricsRegistry::OpenResult::Ok);
                util::MetricsRegistry::instance().inc_tunnels_active(
                    util::MetricsRegistry::Role::Client);
            }
        } else if (new_state == tunnel::Tunnel::State::Closed ||
                   new_state == tunnel::Tunnel::State::Error) {
            if (!reply_sent->exchange(true)) {
                (*reply_cb)(false);
            }
            util::Logger::debug("SOCKS5 tunnel {} state: {}", tunnel_id, to_string(new_state));
            conn->close();
            if (open_counted->load(std::memory_order_acquire) &&
                !active_dec_latch->exchange(true)) {
                util::MetricsRegistry::instance().dec_tunnels_active(
                    util::MetricsRegistry::Role::Client);
            }
        }
    });

    auto* tunnel_mgr_ptr = tunnel_mgr_.get();
    tunnel->set_on_close([tunnel_mgr_ptr, tunnel_id]() {
        util::Logger::debug("SOCKS5 tunnel {} on_close, removing from manager", tunnel_id);
        tunnel_mgr_ptr->remove_tunnel(tunnel_id);
    });
    conn->set_on_data([tunnel_raw](const uint8_t* data, std::size_t length) {
        tunnel_raw->on_tcp_data_received(data, length);
    });
    conn->set_on_disconnect([tunnel_raw](const std::error_code& /*ec*/) { tunnel_raw->close(); });

    bool opened = tunnel->open(host, port);
    if (!opened) {
        util::Logger::error("Failed to open SOCKS5 tunnel {} to {}:{}", tunnel_id, host, port);
        if (!reply_sent->exchange(true)) {
            (*reply_cb)(false);
        }
        conn->close();
        return;
    }
    tunnel_mgr_->add_tunnel(tunnel_id, std::move(tunnel));
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
    const uint32_t fn = server_friend_number_.load(std::memory_order_acquire);
    const bool sent = tox_adapter_->send_lossless_packet(fn, packet.data(), packet.size());
    if (!sent) {
        // The server may legitimately not implement INFO_REQUEST yet, or the
        // send queue may be full; either way let the next online transition
        // try again.
        info_request_sent_.store(false);
        util::Logger::debug("INFO_REQUEST send failed (will retry on next reconnect)");
    } else {
        util::Logger::debug("INFO_REQUEST sent to friend {}", fn);
    }
}

void TunnelClient::record_server_connection() {
    if (!known_servers_ || server_tox_id_hex_.empty())
        return;
    const auto state = tox_adapter_->get_friend_connection_status(
        server_friend_number_.load(std::memory_order_acquire));
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

// ---------------------------------------------------------------------------
// Failover state machine
// ---------------------------------------------------------------------------

std::optional<std::size_t> decide_failover_switch(
    const std::vector<ClientServerEndpoint>& endpoints, std::size_t active_index,
    const FailoverConfig& failover, std::chrono::steady_clock::time_point now) {
    if (endpoints.size() <= 1 || active_index >= endpoints.size()) {
        return std::nullopt;
    }

    auto lowest_index_online_except = [&](std::size_t exclude) -> std::optional<std::size_t> {
        for (std::size_t i = 0; i < endpoints.size(); ++i) {
            if (i == exclude) {
                continue;
            }
            if (endpoints[i].online) {
                return i;
            }
        }
        return std::nullopt;
    };

    const auto& active = endpoints[active_index];

    // Rule 1: active offline long enough -> promote.
    if (!active.online && active.offline_since != std::chrono::steady_clock::time_point{}) {
        const auto offline_for =
            std::chrono::duration_cast<std::chrono::seconds>(now - active.offline_since);
        if (offline_for.count() >= static_cast<int64_t>(failover.timeout_seconds)) {
            if (auto candidate = lowest_index_online_except(active_index); candidate.has_value()) {
                return candidate;
            }
        }
    }

    // Rule 2: switch back to primary after grace period.
    if (active_index != 0) {
        const auto& primary = endpoints[0];
        if (primary.online && primary.online_since != std::chrono::steady_clock::time_point{}) {
            const auto online_for =
                std::chrono::duration_cast<std::chrono::seconds>(now - primary.online_since);
            if (online_for.count() >= static_cast<int64_t>(failover.prefer_primary_grace_seconds)) {
                return std::size_t{0};
            }
        }
    }

    return std::nullopt;
}

std::optional<std::size_t> TunnelClient::pick_next_online_locked() const {
    // Prefer the lowest-index online endpoint that isn't currently active.
    // Lower index == closer to the configured primary.
    for (std::size_t i = 0; i < endpoints_.size(); ++i) {
        if (i == active_index_) {
            continue;
        }
        if (endpoints_[i].online) {
            return i;
        }
    }
    return std::nullopt;
}

void TunnelClient::switch_active_endpoint(std::size_t new_index) {
    std::string old_id_prefix;
    std::string new_id_prefix;
    uint32_t new_friend_number = 0;
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        if (new_index >= endpoints_.size() || new_index == active_index_) {
            return;
        }
        old_id_prefix = endpoints_[active_index_].tox_id_hex.substr(0, 12);
        active_index_ = new_index;
        new_friend_number = endpoints_[new_index].friend_number;
        new_id_prefix = endpoints_[new_index].tox_id_hex.substr(0, 12);
        server_tox_id_hex_ = endpoints_[new_index].tox_id_hex;
        server_online_.store(endpoints_[new_index].online, std::memory_order_release);
    }
    server_friend_number_.store(new_friend_number, std::memory_order_release);

    util::Logger::info("Failover: switching active server {}... -> {}... (friend {})",
                       old_id_prefix, new_id_prefix, new_friend_number);

    // Tear down tunnels routed through the previous active endpoint. The
    // listeners will re-open new tunnels through the new server on the next
    // accepted TCP connection. (For already-established TCP connections, the
    // close propagates back to the local TCP side, which matches the
    // "rebuild on switchover" semantics described in the spec.)
    info_request_sent_.store(false);
    if (tunnel_mgr_) {
        tunnel_mgr_->close_all();
    }

    // Refresh known-servers metadata if the new endpoint is already online.
    if (server_online_.load(std::memory_order_acquire)) {
        record_server_connection();
        send_info_request();
    }
}

void TunnelClient::run_failover_tick() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    if (!config_.client.has_value()) {
        return;
    }
    const auto& failover_cfg = config_.client->failover;
    const auto now = std::chrono::steady_clock::now();

    std::optional<std::size_t> switch_to;
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        switch_to = decide_failover_switch(endpoints_, active_index_, failover_cfg, now);
    }

    if (switch_to.has_value()) {
        switch_active_endpoint(*switch_to);
    }
}

void TunnelClient::schedule_failover_tick() {
    if (!io_ctx_ || !running_.load(std::memory_order_acquire)) {
        return;
    }
    // No fallbacks configured -> the state machine has nothing to do; skip
    // arming the timer entirely to keep the io_context idle.
    if (endpoints_.size() <= 1) {
        return;
    }
    if (!failover_timer_) {
        failover_timer_ = std::make_unique<asio::steady_timer>(io_ctx_->get_io_context());
    }
    failover_timer_->expires_after(kFailoverTickInterval);
    failover_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec || !running_.load(std::memory_order_acquire)) {
            return;
        }
        run_failover_tick();
        schedule_failover_tick();
    });
}

}  // namespace toxtunnel::app
