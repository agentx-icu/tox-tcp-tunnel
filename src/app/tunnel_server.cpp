#include "toxtunnel/app/tunnel_server.hpp"

#include <algorithm>
#include <shared_mutex>
#include <span>

#include "toxtunnel/app/rate_limiter.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/config_reload.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/system_info.hpp"

namespace toxtunnel::app {

using tunnel::kLosslessPacketByte;

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

TunnelServer::TunnelServer() = default;

TunnelServer::~TunnelServer() {
    if (running_.load(std::memory_order_acquire)) {
        stop();
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

util::Expected<void, std::string> TunnelServer::initialize(const Config& config) {
    config_ = config;

    if (!config_.server.has_value()) {
        return util::unexpected(std::string("Config does not contain server configuration"));
    }

    const auto& server_cfg = config_.server.value();
    const auto tox_cfg = config_.effective_tox_config();

    // Load access rules if a rules file is specified.
    if (server_cfg.rules_file.has_value()) {
        auto rules_result = RulesEngine::from_file(server_cfg.rules_file.value());
        if (!rules_result) {
            return util::unexpected(std::string("Failed to load rules file: ") +
                                    rules_result.error());
        }
        rules_engine_ = std::move(rules_result.value());
        util::Logger::info("Loaded access rules from {}", server_cfg.rules_file.value());
    } else {
        util::Logger::info("No rules file configured; using permissive defaults");
    }
    // Propagate the rate-limit configuration from the rules engine into the
    // process-wide singleton. Idempotent — safe to call again on reload.
    sync_rate_limiter();

    // Create IoContext.
    io_context_ = std::make_unique<core::IoContext>();

    // Build the inbound-dispatch strand on the IO pool so each friend's
    // lossless-packet handlers run in arrival order, preserving the order
    // toxcore already guarantees on the wire. See header comment for the
    // out-of-order bug this prevents.
    inbound_strand_.emplace(asio::make_strand(io_context_->get_io_context().get_executor()));

    // Configure ToxAdapter.
    tox::ToxAdapterConfig tox_config;
    tox_config.data_dir = config_.data_dir;
    tox_config.udp_enabled = tox_cfg.udp_enabled;
    tox_config.tcp_port = tox_cfg.tcp_port;
    tox_config.bootstrap_mode = tox_cfg.bootstrap_mode;
    tox_config.local_discovery_enabled = tox_cfg.bootstrap_mode == BootstrapMode::Lan;

    // Convert bootstrap nodes from config format.
    for (const auto& node_cfg : tox_cfg.bootstrap_nodes) {
        auto node_result = node_cfg.to_bootstrap_node();
        if (node_result) {
            tox_config.bootstrap_nodes.push_back(std::move(node_result.value()));
        } else {
            util::Logger::warn("Skipping invalid bootstrap node {}: {}", node_cfg.address,
                               node_result.error());
        }
    }

    // Initialize ToxAdapter.
    tox_adapter_ = std::make_unique<tox::ToxAdapter>();
    auto init_result = tox_adapter_->initialize(tox_config);
    if (!init_result) {
        return util::unexpected(std::string("Failed to initialize ToxAdapter: ") +
                                init_result.error());
    }

    // Wire up callbacks.
    tox_adapter_->set_on_friend_request(
        [this](const tox::PublicKeyArray& pk, std::string_view msg) {
            on_friend_request(pk, msg);
        });

    tox_adapter_->set_on_friend_connection([this](uint32_t friend_number, bool connected) {
        on_friend_connection(friend_number, connected);
    });

    tox_adapter_->set_on_lossless_packet(
        [this](uint32_t friend_number, const uint8_t* data, std::size_t length) {
            // Fires on the ToxAdapter iterate thread. Copy + post onto the IO
            // pool so subsequent frame deserialization, tunnel routing, and
            // TCP egress writes don't block the next tox_iterate tick. Costs
            // one extra vector copy per inbound packet (at most ~1373 B); the
            // win is keeping the Tox thread free to push outbound packets at
            // the next 50ms tick rather than waiting for our processing.
            std::vector<uint8_t> packet(data, data + length);
            asio::post(*inbound_strand_, [this, friend_number, packet = std::move(packet)]() {
                on_lossless_packet(friend_number, packet.data(), packet.size());
            });
        });

    tox_adapter_->set_on_self_connection([this](bool connected) { on_self_connection(connected); });

    util::Logger::info("TunnelServer initialized successfully");
    return {};
}

void TunnelServer::start() {
    if (running_.load(std::memory_order_acquire)) {
        util::Logger::warn("TunnelServer::start() called but already running");
        return;
    }

    // Start IoContext thread pool.
    io_context_->run();

    // Start the Prometheus /metrics HTTP server if the operator opted in.
    if (config_.metrics.enabled) {
        util::MetricsRegistry::instance().set_build_info(TOXTUNNEL_VERSION, "");
        metrics_server_ = std::make_unique<util::MetricsServer>(io_context_->get_io_context(),
                                                                util::MetricsRegistry::instance());
        auto err = metrics_server_->start(config_.metrics.listen, config_.metrics.path);
        if (!err.empty()) {
            util::Logger::warn("Metrics endpoint disabled: {}", err);
            metrics_server_.reset();
        }
    }

    // Start the Tox-thread watchdog *before* the iterate loop so the
    // first heartbeat lands on a primed observer.
    if (config_.watchdog.enabled) {
        watchdog_ = std::make_unique<tox::ToxWatchdog>();
        watchdog_->configure(std::chrono::seconds(config_.watchdog.deadline_seconds),
                             config_.watchdog.enabled);
        watchdog_->set_data_dir(config_.data_dir);
        tox_adapter_->set_watchdog(watchdog_.get());
        watchdog_->start(io_context_->get_io_context());
        util::Logger::info("Tox-thread watchdog enabled (deadline={}s)",
                           config_.watchdog.deadline_seconds);
    }

    // Start ToxAdapter iteration thread.
    tox_adapter_->start();

    // Bootstrap DHT.
    auto bootstrapped = tox_adapter_->bootstrap();
    util::Logger::info("Bootstrapped to {} DHT nodes", bootstrapped);

    // Log the Tox ID.
    auto address = tox_adapter_->get_address();
    util::Logger::info("Tox ID: {}", address.to_hex());

    // Bring up the local IPC inspector after the rest of the daemon so a
    // failing inspect bind cannot prevent the tunnel server from servicing
    // tunnels — the daemon must keep working even if /run is read-only.
    if (config_.inspect.enabled) {
        inspect_server_ = std::make_unique<InspectServer>();
        InspectProviders providers;
        providers.mode = [] { return std::string("server"); };
        providers.version = [] { return std::string(TOXTUNNEL_VERSION); };
        providers.friends_online = [this]() -> std::size_t {
            std::lock_guard lock(managers_mutex_);
            return managers_.size();
        };
        providers.friend_pk_prefix = [this](uint16_t tunnel_id) -> std::string {
            std::lock_guard lock(managers_mutex_);
            for (const auto& [friend_number, manager] : managers_) {
                if (manager->has_tunnel(tunnel_id)) {
                    auto hex = get_friend_pk_hex(friend_number);
                    return hex.size() > 8 ? hex.substr(0, 8) : hex;
                }
            }
            return {};
        };
        providers.snapshot = [this] {
            tunnel::ManagerSnapshot combined;
            std::lock_guard lock(managers_mutex_);
            for (const auto& [_, manager] : managers_) {
                auto snap = manager->snapshot();
                combined.bytes_in += snap.bytes_in;
                combined.bytes_out += snap.bytes_out;
                combined.frames_in += snap.frames_in;
                combined.frames_out += snap.frames_out;
                combined.tunnels.insert(combined.tunnels.end(),
                                        std::make_move_iterator(snap.tunnels.begin()),
                                        std::make_move_iterator(snap.tunnels.end()));
            }
            return combined;
        };
        auto inspect_ok = inspect_server_->start(io_context_->get_io_context(), config_.data_dir,
                                                 std::move(providers));
        if (!inspect_ok) {
            util::Logger::warn("Inspect IPC disabled: {}", inspect_ok.error());
            inspect_server_.reset();
        }
    }

    running_.store(true, std::memory_order_release);
    util::Logger::info("TunnelServer started");
}

void TunnelServer::stop() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    util::Logger::info("TunnelServer stopping...");

    // Phase 1: cancel pending async work but keep the owners alive — the
    // InspectServer/MetricsServer acceptor callbacks captured `this`, so
    // freeing them now (before io_context drains) would UAF on a
    // dispatched-but-not-yet-executed handler (S20 in the 2026-05-20
    // follow-up).
    if (inspect_server_) {
        inspect_server_->stop();
    }
    if (metrics_server_) {
        metrics_server_->stop();
    }

    // Close all tunnel managers.
    {
        std::lock_guard lock(managers_mutex_);
        for (auto& [friend_number, manager] : managers_) {
            util::Logger::debug("Closing tunnels for friend {}", friend_number);
            manager->close_all();
        }
        managers_.clear();
    }

    // Stop watchdog before Tox so it doesn't trip during shutdown.
    if (watchdog_) {
        tox_adapter_->set_watchdog(nullptr);
        watchdog_->stop();
        watchdog_.reset();
    }
    tox_adapter_->stop();

    // Phase 2: stop the io_context and join its workers. After this
    // returns, no async callback can run any more.
    io_context_->stop();

    // Phase 3: NOW it's safe to free the sub-servers; their callbacks
    // have all been drained.
    inspect_server_.reset();
    metrics_server_.reset();

    running_.store(false, std::memory_order_release);
    util::Logger::info("TunnelServer stopped");
}

bool TunnelServer::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

util::Expected<void, std::string> TunnelServer::reload(const Config& new_config) {
    if (auto check = util::check_reloadable(config_, new_config); !check) {
        return util::make_unexpected(check.error());
    }

    std::size_t rule_count = 0;
    if (new_config.server.has_value() && new_config.server->rules_file.has_value()) {
        auto rules_result = RulesEngine::from_file(new_config.server->rules_file.value());
        if (!rules_result) {
            return util::make_unexpected(std::string("Failed to load rules file: ") +
                                         rules_result.error());
        }
        rule_count = rules_result.value().rules().size();
        std::unique_lock rules_lock(rules_mutex_);
        rules_engine_ = std::move(rules_result.value());
    } else {
        std::unique_lock rules_lock(rules_mutex_);
        rules_engine_ = RulesEngine{};
    }
    sync_rate_limiter();

    if (config_.logging.level != new_config.logging.level) {
        util::Logger::set_level(new_config.logging.level);
    }

    config_ = new_config;
    util::Logger::info("config reloaded (rules: {} rules)", rule_count);
    return {};
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

std::string TunnelServer::get_tox_address() const {
    return tox_adapter_->get_address().to_hex();
}

// ---------------------------------------------------------------------------
// Callback handlers
// ---------------------------------------------------------------------------

void TunnelServer::on_friend_request(const tox::PublicKeyArray& public_key,
                                     std::string_view message) {
    auto pk_hex = tox::bytes_to_hex(public_key.data(), public_key.size());
    util::Logger::info("Friend request from {} (message: {})", pk_hex, message);

    // Auto-accept friend requests.
    auto result = tox_adapter_->add_friend_norequest(public_key);
    if (result) {
        util::Logger::info("Accepted friend request from {}, friend_number={}", pk_hex,
                           result.value());
    } else {
        util::Logger::error("Failed to accept friend request from {}: {}", pk_hex, result.error());
    }
}

void TunnelServer::on_friend_connection(uint32_t friend_number, bool connected) {
    auto pk_hex = get_friend_pk_hex(friend_number);

    if (connected) {
        util::Logger::info("Friend {} (pk={}) connected", friend_number, pk_hex);
        setup_tunnel_manager(friend_number);
    } else {
        util::Logger::info("Friend {} (pk={}) disconnected", friend_number, pk_hex);
        teardown_tunnel_manager(friend_number);
    }
    // Recompute from the canonical source (managers_ map) so churn during
    // a Tox reconnect can't drift the gauge.
    std::lock_guard lock(managers_mutex_);
    util::MetricsRegistry::instance().set_friends_online(managers_.size());
}

void TunnelServer::on_lossless_packet(uint32_t friend_number, const uint8_t* data,
                                      std::size_t length) {
    // Lossless packets start with a byte in [160-191]. The actual frame
    // data starts at data[1].
    if (length < 2) {
        util::Logger::warn("Received lossless packet from friend {} with length {} (too short)",
                           friend_number, length);
        return;
    }

    // Deserialize the ProtocolFrame from data+1.
    auto frame_result =
        tunnel::ProtocolFrame::deserialize(std::span<const uint8_t>(data + 1, length - 1));

    if (!frame_result) {
        util::Logger::warn("Failed to deserialize frame from friend {}: {}", friend_number,
                           frame_result.error().message());
        return;
    }

    auto& frame = frame_result.value();

    // Handle INFO_REQUEST as a per-friend control frame outside the TunnelManager
    // (it is not bound to a tunnel_id). Reply with an INFO_REPLY whose payload
    // is filtered by `server.disclose.*`. Always reply — even with an empty
    // payload — so the client can distinguish "modern server, nothing to share"
    // from "old server, ignored the request".
    if (frame.type() == tunnel::FrameType::INFO_REQUEST) {
        const auto& disclose =
            config_.server.has_value() ? config_.server->disclose : ServerInfoDisclose{};
        const auto snapshot = util::gather_system_info(disclose);
        const auto yaml = util::snapshot_to_yaml(snapshot);

        std::vector<uint8_t> packet;
        auto reply = tunnel::ProtocolFrame::make_info_reply(yaml);
        auto wire = reply.serialize();
        packet.reserve(1 + wire.size());
        packet.push_back(kLosslessPacketByte);
        packet.insert(packet.end(), wire.begin(), wire.end());
        const bool sent =
            tox_adapter_->send_lossless_packet(friend_number, packet.data(), packet.size());
        util::Logger::debug(
            "INFO_REQUEST from friend {}: replied with {} bytes ({} fields disclosed, send={})",
            friend_number, yaml.size(), disclose.any() ? "some" : "no", sent);
        return;
    }

    // Handle TUNNEL_OPEN specially: need to check access rules and create TCP connection.
    if (frame.type() == tunnel::FrameType::TUNNEL_OPEN) {
        handle_tunnel_open(friend_number, frame);
        return;
    }

    // Route all other frames to the friend's TunnelManager.
    // IMPORTANT: We must NOT hold managers_mutex_ when calling route_frame(),
    // because route_frame() can synchronously trigger callbacks (e.g., via
    // tcp_conn->close() -> on_disconnect) that need to re-acquire managers_mutex_.
    // Copy the shared_ptr inside the lock so a racing teardown can't free
    // the manager between the lookup and the call (C-1 in the 2026-05-20
    // review).
    std::shared_ptr<tunnel::TunnelManager> manager_ptr;
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it == managers_.end()) {
            util::Logger::warn("Received frame from friend {} but no TunnelManager exists",
                               friend_number);
            return;
        }
        manager_ptr = it->second;
    }

    manager_ptr->route_frame(frame);
}

void TunnelServer::on_self_connection(bool connected) {
    if (connected) {
        util::Logger::info("Connected to Tox DHT");
    } else {
        util::Logger::warn("Disconnected from Tox DHT");
    }
}

void TunnelServer::sync_rate_limiter() {
    auto& limiter = rate_limiter_instance();
    std::shared_lock rules_lock(rules_mutex_);
    // Wipe all prior per-friend specs and bucket state. Without this, a
    // friend that was present in the old rules but removed from the new
    // ones would silently retain its old token bucket and continue to be
    // limited (or unlimited) per the stale spec. Re-applying defaults +
    // per-friend overrides below rebuilds the table from scratch.
    limiter.clear_all_friend_specs();
    limiter.set_default_spec(rules_engine_.rate_limit_defaults());
    for (const auto& rule : rules_engine_.rules()) {
        if (!rule.rate_limit.empty()) {
            limiter.set_friend_spec(rule.friend_pk, rule.rate_limit);
        }
    }
}

void TunnelServer::apply_coalesce_and_flow_control(tunnel::TunnelImpl& tunnel) {
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void TunnelServer::setup_tunnel_manager(uint32_t friend_number) {
    auto manager = std::make_shared<tunnel::TunnelManager>(io_context_->get_io_context());

    // Set up the send handler: serialize frame, prepend lossless packet byte,
    // send via ToxAdapter.
    manager->set_send_handler(
        [this, friend_number](const std::vector<uint8_t>& frame_data) -> bool {
            // Prepend the lossless packet prefix byte.
            std::vector<uint8_t> packet;
            packet.reserve(1 + frame_data.size());
            packet.push_back(kLosslessPacketByte);
            packet.insert(packet.end(), frame_data.begin(), frame_data.end());

            return tox_adapter_->send_lossless_packet(friend_number, packet);
        });

    // Set up tunnel created callback for logging.
    manager->set_on_tunnel_created([friend_number](uint16_t tunnel_id) {
        util::Logger::debug("Tunnel {} created for friend {}", tunnel_id, friend_number);
    });

    // Set up tunnel closed callback for logging.
    manager->set_on_tunnel_closed([friend_number](uint16_t tunnel_id) {
        util::Logger::debug("Tunnel {} closed for friend {}", tunnel_id, friend_number);
    });

    std::lock_guard lock(managers_mutex_);
    managers_[friend_number] = std::move(manager);
}

void TunnelServer::teardown_tunnel_manager(uint32_t friend_number) {
    std::lock_guard lock(managers_mutex_);
    auto it = managers_.find(friend_number);
    if (it != managers_.end()) {
        it->second->close_all();
        managers_.erase(it);
    }
}

void TunnelServer::handle_tunnel_open(uint32_t friend_number, const tunnel::ProtocolFrame& frame) {
    auto open_payload = frame.as_tunnel_open();
    if (!open_payload) {
        util::Logger::warn("Malformed TUNNEL_OPEN from friend {}", friend_number);
        return;
    }

    auto target_host = open_payload->host;
    auto target_port = open_payload->port;
    auto tunnel_id = frame.tunnel_id();

    util::Logger::info("TUNNEL_OPEN from friend {}: tunnel_id={} target={}:{}", friend_number,
                       tunnel_id, target_host, target_port);

    // Anti-DoS rate limit (runs *before* RulesEngine — a rejected friend
    // burns no rules-engine CPU). Mode == Off / Report short-circuits inside
    // the limiter and always returns true.
    auto pk_hex = get_friend_pk_hex(friend_number);
    if (!rate_limiter_instance().try_consume_open(pk_hex)) {
        util::Logger::warn("Rate-limit OPEN reject for friend {} (tunnel_id={})", pk_hex,
                           tunnel_id);
        util::MetricsRegistry::instance().inc_tunnels_opened(
            util::MetricsRegistry::OpenResult::Denied);
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it != managers_.end()) {
            auto error_frame =
                tunnel::ProtocolFrame::make_tunnel_error(tunnel_id, 3, "Rate limit exceeded");
            it->second->send_frame(error_frame);
        }
        return;
    }

    // Check access rules.
    AccessRequest access_req;
    access_req.friend_pk = pk_hex;
    access_req.target_host = target_host;
    access_req.target_port = target_port;

    AccessResult access_result;
    {
        std::shared_lock rules_lock(rules_mutex_);
        access_result = rules_engine_.evaluate(access_req);
    }
    // S14 / 2026-05-20 follow-up: RulesEngine documents a default-deny
    // policy (`rules_engine.hpp:88`) and `evaluate()` itself comments
    // "No matching rule - use default deny" when returning Default. The
    // previous tunnel_server treated Default as "permissive default" and
    // allowed the request — turning the documented default-deny ACL into
    // a default-allow ACL. Only AccessResult::Allowed should pass through.
    if (access_result != AccessResult::Allowed) {
        const char* reason = access_result == AccessResult::Denied
                                 ? "Access denied"
                                 : "No matching allow rule (default deny)";
        util::Logger::warn("Access {} for friend {} to {}:{} ({})",
                           access_result == AccessResult::Denied ? "denied" : "default-denied",
                           pk_hex, target_host, target_port, reason);
        util::MetricsRegistry::instance().inc_tunnels_opened(
            util::MetricsRegistry::OpenResult::Denied);

        // Send error frame back.
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it != managers_.end()) {
            auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(tunnel_id, 1, reason);
            it->second->send_frame(error_frame);
        }
        return;
    }

    util::Logger::debug("Access allowed for friend {} to {}:{}", pk_hex, target_host, target_port);

    // Find or validate the TunnelManager. Hold a shared_ptr copy so the
    // long unlocked tail (handle_incoming_open + async_resolve + connect
    // wiring + add_tunnel) cannot race with a friend-offline teardown
    // (C-2 in the 2026-05-20 review).
    std::shared_ptr<tunnel::TunnelManager> manager_ptr;
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it == managers_.end()) {
            util::Logger::warn("No TunnelManager for friend {} during TUNNEL_OPEN", friend_number);
            return;
        }
        manager_ptr = it->second;
    }

    // Let TunnelManager handle the incoming open (reserves the tunnel_id
    // slot via used_ids_). The slot is released by the RAII guard below
    // unless we successfully reach add_tunnel(), which re-claims it
    // through the same code path. Without the guard, any future early
    // return between handle_incoming_open() and add_tunnel() would leak
    // the slot — 65534 leaks and all IDs are gone (C-19 in the
    // 2026-05-20 review).
    if (!manager_ptr->handle_incoming_open(frame)) {
        util::Logger::warn("TunnelManager rejected TUNNEL_OPEN for tunnel_id={} from friend {}",
                           tunnel_id, friend_number);
        return;
    }
    struct TunnelIdGuard {
        tunnel::TunnelManager* mgr;
        uint16_t id;
        bool committed = false;
        ~TunnelIdGuard() {
            if (!committed && mgr) {
                mgr->release_tunnel_id(id);
            }
        }
    };
    TunnelIdGuard id_guard{manager_ptr.get(), tunnel_id, false};

    auto server_tunnel = std::make_shared<tunnel::TunnelImpl>(io_context_->get_io_context(),
                                                              tunnel_id, friend_number);
    server_tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                                      config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*server_tunnel);
    // Already-serialized frame from TunnelImpl: prepend the lossless prefix
    // byte and send directly. Going via manager_ptr->send_frame would force a
    // deserialize + re-serialize round trip plus a redundant byte copy.
    server_tunnel->set_on_send_to_tox(
        [this, manager_ptr, friend_number](std::span<const uint8_t> data) {
            std::vector<uint8_t> packet;
            packet.reserve(1 + data.size());
            packet.push_back(tunnel::kLosslessPacketByte);
            packet.insert(packet.end(), data.begin(), data.end());
            if (tox_adapter_->send_lossless_packet(friend_number, packet.data(), packet.size())) {
                manager_ptr->record_frame_sent();
                manager_ptr->record_bytes_sent(data.size());
            }
        });
    // Wave B zero-copy outbound: the OwnedFrameBuffer already carries the
    // lossless prefix + 5-byte tunnel header in the same allocation.
    server_tunnel->set_on_send_to_tox_owned(
        [this, manager_ptr, friend_number](tunnel::OwnedFrameBuffer buf) {
            const auto wire = buf.wire_view();
            if (tox_adapter_->send_lossless_packet(friend_number, wire.data(), wire.size())) {
                manager_ptr->record_frame_sent();
                // The lossless prefix byte is bookkeeping overhead, not payload.
                manager_ptr->record_bytes_sent(wire.size() > 1 ? wire.size() - 1 : 0);
            }
        });
    manager_ptr->add_tunnel(tunnel_id, std::move(server_tunnel));
    // add_tunnel re-set used_ids_[tunnel_id]; the guard's release would
    // now wrongly free it. Commit so the destructor skips the release.
    id_guard.committed = true;

    // Create a TCP connection to the target host:port.
    auto tcp_conn = std::make_shared<core::TcpConnection>(io_context_->get_io_context());

    // Resolve the target host and connect.
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io_context_->get_io_context());

    resolver->async_resolve(
        target_host, std::to_string(target_port),
        [this, resolver, tcp_conn, friend_number, tunnel_id, target_host, target_port](
            const std::error_code& ec, asio::ip::tcp::resolver::results_type results) {
            if (ec) {
                util::Logger::error("Failed to resolve {}:{} for tunnel {}: {}", target_host,
                                    target_port, tunnel_id, ec.message());
                util::MetricsRegistry::instance().inc_tunnels_opened(
                    util::MetricsRegistry::OpenResult::Failed);

                // Send error and close the tunnel.
                std::lock_guard lock(managers_mutex_);
                auto it = managers_.find(friend_number);
                if (it != managers_.end()) {
                    auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
                        tunnel_id, 2, "DNS resolution failed: " + ec.message());
                    it->second->send_frame(error_frame);
                    it->second->remove_tunnel(tunnel_id);
                }
                return;
            }

            // Connect to the first resolved endpoint.
            auto endpoint = results.begin()->endpoint();
            tcp_conn->async_connect(endpoint, [this, tcp_conn, friend_number, tunnel_id,
                                               target_host,
                                               target_port](const std::error_code& connect_ec) {
                if (connect_ec) {
                    util::Logger::error("Failed to connect to {}:{} for tunnel {}: {}", target_host,
                                        target_port, tunnel_id, connect_ec.message());
                    util::MetricsRegistry::instance().inc_tunnels_opened(
                        util::MetricsRegistry::OpenResult::Failed);

                    std::lock_guard lock(managers_mutex_);
                    auto it = managers_.find(friend_number);
                    if (it != managers_.end()) {
                        auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
                            tunnel_id, 3, "TCP connect failed: " + connect_ec.message());
                        it->second->send_frame(error_frame);
                        it->second->remove_tunnel(tunnel_id);
                    }
                    return;
                }

                util::Logger::info("TCP connected to {}:{} for tunnel {} (friend {})", target_host,
                                   target_port, tunnel_id, friend_number);

                // Wire up the TCP connection to the tunnel.
                wire_tcp_to_tunnel(friend_number, tunnel_id, tcp_conn);
            });
        });
}

void TunnelServer::wire_tcp_to_tunnel(uint32_t friend_number, uint16_t tunnel_id,
                                      std::shared_ptr<core::TcpConnection> tcp_conn) {
    // Hold a shared_ptr to the TunnelImpl so its lifetime extends across the
    // TCP strand's async callbacks, even if remove_tunnel() fires from the Tox
    // strand mid-flight. Same shared_ptr discipline for the manager
    // (M-1 in the 2026-05-20 review): the unlocked tail below calls
    // manager_ptr->send_frame(ack) after the lock is released.
    std::shared_ptr<tunnel::TunnelImpl> tunnel_impl;
    std::shared_ptr<tunnel::TunnelManager> manager_ptr;

    // Look up manager and tunnel under the lock, then release immediately.
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it == managers_.end()) {
            util::Logger::warn("Cannot wire tunnel {}: no TunnelManager for friend {}", tunnel_id,
                               friend_number);
            tcp_conn->close();
            return;
        }
        manager_ptr = it->second;

        auto tunnel = manager_ptr->get_tunnel(tunnel_id);
        if (!tunnel) {
            util::Logger::warn("Cannot wire: tunnel {} not found for friend {}", tunnel_id,
                               friend_number);
            tcp_conn->close();
            return;
        }

        // Downcast to TunnelImpl for the extended API.
        tunnel_impl = std::dynamic_pointer_cast<tunnel::TunnelImpl>(tunnel);
        if (!tunnel_impl) {
            util::Logger::error("Tunnel {} is not a TunnelImpl", tunnel_id);
            tcp_conn->close();
            return;
        }
    }

    // All wiring below happens WITHOUT holding managers_mutex_.
    // Capturing tunnel_impl by value into each callback keeps the underlying
    // Tunnel alive past remove_tunnel(); the last shared_ptr to release the
    // tunnel is the TcpConnection's callback slot when the TCP socket dies.

    // Associate the TCP connection with the tunnel.
    tunnel_impl->set_tcp_connection(tcp_conn);

    // TCP data -> Tox: when data arrives from TCP, forward it to the tunnel.
    tcp_conn->set_on_data([tunnel_impl](const uint8_t* data, std::size_t length) {
        tunnel_impl->on_tcp_data_received(data, length);
    });

    // TCP disconnect: close the tunnel gracefully.
    // Uses asio::post to defer cleanup, avoiding re-entrance into managers_mutex_
    // if on_disconnect fires synchronously from tcp_conn->close().
    tcp_conn->set_on_disconnect([this, friend_number, tunnel_id](const std::error_code& ec) {
        util::Logger::debug("TCP disconnected for tunnel {} (friend {}): {}", tunnel_id,
                            friend_number, ec.message());

        asio::post(io_context_->get_io_context(), [this, friend_number, tunnel_id]() {
            std::lock_guard inner_lock(managers_mutex_);
            auto mgr_it = managers_.find(friend_number);
            if (mgr_it != managers_.end()) {
                // Send a TUNNEL_CLOSE to the remote peer and remove the tunnel.
                auto close_frame = tunnel::ProtocolFrame::make_tunnel_close(tunnel_id);
                mgr_it->second->send_frame(close_frame);
                mgr_it->second->remove_tunnel(tunnel_id);
            }
        });
    });

    // Tox data -> TCP: set up the callback so tunnel data is written to TCP.
    //
    // Wire the owned-buffer callback for zero-copy hand-off: the shared
    // payload allocated by `ProtocolFrame::deserialize` is passed straight
    // through to `TcpConnection::write(OwnedBufferView)` without any further
    // copy. The buffer's lifetime is held by the shared_ptr until the
    // async TCP write completes. The span-based callback is kept as a
    // safety net for any code path that bypasses the owned-buffer route.
    tunnel_impl->set_on_data_for_tcp_owned(
        [tcp_conn](core::OwnedBufferView buf) { tcp_conn->write(std::move(buf)); });
    tunnel_impl->set_on_data_for_tcp(
        [tcp_conn](std::span<const uint8_t> data) { tcp_conn->write(data.data(), data.size()); });

    // Tunnel close callback: close the TCP connection when the tunnel is closed
    // from the Tox side.
    tunnel_impl->set_on_close([tcp_conn]() { tcp_conn->close(); });

    // Transition the tunnel to Connected state and send ACK to the remote peer.
    tunnel_impl->set_state(tunnel::Tunnel::State::Connected);
    util::MetricsRegistry::instance().inc_tunnels_opened(util::MetricsRegistry::OpenResult::Ok);
    util::MetricsRegistry::instance().inc_tunnels_active(util::MetricsRegistry::Role::Server);
    // Decrement the active gauge once the tunnel reaches a terminal state.
    // Latch via shared_ptr<atomic_flag> so multiple state callbacks (Closed
    // and then Error, or vice versa) never double-decrement.
    auto active_dec_latch = std::make_shared<std::atomic_flag>();
    tunnel_impl->set_on_state_change([active_dec_latch](tunnel::Tunnel::State new_state) {
        if ((new_state == tunnel::Tunnel::State::Closed ||
             new_state == tunnel::Tunnel::State::Error) &&
            !active_dec_latch->test_and_set()) {
            util::MetricsRegistry::instance().dec_tunnels_active(
                util::MetricsRegistry::Role::Server);
        }
    });

    // Send TUNNEL_ACK to confirm the tunnel is open.
    auto ack_frame = tunnel::ProtocolFrame::make_tunnel_ack(tunnel_id, 0);
    manager_ptr->send_frame(ack_frame);

    // Start reading from the TCP connection.
    tcp_conn->start_read();

    util::Logger::debug("Tunnel {} wired to TCP for friend {}", tunnel_id, friend_number);
}

std::string TunnelServer::get_friend_pk_hex(uint32_t friend_number) const {
    auto pk_result = tox_adapter_->get_friend_public_key(friend_number);
    if (pk_result) {
        return tox::bytes_to_hex(pk_result.value().data(), pk_result.value().size());
    }
    return "unknown";
}

}  // namespace toxtunnel::app
