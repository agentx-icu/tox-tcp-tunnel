#include "toxtunnel/app/tunnel_client.hpp"

#include <algorithm>
#include <cstdio>
#include <future>
#include <span>

#include "toxtunnel/app/tunnel_senders.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/asio_timer.hpp"
#include "toxtunnel/util/config_reload.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/system_info.hpp"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace toxtunnel::app {

namespace detail {

// `LosslessPacketSendFn` returns a plain bool, which cannot express SendqFull —
// it is the shape of the *legacy* `ToxAdapter::send_lossless_packet`, not of
// `send_lossless_packet_typed`. Both helpers below therefore map true -> Sent
// and false -> PermanentFail: a lost bool cannot be recovered, and reporting a
// transient refusal as PermanentFail is the safe direction (the caller rolls
// back rather than believing a frame reached the peer).
//
// Neither helper is used in production — the three live client tunnel paths
// wire their callbacks inline so they can also drive TunnelManager's byte /
// frame counters — and the only callers are in
// tests/unit/client_failover_test.cpp. Do not reach for these from production
// code without first giving them a typed send function.

tunnel::TunnelImpl::SendToToxCallback make_fixed_friend_lossless_sender(
    LosslessPacketSendFn send_lossless, uint32_t friend_number) {
    return [send_lossless = std::move(send_lossless),
            friend_number](std::span<const uint8_t> data) -> tunnel::SendOutcome {
        std::vector<uint8_t> packet;
        packet.reserve(1 + data.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), data.begin(), data.end());
        return send_lossless(friend_number, packet.data(), packet.size())
                   ? tunnel::SendOutcome::Sent
                   : tunnel::SendOutcome::PermanentFail;
    };
}

tunnel::TunnelImpl::SendOwnedToToxCallback make_fixed_friend_lossless_owned_sender(
    LosslessPacketSendFn send_lossless, uint32_t friend_number) {
    return [send_lossless = std::move(send_lossless),
            friend_number](tunnel::OwnedFrameBuffer buf) -> tunnel::SendOutcome {
        const auto wire = buf.wire_view();
        return send_lossless(friend_number, wire.data(), wire.size())
                   ? tunnel::SendOutcome::Sent
                   : tunnel::SendOutcome::PermanentFail;
    };
}

}  // namespace detail

// -------------------------------------------------------------------------
// Construction / Destruction
// -------------------------------------------------------------------------

TunnelClient::TunnelClient() = default;

TunnelClient::~TunnelClient() {
    if (running_) {
        // stop() now rethrows the first shutdown-step exception to explicit
        // callers; a destructor must not propagate (issue #29).
        try {
            stop();
        } catch (const std::exception& e) {
            try {
                util::Logger::warn("~TunnelClient: stop() threw during teardown: {}", e.what());
            } catch (...) {
            }
        } catch (...) {
        }
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
    tox_config.ipv6_enabled = tox_cfg.ipv6_enabled;
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
    if (auto err = known_servers_->last_load_error(); err.has_value()) {
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
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        server_tox_id_hex_ = endpoints_[0].tox_id_hex;
    }

    // Create TunnelManager
    tunnel_mgr_ = std::make_shared<tunnel::TunnelManager>(io_ctx_->get_io_context());

    // Idle reaper (opt-in) + half-close linger cap (on by default). Enabled once
    // for the manager's lifetime — unlike keepalive, this is not connection-state
    // dependent. The half-close cap bounds a client-side tunnel stuck in
    // Disconnecting when the server never sends the reciprocal TUNNEL_CLOSE
    // (mirror of the v0.4.4 stuck-Disconnecting leak). Both no-op when 0.
    tunnel_mgr_->enable_reaper(config_.tunnel.idle_timeout_seconds,
                               config_.tunnel.reaper_tick_seconds);
    tunnel_mgr_->enable_half_close_reaper(config_.tunnel.half_close_timeout_seconds,
                                          config_.tunnel.reaper_tick_seconds);

    // Set up callbacks and handlers
    setup_tox_callbacks();
    setup_tunnel_manager();

    // Create TCP listeners for each forwarding rule
    if (auto listeners_ok = create_listeners(client_cfg.forwards); !listeners_ok) {
        return util::make_unexpected(listeners_ok.error());
    }

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
        providers.peer_online_seconds = [this]() -> std::size_t {
            // Seconds the active server has been continuously online, or 0 when
            // offline. Snapshot under endpoints_mutex_ to avoid racing with
            // the friend-status callback / switch_active_endpoint.
            if (!server_online_.load(std::memory_order_acquire)) {
                return 0;
            }
            std::lock_guard<std::mutex> lock(endpoints_mutex_);
            if (active_index_ >= endpoints_.size()) {
                return 0;
            }
            const auto& active = endpoints_[active_index_];
            if (active.online_since == std::chrono::steady_clock::time_point{}) {
                return 0;
            }
            const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::steady_clock::now() - active.online_since)
                                  .count();
            return secs > 0 ? static_cast<std::size_t>(secs) : 0;
        };
        providers.friend_pk_prefix = [this](uint16_t /*tunnel_id*/) -> std::string {
            // Client mode talks to exactly one server, so every tunnel maps
            // to that single peer; ignore tunnel_id and return the prefix
            // directly. Snapshot under `endpoints_mutex_` to avoid racing
            // with `switch_active_endpoint`.
            const auto hex = server_tox_id_snapshot();
            return hex.size() > 8 ? hex.substr(0, 8) : hex;
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
    schedule_connectivity_log_tick();

    if (config_.client.has_value() && config_.client->socks5.enabled) {
        std::string s5_host;
        uint16_t s5_port = 0;
        if (util::parse_listen_spec(config_.client->socks5.listen, s5_host, s5_port)) {
            socks5_listener_ = std::make_shared<Socks5Listener>();
            auto err = socks5_listener_->start(
                io_ctx_->get_io_context(), s5_host, s5_port,
                [this](std::shared_ptr<core::TcpConnection> conn, std::string host, uint16_t port,
                       std::vector<uint8_t> initial_payload,
                       std::function<void(TunnelOpenOutcome)> reply_cb) {
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

            util::Logger::info("Listening on {} -> {}:{}", rule.local_endpoint_label(),
                               rule.remote_host, rule.remote_port);
        }
    }
}

void TunnelClient::stop() {
    // Single-entry: the signal thread (SIGINT/SIGTERM) and the
    // wait_until_stopped() thread (woken by request_stop) can race here. Only
    // the first caller runs the teardown; the loser returns immediately.
    if (stop_started_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    if (!running_) {
        return;
    }

    util::Logger::info("Stopping TunnelClient...");

    // Phase isolation (issue #29): stop() is reached from ~TunnelClient, where
    // an exception would std::terminate, and stop_started_ is already latched
    // so a throw partway leaves the client half torn down with no retry. Every
    // shutdown step runs even if an earlier one throws; the first exception is
    // remembered and rethrown at the very end (after io_ctx_->stop() and the
    // running_ clear), so an explicit stop() caller still learns of it while a
    // destructor caller — see ~TunnelClient — swallows it.
    std::exception_ptr first_ex;
    const auto step = [&first_ex](const char* what, auto&& fn) noexcept {
        try {
            fn();
        } catch (const std::exception& e) {
            try {
                util::Logger::warn("TunnelClient::stop: {} threw: {}", what, e.what());
            } catch (...) {
            }
            if (!first_ex) {
                first_ex = std::current_exception();
            }
        } catch (...) {
            if (!first_ex) {
                first_ex = std::current_exception();
            }
        }
    };

    // Phase 1: signal everything to wind down. We only *cancel* pending
    // async work here; we do NOT yet free the owners. Several of our
    // sub-servers (InspectServer / MetricsServer / Socks5Listener)
    // captured `this` into their async_accept callbacks. If a callback
    // had already been dispatched onto an io_context worker queue but
    // hadn't run yet, freeing the server out from under it would UAF.
    // (S20 in the 2026-05-20 follow-up.)
    if (inspect_server_) {
        step("inspect_server stop", [this] { inspect_server_->stop(); });
    }
    // Timer cancels are non-throwing (util::cancel_timer_noexcept); a throwing
    // cancel here would otherwise skip every later phase.
    if (info_refresh_timer_) {
        util::cancel_timer_noexcept(*info_refresh_timer_);
    }
    if (failover_timer_) {
        util::cancel_timer_noexcept(*failover_timer_);
    }
    if (connectivity_log_timer_) {
        util::cancel_timer_noexcept(*connectivity_log_timer_);
    }
    {
        std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
        resume_tokens_.clear();
        if (resume_deadline_timer_) {
            util::cancel_timer_noexcept(*resume_deadline_timer_);
        }
    }
    if (socks5_listener_) {
        step("socks5_listener stop", [this] { socks5_listener_->stop(); });
    }
    for (auto& listener : listeners_) {
        step("listener stop", [&listener] { listener->stop(); });
    }
    {
        std::shared_ptr<StdioPipeBridge> pb;
        {
            std::lock_guard<std::mutex> lock(pipe_mutex_);
            pb = pipe_bridge_;
        }
        if (pb) {
            step("pipe_bridge stop", [&pb] { pb->stop(); });
        }
    }
    if (metrics_server_) {
        step("metrics_server stop", [this] { metrics_server_->stop(); });
    }

    // Phase 2: close all tunnels and stop the Tox thread. Both of these
    // post final work onto the io_context; we want it drained too.
    step("close_all", [this] { tunnel_mgr_->close_all(); });
    step("tox_adapter stop", [this] { tox_adapter_->stop(); });

    // Phase 3: stop the io_context and join all workers. After this
    // returns, no callback can possibly run any more.
    step("io_ctx stop", [this] { io_ctx_->stop(); });

    // Phase 4: NOW it's safe to free the sub-servers. Any pending
    // async_accept callback was drained in phase 3.
    inspect_server_.reset();
    info_refresh_timer_.reset();
    failover_timer_.reset();
    connectivity_log_timer_.reset();
    resume_deadline_timer_.reset();
    socks5_listener_.reset();
    {
        std::lock_guard<std::mutex> lock(pipe_mutex_);
        pipe_bridge_.reset();
    }
    metrics_server_.reset();

    running_ = false;
    stop_cv_.notify_all();

    util::Logger::info("TunnelClient stopped");

    // All phases ran; surface the first failure to an explicit stop() caller.
    // ~TunnelClient calls stop() inside a try/catch so a destructor never
    // propagates (issue #29).
    if (first_ex) {
        std::rethrow_exception(first_ex);
    }
}

bool TunnelClient::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void TunnelClient::wait_until_stopped() {
    {
        std::unique_lock<std::mutex> lock(stop_mutex_);
        stop_cv_.wait(
            lock, [this] { return !running_.load(std::memory_order_acquire) || stop_requested_; });
    }
    // If a callback asked us to stop (rather than an external stop() having
    // already torn everything down), perform the teardown here — on this
    // non-worker thread — so io_ctx_->stop()'s join never runs on one of the
    // pool's own workers (C-01). stop() is single-entry, so racing with the
    // signal-thread stop() is safe.
    if (running_.load(std::memory_order_acquire)) {
        stop();
    }
}

util::Expected<TunnelClient::ReloadResult, std::string> TunnelClient::reload(
    const Config& new_config) {
    if (auto check = util::check_reloadable(config_, new_config); !check) {
        return util::make_unexpected(check.error());
    }

    const auto& new_client = new_config.client.value();
    const auto diff = util::diff_forwards(forward_rules_, new_client.forwards);

    if (is_pipe_mode() && !diff.empty()) {
        return util::make_unexpected(std::string(
            "client is in pipe mode; forwards cannot be reloaded (restart to switch modes)"));
    }

    // H-02: the listeners_ / forward_rules_ vectors and TcpListener lifetimes
    // must only be touched from the io_context threads that run the accept
    // callbacks — the SIGHUP/reload thread parses, diffs, and validates above,
    // but the mutation itself is posted onto io_ctx_ and we block on the
    // future so the CLI still gets a synchronous result. (TcpListener's own
    // contract also requires operations from its io_context thread.)
    // Collected on the io thread, read back here after the apply completes.
    auto bind_failures = std::make_shared<std::string>();
    auto failed_count = std::make_shared<std::size_t>(0);
    auto apply = [this, new_config, diff, bind_failures, failed_count]() {
        if (!is_pipe_mode() && !diff.empty()) {
            for (const auto& removed : diff.removed) {
                for (std::size_t i = 0; i < forward_rules_.size();) {
                    if (forward_rules_[i] == removed) {
                        listeners_[i]->stop();
                        listeners_.erase(listeners_.begin() + static_cast<std::ptrdiff_t>(i));
                        forward_rules_.erase(forward_rules_.begin() +
                                             static_cast<std::ptrdiff_t>(i));
                        util::Logger::info("Stopped listener on {} -> {}:{}",
                                           removed.local_endpoint_label(), removed.remote_host,
                                           removed.remote_port);
                    } else {
                        ++i;
                    }
                }
            }

            // Bind a rule and, on success, register its listener + rule in the
            // live vectors. Returns the bind error message on failure. Shared
            // by the add loop and the rebind rollback below.
            auto bind_and_register = [this](const ForwardRule& rule) -> std::optional<std::string> {
                auto listener = std::make_shared<core::TcpListener>(
                    io_ctx_->get_io_context(), rule.effective_local_address(), rule.local_port);
                if (!listener->is_bound()) {
                    return listener->bind_error().message();
                }
                const auto captured = rule;
                listener->start_accept([this, captured](std::shared_ptr<core::TcpConnection> conn) {
                    on_tcp_connection_accepted(std::move(conn), captured);
                });
                listeners_.push_back(std::move(listener));
                forward_rules_.push_back(rule);
                return std::nullopt;
            };

            // Rollback pairing is one-to-one: each failed add restores at most
            // ONE removed counterpart, and each removed rule gets at most one
            // restore ATTEMPT (marked before binding, so a failed attempt is
            // not retried by a later failed add and warned about twice).
            std::vector<bool> restore_attempted(diff.removed.size(), false);

            for (const auto& added : diff.added) {
                const auto bind_err = bind_and_register(added);
                if (!bind_err.has_value()) {
                    if (auto advisory = forward_bind_advisory(added)) {
                        // Same rule on the reload path: a forward added by
                        // reload is just as exposed as one added at startup,
                        // and this is the only moment its operator is told.
                        util::Logger::warn("Reload: {}", *advisory);
                    }
                    util::Logger::info("Started listener on {} -> {}:{}",
                                       added.local_endpoint_label(), added.remote_host,
                                       added.remote_port);
                    continue;
                }

                // Reload is best-effort per forward: a busy port must not
                // take down a daemon that is happily serving the others.
                // The rule is NOT recorded, so a later reload retries it.
                ++*failed_count;
                util::Logger::error("Reload: not forwarding {} -> {}:{} ({})",
                                    added.local_endpoint_label(), added.remote_host,
                                    added.remote_port, *bind_err);
                std::string note = added.local_endpoint_label() + ": " + *bind_err;

                // A changed `local_address` arrives as a remove/add pair, and
                // the remove loop above has already torn down the old
                // listener — so without a rollback, a typo in the new address
                // silently takes the forward out of service (issue #26).
                // Restore the previous listener for the first unhandled
                // removed rule that is this add's rebind counterpart: same
                // local port, same target.
                for (std::size_t i = 0; i < diff.removed.size(); ++i) {
                    const auto& old_rule = diff.removed[i];
                    if (restore_attempted[i] || old_rule.local_port != added.local_port ||
                        old_rule.remote_host != added.remote_host ||
                        old_rule.remote_port != added.remote_port) {
                        continue;
                    }
                    restore_attempted[i] = true;
                    const auto restore_err = bind_and_register(old_rule);
                    if (!restore_err.has_value()) {
                        util::Logger::warn(
                            "Reload: restored previous listener on {} -> {}:{} (the new bind "
                            "failed; fix local_address and reload again)",
                            old_rule.local_endpoint_label(), old_rule.remote_host,
                            old_rule.remote_port);
                        note += "; previous listener on " + old_rule.local_endpoint_label() +
                                " restored";
                    } else {
                        util::Logger::error(
                            "Reload: previous listener on {} was stopped and could not be "
                            "restored ({}) — port {} is NOT serving",
                            old_rule.local_endpoint_label(), *restore_err, old_rule.local_port);
                        note += "; previous listener on " + old_rule.local_endpoint_label() +
                                " was stopped and could not be restored (" + *restore_err + ")";
                    }
                    break;
                }

                if (!bind_failures->empty()) {
                    *bind_failures += "; ";
                }
                *bind_failures += note;
            }
        }

        // Refresh provenance on the forwards that SURVIVED this reload.
        //
        // This deliberately runs OUTSIDE the `!diff.empty()` guard above.
        // `operator==` compares the *effective* bind address, so adding or
        // removing an explicit `127.0.0.1` yields an EMPTY diff — which is the
        // behaviour we want for the listener, since rebinding an unchanged
        // socket would drop live connections for nothing, but it also means the
        // block above never runs for exactly this case.
        //
        // Left alone, the surviving rule in `forward_rules_` keeps the OLD
        // explicit/absent flag while `config_` below takes the new one, and the
        // two then disagree about the same forward. That is not cosmetic:
        // whether the operator wrote the key by hand is precisely what decides
        // if this forward is entitled to a bind advisory, so a stale flag
        // either suppresses a warning they should see or repeats one they have
        // already answered.
        if (!is_pipe_mode() && new_config.client) {
            const auto& fwds = new_config.client->forwards;
            for (auto& live : forward_rules_) {
                const auto match =
                    // operator== already covers the remote host/port and the
                    // effective bind address; that IS the forward's identity.
                    std::find_if(fwds.begin(), fwds.end(), [&live](const ForwardRule& candidate) {
                        return candidate == live;
                    });
                if (match == fwds.end() ||
                    match->has_explicit_local_address() == live.has_explicit_local_address()) {
                    continue;
                }
                const bool became_implicit = !match->has_explicit_local_address();
                live.local_address = match->local_address;
                if (became_implicit) {
                    // explicit -> absent. The bind is unchanged, but the
                    // operator just deleted the line recording their intent, so
                    // this is the moment to tell them what it now means.
                    if (auto advisory = forward_bind_advisory(live)) {
                        util::Logger::warn("Reload: {}", *advisory);
                    }
                }
            }
        }

        if (config_.logging.level != new_config.logging.level) {
            util::Logger::set_level(new_config.logging.level);
        }
        config_ = new_config;
    };

    if (io_ctx_ && running_.load(std::memory_order_acquire)) {
        std::promise<void> done;
        auto fut = done.get_future();
        asio::post(io_ctx_->get_io_context(), [&apply, &done]() {
            // A throwing apply() must fulfil the promise (issue #29): otherwise
            // fut.get()/wait() below blocks the reload caller forever. Forward
            // the exception so it surfaces to that caller instead.
            try {
                apply();
                done.set_value();
            } catch (...) {
                done.set_exception(std::current_exception());
            }
        });
        fut.get();  // Propagates any exception the posted apply() forwarded.
    } else {
        // Not running yet (no io threads to serialize against): apply inline.
        apply();
    }

    util::Logger::info("config reloaded (forwards: +{} -{})", diff.added.size() - *failed_count,
                       diff.removed.size());
    // Bind failures are warnings, not a rejection: the rest of the reload has
    // already been applied and the daemon is still serving. Returning an error
    // here would contradict the "on error nothing was applied" contract.
    return ReloadResult{*bind_failures};
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
        // S15 / 2026-05-20 follow-up: capture the endpoint's tox_id while
        // holding endpoints_mutex_, so a concurrent switch_active_endpoint
        // cannot misattribute the connection event to the new server.
        std::string sender_tox_id;
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
            sender_tox_id = ep.tox_id_hex;
            is_active = (hit_index == active_index_);
            if (is_active) {
                server_online_.store(connected, std::memory_order_release);
                util::MetricsRegistry::instance().set_friends_online(connected ? 1 : 0);
                // The active session ended (disconnect) or a new one began
                // (reconnect); either way ids may be reused, so invalidate any
                // outstanding RESUME_ACK from the prior session (issue #28).
                ++resume_session_generation_;
            }
        }

        if (is_active) {
            if (connected) {
                util::Logger::info("Server friend {} is now online", friend_number);
                record_server_connection(sender_tox_id, friend_number);
                send_info_request();
                // M-02: (re)start keepalive — enable_keepalive resets the
                // liveness baseline + dead latch, so a reconnect starts fresh.
                if (config_.tunnel.keepalive_enabled() && tunnel_mgr_) {
                    tunnel_mgr_->enable_keepalive(config_.tunnel.keepalive_interval_seconds, 0);
                }
                // H-07: ask the server to reattach any tunnels that survived a
                // brief disconnect (no-op on the first connect / when disabled).
                if (config_.tunnel.resume.enabled && running_) {
                    io_ctx_->post([this] { send_resume_requests(); });
                }
                if (is_pipe_mode() && running_) {
                    io_ctx_->post([this] { start_pipe_mode(); });
                }
            } else {
                util::Logger::warn("Server friend {} went offline", friend_number);
                info_request_sent_.store(false);
                if (tunnel_mgr_) {
                    tunnel_mgr_->disable_keepalive();
                    // Drop any control frames the manager parked for this
                    // peer. The drain timer would otherwise keep retrying
                    // PermanentFail-class sends until the queue cap forces
                    // a drop (or, on reconnect, deliver a stale OPEN_ACK
                    // for a tunnel the peer no longer remembers).
                    tunnel_mgr_->clear_pending_outbound();
                }
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
    tox_adapter_->set_on_lossless_packet(
        [this](uint32_t friend_number, const uint8_t* data, std::size_t length) {
            // S15 / 2026-05-20 follow-up: filter + capture sender identity
            // atomically under endpoints_mutex_. A simple "is this the
            // current active friend_number" check, followed by a later
            // server_tox_id_snapshot(), would race with switch_active_endpoint
            // and misattribute the inbound INFO_REPLY to the freshly-promoted
            // server's record.
            std::string sender_tox_id;
            std::uint64_t captured_generation = 0;
            {
                std::lock_guard<std::mutex> lock(endpoints_mutex_);
                if (active_index_ >= endpoints_.size() ||
                    endpoints_[active_index_].friend_number != friend_number) {
                    // Stale packet from a freshly-demoted fallback, or an
                    // unexpected friend. Either way, ignore.
                    util::Logger::debug(
                        "Received lossless packet from non-active friend {} (active idx {})",
                        friend_number, active_index_);
                    return;
                }
                sender_tox_id = endpoints_[active_index_].tox_id_hex;
                // Capture the resume-session generation atomically with the
                // active-friend check (issue #28): a RESUME_ACK dispatched from
                // the strand after a later switch/reconnect bump is stale.
                captured_generation = resume_session_generation_;
            }
            if (length < 2) {
                util::Logger::warn("Lossless packet too short ({} bytes)", length);
                return;
            }

            std::vector<uint8_t> packet(data, data + length);
            asio::post(*inbound_strand_, [this, packet = std::move(packet),
                                          sender_tox_id = std::move(sender_tox_id),
                                          captured_generation, friend_number]() {
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
                    record_server_info(sender_tox_id, frame_result.value().as_info_reply_yaml());
                    return;
                }

                // H-07: TUNNEL_RESUME_ACK is a per-friend control frame (not
                // routed to a tunnel by the manager). Intercept it here.
                if (frame_result.value().type() == tunnel::FrameType::TUNNEL_RESUME_ACK) {
                    if (auto ack = frame_result.value().as_tunnel_resume_ack()) {
                        handle_resume_ack(*ack, captured_generation);
                    }
                    return;
                }

                // Active-friend gate for the generic routing path (issue #30),
                // evaluated on the inbound strand against strand_route_friend_.
                // A packet admitted from the OLD active friend before a failover
                // switch could otherwise reach here after the manager handler
                // was repinned to the new friend, and route_frame() would reply
                // (PONG for a PING, an unknown-tunnel TUNNEL_ERROR) via the new
                // handler — hitting the NEW server. The switch repins the
                // handler AND strand_route_friend_ in one strand task, so this
                // gate and that repin are serialized by the strand: a frame
                // that passes replies through the handler for the SAME friend.
                //
                // No lock is held across route_frame() (which can block on the
                // Tox thread for the reply send), so there is no Tox-thread /
                // app-lock inversion. Keyed on the FRIEND, not the resume
                // generation (which also bumps on a same-friend reconnect), so
                // a connection blip does not drop legitimately-resumed traffic.
                if (friend_number != strand_route_friend_) {
                    util::Logger::debug(
                        "Dropping inbound frame from friend {}: not the strand route friend {}",
                        friend_number, strand_route_friend_);
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
    // Route-pinned to the active friend (issue #30). Capturing the friend
    // number by value — rather than reading server_friend_number_ per send —
    // means a pending-queue drain that snapshotted this handler keeps sending
    // to the friend it was queued for even if a failover switch reinstalls the
    // handler for the new friend mid-drain. switch_active_endpoint reinstalls
    // it (after clearing the queue) so new-session frames target the new
    // server. Returns the typed outcome so the manager can distinguish
    // transient backpressure (queue + retry) from a permanent failure.
    // Safe to set directly here: the io_context / inbound strand is not
    // running yet, so there is no concurrent strand access (issue #30).
    strand_route_friend_ = server_friend_number_.load(std::memory_order_acquire);
    install_manager_send_handler(strand_route_friend_);

    // Tunnel closed callback
    tunnel_mgr_->set_on_tunnel_closed(
        [](uint16_t tunnel_id) { util::Logger::debug("Tunnel {} closed", tunnel_id); });

    // M-02: when the active server stops answering keepalive PINGs (its
    // toxcore link still looks alive but the app is wedged), mark it offline
    // and drop its tunnels so the failover state machine promotes a fallback.
    if (config_.tunnel.keepalive_enabled()) {
        tunnel_mgr_->set_on_peer_dead([this]() {
            io_ctx_->post([this]() {
                util::Logger::warn(
                    "Active server unresponsive (keepalive); marking offline and failing over");
                {
                    std::lock_guard<std::mutex> lock(endpoints_mutex_);
                    if (active_index_ < endpoints_.size() && endpoints_[active_index_].online) {
                        endpoints_[active_index_].online = false;
                        endpoints_[active_index_].offline_since = std::chrono::steady_clock::now();
                    }
                    server_online_.store(false, std::memory_order_release);
                    util::MetricsRegistry::instance().set_friends_online(0);
                }
                if (tunnel_mgr_) {
                    tunnel_mgr_->close_all();
                }
                info_request_sent_.store(false);
            });
        });
    }
}

util::Expected<void, std::string> TunnelClient::create_listeners(
    const std::vector<ForwardRule>& forwards) {
    forward_rules_ = forwards;
    listeners_.reserve(forwards.size());

    std::string failures;
    std::vector<std::string> advisories;
    for (const auto& rule : forwards) {
        auto listener = std::make_shared<core::TcpListener>(
            io_ctx_->get_io_context(), rule.effective_local_address(), rule.local_port);
        if (!listener->is_bound()) {
            if (!failures.empty()) {
                failures += "; ";
            }
            // address:port, not port alone: with local_address configurable,
            // "port 2222 is busy" no longer identifies which forward failed.
            failures += rule.local_endpoint_label() + ": " + listener->bind_error().message();
        } else if (auto advisory = forward_bind_advisory(rule)) {
            // COLLECTED, not emitted yet. Startup is all-or-nothing: if a later
            // forward fails to bind, every listener is torn down and the daemon
            // exits, so a notice already printed would claim a forward is
            // listening when in fact nothing is listening at all. Held until
            // every bind has succeeded.
            advisories.push_back(std::move(*advisory));
        }
        listeners_.push_back(std::move(listener));
    }
    if (!failures.empty()) {
        // Startup-time bind failures are fatal: a client whose forward port is
        // taken would look healthy while forwarding nothing. (Another
        // toxtunnel already running on that port is the usual cause.)
        listeners_.clear();
        forward_rules_.clear();
        return util::make_unexpected("cannot listen on configured forward port(s): " + failures);
    }
    // Every forward is bound, so these listeners really are up and really are
    // exposed. Only now is the warning true.
    for (const auto& advisory : advisories) {
        util::Logger::warn("{}", advisory);
    }
    return {};
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
    {
        std::lock_guard<std::mutex> lock(pipe_mutex_);
        pipe_bridge_ = std::make_shared<StdioPipeBridge>(STDIN_FILENO, STDOUT_FILENO);
    }
#endif

    auto allocated_id = tunnel_mgr_->allocate_tunnel_id();
    if (!allocated_id) {
        util::Logger::error("No available tunnel IDs for pipe mode");
        {
            std::lock_guard<std::mutex> lock(pipe_mutex_);
            pipe_bridge_.reset();
        }
        pipe_mode_started_ = false;
        request_stop();
        return;
    }
    const uint16_t tunnel_id = *allocated_id;
    auto tunnel =
        std::make_shared<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);
    const uint32_t tunnel_friend_number = server_friend_number_.load(std::memory_order_acquire);

    // Shared with the server and the other two client tunnel paths; see
    // detail::make_tunnel_senders() for the manager accounting and the outbound
    // FIFO barrier it applies. Capture `tunnel_mgr_` by shared_ptr value — NOT
    // `tunnel_mgr_.get()` — so the callbacks can safely run after a
    // request_stop() that has begun tearing down TunnelClient. The raw-pointer
    // form was H-S-2/H-S-4 in the fix-storm review (UAF), and the comment on
    // `tunnel_mgr_` in tunnel_client.hpp explicitly warns against it.
    auto manager_ref = tunnel_mgr_;
    auto senders = detail::make_tunnel_senders(
        [this](std::uint32_t friend_num, const std::uint8_t* data, std::size_t length) {
            return tox_adapter_->send_lossless_packet_typed(friend_num, data, length);
        },
        manager_ref, tunnel_friend_number);
    tunnel->set_on_send_to_tox(std::move(senders.span));
    tunnel->set_on_send_to_tox_owned(std::move(senders.owned));

    const std::weak_ptr<tunnel::TunnelImpl> weak_tunnel = tunnel;

    // H-04: snapshot pipe_bridge_ under pipe_mutex_ before each use, so a
    // concurrent stop()/on_close reset can't free it mid-call. Stdout is
    // treated as always-accepting (the OS buffers), so we report true.
    tunnel->set_on_data_for_tcp([this](std::span<const uint8_t> data) -> bool {
        std::shared_ptr<StdioPipeBridge> pb;
        {
            std::lock_guard<std::mutex> lock(pipe_mutex_);
            pb = pipe_bridge_;
        }
        if (pb) {
            pb->write_output(data);
        }
        return true;
    });

    tunnel->set_on_state_change([this, weak_tunnel, tunnel_id](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected) {
            auto locked_tunnel = weak_tunnel.lock();
            if (!locked_tunnel) {
                return;
            }
            std::shared_ptr<StdioPipeBridge> pb;
            {
                std::lock_guard<std::mutex> lock(pipe_mutex_);
                pb = pipe_bridge_;
            }
            if (!pb) {
                return;
            }
            auto start_result = pb->start(
                [weak_tunnel](std::span<const uint8_t> data) {
                    if (auto tunnel = weak_tunnel.lock()) {
                        tunnel->on_tcp_data_received(data.data(), data.size());
                    }
                },
                [weak_tunnel]() {
                    if (auto tunnel = weak_tunnel.lock()) {
                        tunnel->close();
                    }
                });
            if (!start_result) {
                util::Logger::error("Failed to start stdio pipe bridge for tunnel {}: {}",
                                    tunnel_id, start_result.error());
                locked_tunnel->close();
                request_stop();
            }
        } else if (new_state == tunnel::Tunnel::State::Error) {
            std::shared_ptr<StdioPipeBridge> pb;
            {
                std::lock_guard<std::mutex> lock(pipe_mutex_);
                pb = pipe_bridge_;
            }
            if (pb) {
                pb->stop();
            }
            request_stop();
        }
    });

    // H-S-2 (2026-05-20 fix-storm review): capture shared_ptr to the
    // manager, not a raw pointer. request_stop() can race the on_close
    // lambda; without this the lambda could deref a destroyed manager.
    auto mgr = tunnel_mgr_;
    // weak, not shared: this callback is owned by the tunnel it names, so a
    // strong capture would be a cycle. It exists so the removal below can say
    // WHICH tunnel it means — ids are recycled per friend.
    const std::weak_ptr<tunnel::TunnelImpl> weak_self = tunnel;
    tunnel->set_on_close([this, mgr, weak_self, tunnel_id]() {
        // Move the bridge out under the lock, then stop()/destroy the local
        // copy outside it (stop() may join the read thread).
        std::shared_ptr<StdioPipeBridge> pb;
        {
            std::lock_guard<std::mutex> lock(pipe_mutex_);
            pb = std::move(pipe_bridge_);
        }
        if (pb) {
            pb->stop();
        }
        pipe_mode_started_ = false;
        if (auto self = weak_self.lock()) {
            (void)mgr->remove_tunnel_if(tunnel_id, self.get());
        }
        request_stop();
    });

    tunnel_mgr_->add_tunnel(tunnel_id, tunnel);

    if (!tunnel->open(target.remote_host, target.remote_port)) {
        util::Logger::error("Failed to open pipe-mode tunnel {} to {}:{}", tunnel_id,
                            target.remote_host, target.remote_port);
        tunnel_mgr_->remove_tunnel(tunnel_id);
        {
            std::lock_guard<std::mutex> lock(pipe_mutex_);
            pipe_bridge_.reset();
        }
        pipe_mode_started_ = false;
        request_stop();
        return;
    }

    util::Logger::info("Pipe mode opening tunnel {} -> {}:{}", tunnel_id, target.remote_host,
                       target.remote_port);
}

void TunnelClient::request_stop() {
    // Called from Tox-iterate and io-worker callbacks (pipe-mode errors,
    // server-offline, etc.). We must NOT run stop() here: stop() joins the
    // io_context worker pool, and these callbacks already run on a worker (or
    // the Tox thread), so a direct/posted stop() would self-join and deadlock
    // (C-01). Instead, signal the thread blocked in wait_until_stopped() — a
    // non-worker thread — to perform the teardown.
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(stop_mutex_);
        stop_requested_ = true;
    }
    stop_cv_.notify_all();
}

void TunnelClient::install_manager_send_handler(std::uint32_t friend_number) {
    if (!tunnel_mgr_) {
        return;
    }
    tunnel_mgr_->set_send_handler(
        [this, friend_number](const std::vector<uint8_t>& frame_data) -> tunnel::SendOutcome {
            std::vector<uint8_t> packet;
            packet.reserve(1 + frame_data.size());
            packet.push_back(tunnel::kLosslessPacketByte);
            packet.insert(packet.end(), frame_data.begin(), frame_data.end());

            // friend_number is captured by value (issue #30): a drain that
            // snapshotted this handler sends to the friend it was queued for,
            // not whatever endpoint is now active.
            const auto outcome = tox_adapter_->send_lossless_packet_typed(
                friend_number, packet.data(), packet.size());
            switch (outcome) {
                case tox::ToxAdapter::LosslessSendOutcome::Sent:
                    return tunnel::SendOutcome::Sent;
                case tox::ToxAdapter::LosslessSendOutcome::SendqFull:
                    return tunnel::SendOutcome::SendqFull;
                case tox::ToxAdapter::LosslessSendOutcome::PermanentFail:
                    return tunnel::SendOutcome::PermanentFail;
            }
            return tunnel::SendOutcome::PermanentFail;
        });
}

void TunnelClient::send_resume_requests() {
    if (!tunnel_mgr_ || !config_.tunnel.resume.enabled) {
        return;
    }
    // Snapshot the session identity (issue #28): the friend to send to AND the
    // generation the outstanding tokens are stamped with, atomically, so a
    // switch cannot interleave between reading the friend and stamping tokens.
    uint32_t fn = 0;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        if (active_index_ >= endpoints_.size()) {
            return;
        }
        fn = endpoints_[active_index_].friend_number;
        generation = resume_session_generation_;
    }
    // Fresh session: drop stale tokens from a prior generation before recording
    // this round's.
    {
        std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
        resume_tokens_.clear();
    }
    // Snapshot ids, then look up each tunnel without holding the manager lock
    // across the (cross-thread) send.
    for (uint16_t id : tunnel_mgr_->get_tunnel_ids()) {
        auto impl = std::dynamic_pointer_cast<tunnel::TunnelImpl>(tunnel_mgr_->get_tunnel(id));
        if (!impl || impl->state() != tunnel::Tunnel::State::Connected) {
            continue;
        }
        // Issue #24 slice 3: a tunnel whose outbound side is Abort-sealed (e.g.
        // driven terminal by a throwing DATA callback) can read Connected for
        // a transient window but will refuse all further outbound admission —
        // resuming it would hand the peer a tunnel that can never send. Skip
        // it and force-settle it locally instead.
        if (impl->outbound_aborted()) {
            impl->force_close();
            continue;
        }
        tunnel::TunnelResumeRequestPayload req;
        req.prior_tunnel_id = id;
        req.last_local_recv_offset = impl->bytes_received();
        // Emitted (on-the-wire), NOT accepted-from-TCP: bytes still buffered in
        // the coalescer haven't reached the peer, so reporting bytes_sent() here
        // would look like a gap and falsely close a recoverable tunnel.
        req.last_local_send_offset = impl->bytes_emitted();
        req.host = impl->target_host();
        req.target_port = impl->target_port();

        // Record the outstanding-resume token BEFORE sending, so a fast ACK
        // cannot arrive before the token exists (issue #28). One token per
        // tunnel object per session, stamped with a response deadline so a
        // lost ACK force-settles the tunnel rather than lingering.
        {
            std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
            resume_tokens_[id] = ResumeToken{
                generation, impl, std::chrono::steady_clock::now() + kResumeResponseDeadline};
        }

        auto frame = tunnel::ProtocolFrame::make_tunnel_resume_request(req);
        auto wire = frame.serialize();
        std::vector<uint8_t> packet;
        packet.reserve(1 + wire.size());
        packet.push_back(tunnel::kLosslessPacketByte);
        packet.insert(packet.end(), wire.begin(), wire.end());
        (void)tox_adapter_->send_lossless_packet(fn, packet.data(), packet.size());
        util::MetricsRegistry::instance().inc_resume_attempts();
        util::Logger::info("Sent RESUME_REQUEST for tunnel {} (recv={} send={})", id,
                           req.last_local_recv_offset, req.last_local_send_offset);
    }

    // Arm the response-deadline timer for the earliest outstanding token.
    {
        std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
        arm_resume_deadline_timer_locked();
    }
}

void TunnelClient::arm_resume_deadline_timer_locked() {
    // Caller holds resume_tokens_mutex_.
    if (!io_ctx_) {
        return;
    }
    if (resume_tokens_.empty()) {
        if (resume_deadline_timer_) {
            util::cancel_timer_noexcept(*resume_deadline_timer_);
        }
        return;
    }
    auto earliest = std::chrono::steady_clock::time_point::max();
    for (const auto& [id, tok] : resume_tokens_) {
        earliest = std::min(earliest, tok.deadline);
    }
    if (!resume_deadline_timer_) {
        resume_deadline_timer_ = std::make_unique<asio::steady_timer>(io_ctx_->get_io_context());
    }
    resume_deadline_timer_->expires_at(earliest);
    resume_deadline_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec) {
            return;  // Cancelled / rearmed.
        }
        on_resume_deadline();
    });
}

void TunnelClient::on_resume_deadline() {
    const auto now = std::chrono::steady_clock::now();
    // Collect expired tokens under the lock; act on them (force-settle) with
    // the lock released, since close() re-enters the manager. The generation is
    // checked per tunnel afterwards, never nesting endpoints_mutex_ inside
    // resume_tokens_mutex_.
    std::vector<std::pair<std::weak_ptr<tunnel::TunnelImpl>, std::uint64_t>> expired;
    {
        std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
        for (auto it = resume_tokens_.begin(); it != resume_tokens_.end();) {
            if (it->second.deadline <= now) {
                expired.emplace_back(it->second.tunnel, it->second.generation);
                it = resume_tokens_.erase(it);
            } else {
                ++it;
            }
        }
        arm_resume_deadline_timer_locked();
    }

    const std::uint64_t current_generation = [this] {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        return resume_session_generation_;
    }();

    for (auto& [weak, gen] : expired) {
        if (gen != current_generation) {
            // A switch/reconnect already invalidated this session; its own
            // teardown owns the tunnel. Nothing to force-settle here.
            continue;
        }
        auto impl = weak.lock();
        if (!impl) {
            continue;  // Already gone.
        }
        util::MetricsRegistry::instance().inc_resume_failures();
        util::Logger::warn("Tunnel {} RESUME_ACK not received before deadline; closing",
                           impl->tunnel_id());
        impl->close();
    }
}

void TunnelClient::handle_resume_ack(const tunnel::TunnelResumeAckPayload& ack,
                                     std::uint64_t captured_generation) {
    // Session-generation gate (issue #28): a switch/reconnect that bumped the
    // generation while this ACK sat in the strand makes it stale — the id it
    // names may have been reused by a newer session. Drop it.
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        if (captured_generation != resume_session_generation_) {
            util::Logger::debug(
                "RESUME_ACK for tunnel {} dropped: session generation changed ({} != {})",
                ack.new_tunnel_id, captured_generation, resume_session_generation_);
            return;
        }
    }

    auto impl = std::dynamic_pointer_cast<tunnel::TunnelImpl>(
        tunnel_mgr_ ? tunnel_mgr_->get_tunnel(ack.new_tunnel_id) : nullptr);
    if (!impl) {
        util::Logger::debug("RESUME_ACK for unknown/closed tunnel {}", ack.new_tunnel_id);
        return;
    }

    // Object-identity gate (issue #28): consume the outstanding token for this
    // id and require it to belong to this generation AND resolve to the very
    // tunnel object we are about to act on. This catches a same-generation id
    // reuse the generation check alone would miss, and an ACK for which we sent
    // no request.
    {
        std::lock_guard<std::mutex> lock(resume_tokens_mutex_);
        auto it = resume_tokens_.find(ack.new_tunnel_id);
        if (it == resume_tokens_.end()) {
            util::Logger::debug("RESUME_ACK for tunnel {} dropped: no outstanding request",
                                ack.new_tunnel_id);
            return;
        }
        const bool matches =
            it->second.generation == captured_generation && it->second.tunnel.lock() == impl;
        resume_tokens_.erase(it);  // Consume regardless: one ACK per request.
        // The consumed token may have been the earliest deadline; rearm.
        arm_resume_deadline_timer_locked();
        if (!matches) {
            util::Logger::debug(
                "RESUME_ACK for tunnel {} dropped: token/object mismatch (stale or recycled id)",
                ack.new_tunnel_id);
            return;
        }
    }

    if (ack.status == tunnel::TunnelResumeStatus::Ok) {
        // Issue #24 slice 3: revalidate the seal AFTER the exchange. An Abort
        // that raced the request/ACK (a throwing DATA callback drove the
        // tunnel terminal while the ACK was in flight) means this "resumed"
        // tunnel can never send again — force-settle it instead of reporting
        // success.
        if (impl->outbound_aborted()) {
            util::MetricsRegistry::instance().inc_resume_failures();
            util::Logger::warn(
                "Tunnel {} RESUME_ACK Ok but the tunnel was aborted mid-exchange; closing",
                ack.new_tunnel_id);
            impl->force_close();
            return;
        }
        util::MetricsRegistry::instance().inc_resume_successes();
        util::Logger::info("Tunnel {} resumed (server recv={} send={})", ack.new_tunnel_id,
                           ack.server_recv_offset, ack.server_send_offset);
        // The tunnel kept its Connected state and TCP connection; nothing more
        // to do — buffered bytes flush via the coalesce retry timer.
    } else {
        util::MetricsRegistry::instance().inc_resume_failures();
        util::Logger::warn("Tunnel {} resume declined (status {}); closing", ack.new_tunnel_id,
                           static_cast<int>(ack.status));
        impl->close();
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

    // Allocate a tunnel ID and create the tunnel. C-07: handle exhaustion
    // (nullopt) instead of proceeding with the control-plane id 0.
    auto allocated_id = tunnel_mgr_->allocate_tunnel_id();
    if (!allocated_id) {
        util::Logger::error("No available tunnel IDs; closing connection on port {}",
                            rule.local_port);
        conn->close();
        return;
    }
    const uint16_t tunnel_id = *allocated_id;
    util::Logger::debug("New TCP connection on port {}, creating tunnel {} -> {}:{}",
                        rule.local_port, tunnel_id, rule.remote_host, rule.remote_port);

    auto tunnel =
        std::make_shared<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);
    const uint32_t tunnel_friend_number = server_friend_number_.load(std::memory_order_acquire);

    // Set the TCP connection on the tunnel
    tunnel->set_tcp_connection(conn);

    // Wire callback: when TunnelImpl wants to send data to Tox, prepend the
    // lossless packet prefix and forward to ToxAdapter. The frame is already
    // serialized — no need to round-trip through deserialize / re-serialize.
    // Built by detail::make_tunnel_senders() rather than the
    // make_fixed_friend_lossless_* helpers, so the manager-level bytes_sent /
    // frames_sent counters are maintained and the outbound FIFO barrier is
    // applied. Without those record_* calls, `inspect status --json` shows
    // bytes_out=0 on the client even when data flows (the per-tunnel TunnelImpl
    // counter still increments — but that tracks bytes offered to the
    // coalescer, not bytes successfully sent).
    //
    // Capture by shared_ptr value — `tunnel_mgr_.get()` is the UAF pattern
    // called out in tunnel_client.hpp:215-223 (H-S-2/H-S-4).
    auto manager_ref = tunnel_mgr_;
    auto senders = detail::make_tunnel_senders(
        [this](std::uint32_t friend_num, const std::uint8_t* data, std::size_t length) {
            return tox_adapter_->send_lossless_packet_typed(friend_num, data, length);
        },
        manager_ref, tunnel_friend_number);
    tunnel->set_on_send_to_tox(std::move(senders.span));
    tunnel->set_on_send_to_tox_owned(std::move(senders.owned));

    // Wire callback: when data arrives from Tox for this tunnel, write to TCP.
    // Prefer the zero-copy owned-buffer route so the payload buffer
    // allocated during `ProtocolFrame::deserialize` is handed straight to
    // the TCP write queue without an intermediate `vector<uint8_t>` copy.
    tunnel->set_on_data_for_tcp_owned(
        [conn](core::OwnedBufferView buf) -> bool { return conn->write(std::move(buf)); });
    tunnel->set_on_data_for_tcp([conn](std::span<const uint8_t> data) -> bool {
        return conn->write(data.data(), data.size());
    });

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

    // Wire tunnel close callback. H-S-4 (2026-05-20 fix-storm review):
    // capture shared_ptr — see the matching note on the pipe-mode
    // on_close above.
    auto mgr = tunnel_mgr_;
    // See the pipe-mode note: weak so the callback does not own its own tunnel,
    // and identity-checked so a recycled id is not torn down by mistake.
    const std::weak_ptr<tunnel::TunnelImpl> weak_self = tunnel;
    tunnel->set_on_close([mgr, weak_self, tunnel_id]() {
        util::Logger::debug("Tunnel {} on_close, removing from manager", tunnel_id);
        if (auto self = weak_self.lock()) {
            (void)mgr->remove_tunnel_if(tunnel_id, self.get());
        }
    });

    const std::weak_ptr<tunnel::TunnelImpl> weak_tunnel = tunnel;
    // Wire TCP data + disconnect callbacks. Capturing the tunnel shared_ptr by
    // weak_ptr breaks the TcpConnection<->TunnelImpl ownership cycle while
    // still letting in-flight callbacks lock the tunnel if it is alive.
    conn->set_on_data([weak_tunnel](const uint8_t* data, std::size_t length) {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_data_received(data, length);
        }
    });
    conn->set_on_read_eof([weak_tunnel]() {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_read_eof();
        }
    });
    conn->set_on_disconnect([weak_tunnel](const std::error_code& /*ec*/) {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->close();
        }
    });
    // C-03: flush a deferred ACK once the local TCP write queue drains.
    conn->set_on_writable([weak_tunnel]() -> bool {
        if (auto tunnel = weak_tunnel.lock()) {
            return tunnel->notify_tcp_writable();
        }
        return true;  // tunnel gone — nothing to flush
    });

    // C-04: register the tunnel with the manager BEFORE sending TUNNEL_OPEN, so
    // a fast ACK/ERROR from the server routes to a known tunnel instead of being
    // dropped as "unknown tunnel". Roll back (release the id) if the manager is
    // at capacity (H-05).
    if (!tunnel_mgr_->add_tunnel(tunnel_id, tunnel)) {
        util::Logger::error("Tunnel manager at capacity; dropping connection on port {}",
                            rule.local_port);
        tunnel_mgr_->release_tunnel_id(tunnel_id);
        conn->close();
        return;
    }

    // Initiate tunnel opening: sends TUNNEL_OPEN frame to server.
    if (!tunnel->open(rule.remote_host, rule.remote_port)) {
        util::Logger::error("Failed to open tunnel {} to {}:{}", tunnel_id, rule.remote_host,
                            rule.remote_port);
        // remove_tunnel() closes the tunnel and releases the id.
        tunnel_mgr_->remove_tunnel(tunnel_id);
        conn->close();
        return;
    }

    util::Logger::debug("Tunnel {} created and TUNNEL_OPEN sent to {}:{}", tunnel_id,
                        rule.remote_host, rule.remote_port);
}

void TunnelClient::open_socks5_tunnel(std::shared_ptr<core::TcpConnection> conn, std::string host,
                                      uint16_t port, std::vector<uint8_t> initial_payload,
                                      std::function<void(TunnelOpenOutcome)> on_tunnel_state) {
    if (!server_online_) {
        util::Logger::warn("SOCKS5 destination {}:{} requested but server is offline", host, port);
        on_tunnel_state(TunnelOpenOutcome::Failed);
        conn->close();
        return;
    }

    auto allocated_id = tunnel_mgr_->allocate_tunnel_id();
    if (!allocated_id) {
        util::Logger::error("No available tunnel IDs for SOCKS5 destination {}:{}", host, port);
        on_tunnel_state(TunnelOpenOutcome::Failed);
        conn->close();
        return;
    }
    const uint16_t tunnel_id = *allocated_id;
    util::Logger::debug("SOCKS5 destination {}:{} -> tunnel {}", host, port, tunnel_id);

    auto tunnel =
        std::make_shared<tunnel::TunnelImpl>(io_ctx_->get_io_context(), tunnel_id,
                                             server_friend_number_.load(std::memory_order_acquire));
    tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                               config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*tunnel);
    tunnel->set_tcp_connection(conn);
    const uint32_t tunnel_friend_number = server_friend_number_.load(std::memory_order_acquire);

    // Capture by shared_ptr value — same UAF concern as the other two sites
    // (see comment on `tunnel_mgr_` in tunnel_client.hpp:215-223).
    auto manager_ref = tunnel_mgr_;
    auto senders = detail::make_tunnel_senders(
        [this](std::uint32_t friend_num, const std::uint8_t* data, std::size_t length) {
            return tox_adapter_->send_lossless_packet_typed(friend_num, data, length);
        },
        manager_ref, tunnel_friend_number);
    tunnel->set_on_send_to_tox(std::move(senders.span));
    tunnel->set_on_send_to_tox_owned(std::move(senders.owned));

    tunnel->set_on_data_for_tcp([conn](std::span<const uint8_t> data) -> bool {
        return conn->write(data.data(), data.size());
    });

    // The reply gate latch ensures the listener's reply callback is invoked
    // exactly once across all possible state transitions of this tunnel.
    auto reply_sent = std::make_shared<std::atomic<bool>>(false);
    auto open_counted = std::make_shared<std::atomic<bool>>(false);
    auto active_dec_latch = std::make_shared<std::atomic<bool>>(false);
    auto reply_cb =
        std::make_shared<std::function<void(TunnelOpenOutcome)>>(std::move(on_tunnel_state));
    // Wrap initial_payload in a shared_ptr so the state-change lambda can drain
    // it exactly once. Bytes that arrived past the SOCKS/CONNECT handshake go
    // upstream BEFORE we start_read so the tunnel sees them in original order.
    auto initial_payload_holder =
        std::make_shared<std::vector<uint8_t>>(std::move(initial_payload));
    const std::weak_ptr<tunnel::TunnelImpl> weak_tunnel = tunnel;
    tunnel->set_on_state_change([conn, tunnel_id, weak_tunnel, reply_sent, open_counted,
                                 active_dec_latch, reply_cb,
                                 initial_payload_holder](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Connected) {
            auto locked_tunnel = weak_tunnel.lock();
            if (!locked_tunnel) {
                return;
            }
            if (!reply_sent->exchange(true)) {
                (*reply_cb)(TunnelOpenOutcome::Connected);
            }
            if (!initial_payload_holder->empty()) {
                locked_tunnel->on_tcp_data_received(initial_payload_holder->data(),
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
                // Translate the peer's TUNNEL_ERROR reason so the listener can
                // answer 0x02 ("not allowed by ruleset") for a policy denial
                // rather than a generic host-unreachable. The classification
                // itself lives in tunnel_open_outcome_for() so that it is pure,
                // has a single definition, and can be tested across the whole
                // old-server / new-server matrix without a live tunnel.
                auto outcome = TunnelOpenOutcome::Failed;
                if (auto locked = weak_tunnel.lock()) {
                    outcome = tunnel_open_outcome_for(locked->last_error_code(),
                                                      locked->last_error_description());
                }
                (*reply_cb)(outcome);
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

    auto mgr = tunnel_mgr_;
    // See the pipe-mode note: weak, and identity-checked.
    const std::weak_ptr<tunnel::TunnelImpl> weak_self = tunnel;
    tunnel->set_on_close([mgr, weak_self, tunnel_id]() {
        util::Logger::debug("SOCKS5 tunnel {} on_close, removing from manager", tunnel_id);
        if (auto self = weak_self.lock()) {
            (void)mgr->remove_tunnel_if(tunnel_id, self.get());
        }
    });
    conn->set_on_data([weak_tunnel](const uint8_t* data, std::size_t length) {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_data_received(data, length);
        }
    });
    conn->set_on_read_eof([weak_tunnel]() {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_read_eof();
        }
    });
    conn->set_on_disconnect([weak_tunnel](const std::error_code& /*ec*/) {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->close();
        }
    });
    conn->set_on_writable([weak_tunnel]() -> bool {
        if (auto tunnel = weak_tunnel.lock()) {
            return tunnel->notify_tcp_writable();
        }
        return true;  // tunnel gone — nothing to flush
    });

    // C-04: register before opening (see on_tcp_connection_accepted).
    if (!tunnel_mgr_->add_tunnel(tunnel_id, tunnel)) {
        util::Logger::error("Tunnel manager at capacity; rejecting SOCKS5 {}:{}", host, port);
        tunnel_mgr_->release_tunnel_id(tunnel_id);
        if (!reply_sent->exchange(true)) {
            (*reply_cb)(TunnelOpenOutcome::Failed);
        }
        conn->close();
        return;
    }

    bool opened = tunnel->open(host, port);
    if (!opened) {
        util::Logger::error("Failed to open SOCKS5 tunnel {} to {}:{}", tunnel_id, host, port);
        tunnel_mgr_->remove_tunnel(tunnel_id);
        if (!reply_sent->exchange(true)) {
            (*reply_cb)(TunnelOpenOutcome::Failed);
        }
        conn->close();
        return;
    }
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

std::string TunnelClient::server_tox_id_snapshot() const {
    std::lock_guard<std::mutex> lock(endpoints_mutex_);
    return server_tox_id_hex_;
}

void TunnelClient::record_server_connection(std::string_view tox_id, std::uint32_t friend_number) {
    if (!known_servers_ || tox_id.empty())
        return;
    const auto state = tox_adapter_->get_friend_connection_status(friend_number);
    const auto type = to_known_connection_type(state);
    if (!known_servers_->record_connection(std::string(tox_id), type)) {
        util::Logger::warn("known_servers: record_connection rejected tox_id");
        return;
    }
    if (auto save = known_servers_->save(); !save) {
        util::Logger::warn("known_servers: failed to save: {}", save.error());
    }
}

void TunnelClient::record_server_info(std::string_view tox_id, std::string_view yaml_payload) {
    if (!known_servers_ || tox_id.empty())
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

    if (!known_servers_->record_info(std::string(tox_id), info)) {
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
    std::string new_tox_id;
    uint32_t new_friend_number = 0;
    {
        // ONE critical section decides the switch, publishes the new active
        // endpoint, and dispatches the manager route repin (issue #30). Keeping
        // it atomic avoids a racing-second-switch desync between active_index_
        // and the strand route pin.
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        if (new_index >= endpoints_.size() || new_index == active_index_) {
            return;
        }
        old_id_prefix = endpoints_[active_index_].tox_id_hex.substr(0, 12);
        active_index_ = new_index;
        // A switch reuses tunnel ids under a new session; invalidate any
        // outstanding RESUME_ACK captured before this point (issue #28).
        ++resume_session_generation_;
        new_friend_number = endpoints_[new_index].friend_number;
        new_id_prefix = endpoints_[new_index].tox_id_hex.substr(0, 12);
        new_tox_id = endpoints_[new_index].tox_id_hex;
        server_tox_id_hex_ = new_tox_id;
        server_online_.store(endpoints_[new_index].online, std::memory_order_release);
        server_friend_number_.store(new_friend_number, std::memory_order_release);

        // Repin the manager route ON the inbound strand — POSTED while STILL
        // holding endpoints_mutex_. asio::post always ENQUEUES (never runs the
        // handler inline, unlike dispatch which can when the strand is idle),
        // so nothing runs here and it is safe under the lock. Queuing it now —
        // before releasing the lock — orders the repin task ahead of any
        // inbound task for a new-friend packet, because that packet's ingress
        // must take THIS lock (to read active) before it can post, and cannot
        // do so until we release. So new-session frames are never dropped by
        // the gate, and the whole decision stays a single atomic critical
        // section.
        //
        // Running on the strand serializes the repin with the inbound routing
        // gate — a frame that passes the gate replies through the handler
        // pinned to the same friend, with NO client lock held across the
        // (Tox-thread-blocking) reply send, so there is no Tox-thread/app-lock
        // inversion.
        //  * clear_pending_outbound() empties the old queue (and bumps the
        //    drain epoch), so no old-session frame streams to the new server.
        //  * strand_route_friend_ is set together with the handler in one
        //    strand task, keeping the gate and the reply route consistent.
        //  * An in-flight drain is unaffected: it holds a value copy of the old
        //    handler in its SendSnapshot and sends its one popped frame to the
        //    old friend.
        if (tunnel_mgr_ && inbound_strand_) {
            asio::post(*inbound_strand_, [this, new_friend_number]() {
                strand_route_friend_ = new_friend_number;
                tunnel_mgr_->clear_pending_outbound();
                install_manager_send_handler(new_friend_number);
            });
        }
    }

    util::Logger::info("Failover: switching active server {}... -> {}... (friend {})",
                       old_id_prefix, new_id_prefix, new_friend_number);

    // Tear down tunnels routed through the previous active endpoint. The
    // listeners will re-open new tunnels through the new server on the next
    // accepted TCP connection. (For already-established TCP connections, the
    // close propagates back to the local TCP side, which matches the
    // "rebuild on switchover" semantics described in the spec.) close_all()
    // runs OUTSIDE endpoints_mutex_ because it fires on_close callbacks that
    // re-enter the client.
    info_request_sent_.store(false);
    if (tunnel_mgr_) {
        tunnel_mgr_->close_all();
    }

    // Refresh known-servers metadata if the new endpoint is already online.
    if (server_online_.load(std::memory_order_acquire)) {
        record_server_connection(new_tox_id, new_friend_number);
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

void TunnelClient::run_connectivity_log_tick() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }
    // Quiet while online — the heartbeat exists only to make a *stuck* offline
    // state visible (field notes #3: a client started before its server logged
    // one line at startup and then went silent).
    if (server_online_.load(std::memory_order_acquire)) {
        return;
    }

    std::string id_prefix;
    std::chrono::seconds::rep offline_secs = -1;
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        if (active_index_ < endpoints_.size()) {
            const auto& active = endpoints_[active_index_];
            const auto& hex = active.tox_id_hex;
            id_prefix = hex.size() > 8 ? hex.substr(0, 8) : hex;
            if (active.offline_since != std::chrono::steady_clock::time_point{}) {
                offline_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::steady_clock::now() - active.offline_since)
                                   .count();
            }
        }
    }

    if (offline_secs >= 0) {
        util::Logger::warn("Still trying to reach server {}...; offline for {}s (retrying)",
                           id_prefix, offline_secs);
    } else {
        util::Logger::warn("Still trying to reach server {}... (retrying)", id_prefix);
    }
}

void TunnelClient::schedule_connectivity_log_tick() {
    if (!io_ctx_ || !running_.load(std::memory_order_acquire)) {
        return;
    }
    if (!connectivity_log_timer_) {
        connectivity_log_timer_ = std::make_unique<asio::steady_timer>(io_ctx_->get_io_context());
    }
    connectivity_log_timer_->expires_after(kConnectivityLogInterval);
    connectivity_log_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec || !running_.load(std::memory_order_acquire)) {
            return;
        }
        run_connectivity_log_tick();
        schedule_connectivity_log_tick();
    });
}

}  // namespace toxtunnel::app
