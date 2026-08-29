#include "toxtunnel/app/tunnel_server.hpp"

#include <algorithm>
#include <cctype>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "toxtunnel/app/rate_limiter.hpp"
#include "toxtunnel/app/tunnel_senders.hpp"
#include "toxtunnel/core/tcp_connection.hpp"
#include "toxtunnel/tunnel/protocol.hpp"
#include "toxtunnel/tunnel/tunnel.hpp"
#include "toxtunnel/util/config_reload.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/system_info.hpp"

namespace toxtunnel::app {

using tunnel::kLosslessPacketByte;

namespace {

/// Canonicalise a hex public key to the uppercase form used everywhere else
/// (RulesEngine canonicalises on load; `tox::bytes_to_hex` emits uppercase).
std::string canonical_pk(std::string_view pk) {
    std::string out;
    out.reserve(pk.size());
    for (char c : pk) {
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

}  // namespace

namespace detail {

std::vector<std::string> friend_keys_to_preseed(
    const std::vector<std::string>& rule_public_keys,
    const std::vector<std::string>& existing_friend_public_keys) {
    // Seeded with the keys already in the friend list; from then on it doubles
    // as the de-dup set, so a key listed twice in rules.yaml is emitted once.
    std::unordered_set<std::string> seen;
    seen.reserve(existing_friend_public_keys.size() + rule_public_keys.size());
    for (const auto& pk : existing_friend_public_keys) {
        seen.insert(canonical_pk(pk));
    }

    std::vector<std::string> missing;
    for (const auto& pk : rule_public_keys) {
        auto key = canonical_pk(pk);
        // RulesEngine::from_file already rejects malformed keys, but a
        // programmatically-assembled engine can still carry one and
        // tox_friend_add_norequest would read a short buffer. Filter here so the
        // caller can convert every returned key unconditionally.
        if (!tox::parse_public_key(key)) {
            continue;
        }
        if (!seen.insert(key).second) {
            continue;
        }
        missing.push_back(std::move(key));
    }
    return missing;
}

bool frame_bypasses_byte_throttle(tunnel::FrameType type) noexcept {
    switch (type) {
        case tunnel::FrameType::PING:
        case tunnel::FrameType::PONG:
        case tunnel::FrameType::TUNNEL_ACK:
        case tunnel::FrameType::INFO_REQUEST:
        case tunnel::FrameType::INFO_REPLY:
        case tunnel::FrameType::Unknown:
            return true;
        default:
            // TUNNEL_OPEN / DATA / CLOSE / ERROR and the resume opcodes are all
            // tunnel-lifecycle frames whose order relative to DATA is load
            // bearing; they queue.
            return false;
    }
}

std::int64_t InboundByteThrottle::now_nanos() const {
    if (clock_) {
        return clock_();
    }
    // duration_cast, not .count(): steady_clock's period is implementation
    // defined, and these values are mixed with nanosecond budgets.
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

InboundByteThrottle::Admission InboundByteThrottle::admit(std::span<const std::uint8_t> packet,
                                                          tunnel::FrameType type,
                                                          std::size_t data_bytes,
                                                          std::chrono::nanoseconds max_wait) {
    if (frame_bypasses_byte_throttle(type)) {
        return Admission::Dispatch;
    }
    if (backlog_.empty()) {
        // Nothing deferred, so ordering imposes nothing: a frame that carries
        // no metered payload, or a friend with no budget, goes straight
        // through without ever touching the limiter's mutex.
        if (!active_ || data_bytes == 0) {
            return Admission::Dispatch;
        }
        std::chrono::nanoseconds wait{};
        if (limiter_->try_consume_bytes(friend_pk_, data_bytes, wait)) {
            return Admission::Dispatch;
        }
        retry_after_ = wait;
    } else if (active_ && data_bytes > 0) {
        // Queued behind an existing backlog: this frame never reached the
        // bucket (the head is what is short), but the budget is why it waits,
        // so it is counted here. Otherwise the throttle counter would report a
        // 400-frame congestion episode as a single frame.
        limiter_->note_bytes_throttled(friend_pk_);
    }
    // Either this frame is over budget, or something ahead of it is. Both mean
    // the same thing: it goes to the back of the queue, because letting it past
    // would reorder the friend's stream. It is enqueued even when that crosses
    // the memory rail — overshooting by one packet is nothing next to dropping
    // it, and the rail's job is to trigger the release below, not to refuse.
    backlog_bytes_ += packet.size();
    backlog_.push_back(
        Deferred{std::vector<std::uint8_t>(packet.begin(), packet.end()), data_bytes});
    const std::int64_t now = now_nanos();
    const std::int64_t deadline = now + std::max<std::int64_t>(max_wait.count(), 0);
    if (release_deadline_ns_ == 0 || deadline < release_deadline_ns_) {
        release_deadline_ns_ = deadline;
    }
    if (backlog_bytes_ > max_backlog_bytes_) {
        releasing_ = true;
        return Admission::Release;
    }
    if (release_deadline_ns_ <= now) {
        // This frame's tunnel is already at (or past) the point where waiting
        // risks the reaper. Do not hand it to the retry timer — that timer is
        // scheduled from the refill rate and would happily sleep. Tell the
        // caller to drain now.
        releasing_ = true;
        deadline_release_notice_ = true;
        return Admission::Release;
    }
    return Admission::Parked;
}

std::chrono::nanoseconds InboundByteThrottle::time_until_release() const {
    if (backlog_.empty() || release_deadline_ns_ == 0) {
        return std::chrono::nanoseconds::max();
    }
    return std::chrono::nanoseconds(std::max<std::int64_t>(release_deadline_ns_ - now_nanos(), 0));
}

bool InboundByteThrottle::take_deadline_release_notice() noexcept {
    const bool notice = deadline_release_notice_;
    deadline_release_notice_ = false;
    return notice;
}

bool InboundByteThrottle::next_ready(std::vector<std::uint8_t>& out) {
    if (backlog_.empty()) {
        releasing_ = false;
        release_deadline_ns_ = 0;
        return false;
    }
    Deferred& front = backlog_.front();
    if (!releasing_ && release_deadline_ns_ != 0 && now_nanos() >= release_deadline_ns_) {
        // Some queued frame's tunnel is now close enough to its reaper deadline
        // that waiting any longer risks the reaper closing it — and a tunnel
        // closed underneath queued bytes is exactly the silent loss this whole
        // mechanism exists to prevent. Give up on the budget for this backlog.
        releasing_ = true;
        deadline_release_notice_ = true;
    }
    if (!releasing_ && active_ && front.data_bytes > 0) {
        std::chrono::nanoseconds wait{};
        // Silent: this payload was counted when it was first judged in
        // `admit()`. Counting each retry would make the throttle metric
        // measure the retry cadence instead of the traffic.
        if (!limiter_->try_consume_bytes(friend_pk_, front.data_bytes, wait,
                                         RateLimiter::ThrottleAccounting::Silent)) {
            retry_after_ = wait;
            return false;
        }
    }
    out = std::move(front.packet);
    backlog_bytes_ -= out.size();
    backlog_.pop_front();
    retry_after_ = std::chrono::nanoseconds::zero();
    if (backlog_.empty()) {
        releasing_ = false;
        release_deadline_ns_ = 0;
    }
    return true;
}

void InboundByteThrottle::clear() noexcept {
    backlog_.clear();
    backlog_bytes_ = 0;
    releasing_ = false;
    release_deadline_ns_ = 0;
    retry_after_ = std::chrono::nanoseconds::zero();
}

}  // namespace detail

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
        // M-S-3 (2026-05-20 fix-storm review): S14 made the empty
        // rules engine default-deny. The previous "permissive
        // defaults" message lied — every incoming TUNNEL_OPEN would
        // be silently refused, and operators reading logs while
        // debugging a "tunnel never connects" issue would never
        // suspect this was the cause. Tell the truth, and tell them
        // where to fix it.
        util::Logger::warn(
            "No rules file configured; ALL incoming tunnels will be denied "
            "(default-deny). Configure server.rules_file in toxtunnel.yaml.");
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
    tox_config.ipv6_enabled = tox_cfg.ipv6_enabled;
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

    // Populate the friend list from the rules allowlist before the iterate
    // thread starts. Safe here: the Tox instance is initialized but
    // `ToxAdapter::running_` is still false, so run_on_tox_thread() executes
    // inline on this thread.
    preseed_friends_from_rules();

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
        // Report the deadline the watchdog ACTUALLY runs with: configure()
        // clamps anything under 5 s, and printing the raw config value made
        // `deadline_seconds: 0` look like it had taken effect.
        const auto effective_deadline = watchdog_->deadline().count();
        if (static_cast<std::int64_t>(config_.watchdog.deadline_seconds) != effective_deadline) {
            util::Logger::warn("watchdog.deadline_seconds={} is below the {}s minimum; using {}s",
                               config_.watchdog.deadline_seconds, effective_deadline,
                               effective_deadline);
        }
        util::Logger::info("Tox-thread watchdog enabled (deadline={}s)", effective_deadline);
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
            // Resolve tunnel_id -> friend_number under managers_mutex_, then
            // RELEASE the lock BEFORE get_friend_pk_hex(). That call marshals to
            // the Tox thread and blocks on it (ToxAdapter::get_friend_public_key
            // -> run_on_tox_thread), and the inbound-frame path
            // (on_lossless_packet) takes managers_mutex_ on the Tox thread — so
            // holding it here while blocking on that thread deadlocks: the Tox
            // thread can't drain the marshaled task because it's waiting on the
            // lock we hold. Same snapshot-then-release discipline as route_frame
            // / resolve_manager below.
            uint32_t friend_number = 0;
            bool found = false;
            {
                std::lock_guard lock(managers_mutex_);
                for (const auto& [fn, manager] : managers_) {
                    if (manager->has_tunnel(tunnel_id)) {
                        friend_number = fn;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                return {};
            }
            auto hex = get_friend_pk_hex(friend_number);
            return hex.size() > 8 ? hex.substr(0, 8) : hex;
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

    // Close all tunnel managers (live + held-for-resume).
    {
        std::lock_guard lock(managers_mutex_);
        for (auto& [friend_number, manager] : managers_) {
            util::Logger::debug("Closing tunnels for friend {}", friend_number);
            manager->close_all();
        }
        managers_.clear();
        // H-07: drop any managers held pending resume — cancel their prune
        // timers and close their tunnels.
        for (auto& [friend_number, held] : held_managers_) {
            if (held.prune_timer) {
                held.prune_timer->cancel();
            }
            if (held.manager) {
                held.manager->close_all();
            }
        }
        held_managers_.clear();
    }

    // Detach and stop the observer before Tox so it cannot trip during
    // shutdown. An iterate already holding the old atomic raw pointer may
    // still call heartbeat(), so retain the owner until stop() joins that
    // thread.
    if (watchdog_) {
        tox_adapter_->set_watchdog(nullptr);
        watchdog_->stop();
    }
    tox_adapter_->stop();
    watchdog_.reset();

    // Phase 2: stop the io_context and join its workers. After this
    // returns, no async callback can run any more.
    io_context_->stop();

    // Phase 3: NOW it's safe to free the sub-servers; their callbacks
    // have all been drained.
    inspect_server_.reset();
    metrics_server_.reset();
    // Same phase for the throttle slots: they own steady_timers on the (now
    // stopped and joined) io_context, so no handler can be mid-flight.
    inbound_.clear();

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
    // Byte budgets are reloadable too, and the per-friend "is this friend
    // metered?" flag is strand-confined state, so the refresh has to be posted
    // rather than done here on the signal thread.
    if (inbound_strand_) {
        asio::post(*inbound_strand_, [this]() { refresh_inbound_throttles(); });
    }
    // Per-friend concurrent-tunnel caps live in the (reloadable) rules_file, so
    // push the new values onto already-connected managers too — not just fresh
    // ones via setup_tunnel_manager().
    reapply_tunnel_caps();
    // Keys added to rules.yaml by this reload must reach the Tox friend list
    // now: a client that already knows this server will never re-send a friend
    // request, so `on_friend_request` cannot pick them up later. Runs after the
    // rules_mutex_ writer lock above has been released — this call blocks on the
    // Tox thread, which takes rules_mutex_ on the inbound path.
    preseed_friends_from_rules();

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

    // S28 / H-2 (2026-05-20 review): use the rules engine as an
    // implicit allowlist. Previously every incoming friend request was
    // auto-accepted, so anyone holding the server's Tox ID could spam
    // requests and grow the friend list without bound (toxcore enforces
    // an internal cap, but well before that the daemon's memory and the
    // rules engine's per-friend lookup both degrade). A friend that
    // appears nowhere in rules.yaml can never open a tunnel anyway
    // (default-deny — see S14), so refusing the friend request itself
    // is strictly safer.
    bool allowed;
    {
        std::shared_lock rules_lock(rules_mutex_);
        allowed = rules_engine_.has_rules_for_friend(pk_hex);
    }
    if (!allowed) {
        util::Logger::warn(
            "Refused friend request from {}: no rule entry for this Tox ID — "
            "add the public key to rules.yaml to allow this peer",
            pk_hex);
        return;
    }

    auto result = tox_adapter_->add_friend_norequest(public_key);
    if (result) {
        util::Logger::info("Accepted friend request from {}, friend_number={}", pk_hex,
                           result.value());
    } else {
        util::Logger::error("Failed to accept friend request from {}: {}", pk_hex, result.error());
    }
}

void TunnelServer::on_friend_connection(uint32_t friend_number, bool connected) {
    // Fires on the Tox iterate thread. Every friend-lifecycle transition is
    // funnelled onto inbound_strand_ instead of running here, for two reasons:
    //
    //  1. Serialisation. setup/teardown classify state under managers_mutex_
    //     and then act after releasing it. Locking the maps is not enough on
    //     its own: two transitions for the same friend could interleave between
    //     classification and action (a `connected` deciding KeepExisting while a
    //     queued keepalive teardown moves that very manager to the held map, so
    //     the connected path returns leaving no live manager). On one strand the
    //     transitions cannot overlap at all, so the decision a transition made
    //     is still true when it acts.
    //  2. Mutual exclusion with inbound frames. RESUME_REQUEST handling runs on
    //     this same strand, so a resume can no longer land halfway through a
    //     teardown and be told there is no held tunnel while one is being
    //     installed.
    //
    // Ordering is preserved: toxcore delivers per-friend events in order and a
    // strand runs posted work in post order.
    // Resolve the public key HERE, on the Tox thread, where
    // ToxAdapter::run_on_tox_thread() detects the same-thread case and runs the
    // lookup inline. Doing it inside the strand handler instead would marshal
    // back to the Tox thread and BLOCK until its next tick (up to one
    // tox_iteration_interval, ~50 ms) — and because this strand also carries
    // inbound frame handling, that stall would apply to data, not just to the
    // connect event. Cheap here, expensive there.
    auto pk_hex = get_friend_pk_hex(friend_number);

    asio::post(*inbound_strand_, [this, friend_number, connected, pk_hex = std::move(pk_hex)]() {
        if (connected) {
            util::Logger::info("Friend {} (pk={}) connected", friend_number, pk_hex);
            setup_tunnel_manager(friend_number, pk_hex);
        } else {
            util::Logger::info("Friend {} (pk={}) disconnected", friend_number, pk_hex);
            teardown_tunnel_manager(friend_number);
        }
        // Recompute from the canonical source (managers_ map) so churn during
        // a Tox reconnect can't drift the gauge.
        std::lock_guard lock(managers_mutex_);
        util::MetricsRegistry::instance().set_friends_online(managers_.size());
    });
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

    // Per-friend inbound byte budget (`rate_limit.bytes_per_sec`). The gate
    // either lets the frame through, parks it in arrival order until the bucket
    // refills, or reports that the friend has buried us in deferred bytes. It
    // takes no lock, so it cannot interact with the manager/tunnel locking
    // discipline below.
    if (auto it = inbound_.find(friend_number); it != inbound_.end()) {
        const std::size_t data_bytes =
            frame.type() == tunnel::FrameType::TUNNEL_DATA ? frame.as_tunnel_data().size() : 0;
        // The deadline only matters for a frame that can actually be parked, so
        // pay for the tunnel lookup inside inbound_deferral_budget() only then.
        // Everything else — an unmetered friend, a report-mode one (which never
        // defers), a bypassing control frame, or a non-DATA frame with nothing
        // queued ahead of it — takes the default and never touches
        // managers_mutex_ on the data path.
        const bool may_park = it->second.enforcing &&
                              !detail::frame_bypasses_byte_throttle(frame.type()) &&
                              (data_bytes > 0 || !it->second.throttle.empty());
        const auto max_wait =
            may_park ? inbound_deferral_budget(friend_number, frame.tunnel_id())
                     : std::chrono::nanoseconds(detail::InboundByteThrottle::kDefaultMaxDeferral);
        switch (it->second.throttle.admit(std::span<const uint8_t>(data, length), frame.type(),
                                          data_bytes, max_wait)) {
            case detail::InboundByteThrottle::Admission::Dispatch:
                break;
            case detail::InboundByteThrottle::Admission::Parked:
                arm_inbound_retry(friend_number);
                return;
            case detail::InboundByteThrottle::Admission::Release:
                // Either rail can produce Release. The deadline one is
                // announced by drain_inbound_backlog() through the notice;
                // report the memory one here, where the backlog size still
                // means something.
                if (!it->second.throttle.deadline_release_pending()) {
                    util::Logger::warn(
                        "Friend {} reached the inbound throttle backlog rail ({} bytes "
                        "deferred); releasing the backlog now — its byte budget will be "
                        "exceeded for this burst. The stream is intact; raise bytes_per_sec, "
                        "or check whether the peer is honouring flow control.",
                        friend_number, it->second.throttle.backlog_bytes());
                }
                drain_inbound_backlog(friend_number);
                return;
        }
    }

    dispatch_inbound_frame(friend_number, frame);
}

void TunnelServer::dispatch_inbound_frame(uint32_t friend_number,
                                          const tunnel::ProtocolFrame& frame) {
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

    // H-07: TUNNEL_RESUME_REQUEST is a per-friend control frame, not bound to a
    // live tunnel. Answer it explicitly (decline) so it isn't routed to a
    // non-existent tunnel and silently dropped.
    if (frame.type() == tunnel::FrameType::TUNNEL_RESUME_REQUEST) {
        handle_resume_request(friend_number, frame);
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

void TunnelServer::drain_inbound_backlog(uint32_t friend_number) {
    auto it = inbound_.find(friend_number);
    if (it == inbound_.end()) {
        return;
    }

    // Collect first, dispatch second. `dispatch_inbound_frame` re-enters the
    // manager and can run arbitrary tunnel callbacks; taking every packet the
    // budget allows *before* any of that means no reference into `inbound_` is
    // held across a call that might one day touch the map.
    std::vector<std::vector<std::uint8_t>> ready;
    std::vector<std::uint8_t> packet;
    while (it->second.throttle.next_ready(packet)) {
        ready.push_back(std::move(packet));
    }
    // Read the notice, not `releasing()`: the pop that empties the queue clears
    // the latch, so by now `releasing()` is false again and a single-frame
    // release would go unreported. (The memory rail logs at its own call site,
    // where the backlog size is still meaningful.)
    if (it->second.throttle.take_deadline_release_notice()) {
        util::Logger::warn(
            "Friend {}: a deferred frame reached its release deadline (its tunnel would soon "
            "be reaped as idle); releasing {} deferred frame(s) now — the byte budget is "
            "exceeded for this burst, but the stream stays intact.",
            friend_number, ready.size());
    }

    for (const auto& p : ready) {
        if (p.size() < 2) {
            continue;
        }
        auto parsed = tunnel::ProtocolFrame::deserialize(
            std::span<const uint8_t>(p.data() + 1, p.size() - 1));
        if (!parsed) {
            // Cannot happen: the packet decoded once already, on arrival.
            util::Logger::warn("Deferred frame from friend {} failed to re-deserialize",
                               friend_number);
            continue;
        }
        dispatch_inbound_frame(friend_number, parsed.value());
    }

    // Re-find: the loop above ran unlocked callbacks, and the entry could in
    // principle be gone (a teardown posted onto this same strand cannot
    // interleave, but a future direct caller could).
    if (auto entry = inbound_.find(friend_number); entry != inbound_.end()) {
        entry->second.retry_armed = false;
        arm_inbound_retry(friend_number);
    }
}

void TunnelServer::arm_inbound_retry(uint32_t friend_number) {
    auto it = inbound_.find(friend_number);
    if (it == inbound_.end() || it->second.retry_armed || it->second.throttle.empty()) {
        return;
    }
    auto& entry = it->second;

    // Floor: sub-millisecond timers are not honoured on every platform (the
    // Windows tick is ~15.6 ms), and a shorter wait would just re-ask for a
    // token that has not accrued. Ceiling: re-check at least once a second so a
    // budget loosened by a hot reload is picked up promptly instead of after a
    // wait computed under the old, tighter rate.
    constexpr auto kMinRetry = std::chrono::milliseconds(1);
    constexpr auto kMaxRetry = std::chrono::milliseconds(1000);
    // Never sleep past the release deadline. `retry_after()` only knows when
    // the BUDGET will be ready; the deadline is when a queued frame's tunnel
    // stops being safe to keep waiting on, and that is the harder constraint.
    // Cap before rounding: `time_until_release()` is `nanoseconds::max()` when
    // no deadline is set, and adding to that overflows.
    const auto capped =
        std::min({std::chrono::duration_cast<std::chrono::nanoseconds>(kMaxRetry),
                  entry.throttle.retry_after(), entry.throttle.time_until_release()});
    const auto wait = std::clamp(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     capped + std::chrono::nanoseconds(999'999)),
                                 kMinRetry, kMaxRetry);

    entry.retry_armed = true;
    entry.retry_timer->expires_after(wait);
    entry.retry_timer->async_wait(asio::bind_executor(
        *inbound_strand_,
        [this, friend_number, timer = entry.retry_timer](const asio::error_code& ec) {
            // `timer` is captured for lifetime only: teardown erases the map
            // entry (and with it the map's shared_ptr) while this wait is
            // still pending, and the handler must not run against a freed
            // timer.
            (void)timer;
            if (ec) {
                return;  // cancelled by teardown; the backlog went with it
            }
            drain_inbound_backlog(friend_number);
        }));
}

std::chrono::nanoseconds TunnelServer::inbound_deferral_budget(uint32_t friend_number,
                                                               uint16_t tunnel_id) const {
    // Ceiling regardless of reapers: a stream running minutes behind is
    // indistinguishable from a hung one, so deferral is bounded even when
    // nothing would reap the tunnel.
    auto budget = std::chrono::nanoseconds(detail::InboundByteThrottle::kDefaultMaxDeferral);

    // The reapers judge a tunnel by how long it has gone without TUNNEL_DATA,
    // and a deferred frame has not reached its tunnel — so the safe wait is not
    // a property of the queue but of THIS tunnel, which may already have been
    // sitting idle when the frame arrived. Ask it.
    std::uint32_t tightest_timeout = 0;
    for (const std::uint32_t timeout :
         {config_.tunnel.idle_timeout_seconds, config_.tunnel.half_close_timeout_seconds}) {
        if (timeout > 0 && (tightest_timeout == 0 || timeout < tightest_timeout)) {
            tightest_timeout = timeout;
        }
    }
    if (tightest_timeout == 0) {
        return budget;  // no reaper armed; nothing can close the tunnel under us
    }

    // H-01: copy the manager out under the lock, query outside it.
    std::shared_ptr<tunnel::TunnelManager> mgr;
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it != managers_.end()) {
            mgr = it->second;
        }
    }
    std::shared_ptr<tunnel::Tunnel> tunnel = mgr ? mgr->get_tunnel(tunnel_id) : nullptr;
    auto* impl = dynamic_cast<tunnel::TunnelImpl*>(tunnel.get());

    // Slack = what the reaper still allows, minus its tick (it samples, so it
    // can act up to one tick late) and minus the same again as drain margin.
    // An unknown tunnel gets the minimum: the frame is about to be dropped by
    // routing anyway, and holding it helps nobody.
    const auto timeout_ns = std::chrono::nanoseconds(std::chrono::seconds(tightest_timeout));
    const auto tick_ns =
        std::chrono::nanoseconds(std::chrono::seconds(config_.tunnel.reaper_tick_seconds));
    const auto idle_ns = impl != nullptr ? std::chrono::nanoseconds(impl->IdleNanos())
                                         : std::chrono::nanoseconds::zero();
    const auto slack =
        impl != nullptr ? timeout_ns - idle_ns - 2 * tick_ns : std::chrono::nanoseconds::zero();
    budget = std::min(budget, slack);
    // Never negative, and never zero: a zero budget releases on the very next
    // drain, which is the intended behaviour for an at-risk tunnel, but the
    // deadline arithmetic reads better with a floor than with a sentinel.
    return std::max(budget, std::chrono::nanoseconds::zero());
}

void TunnelServer::refresh_inbound_throttles() {
    auto& limiter = rate_limiter_instance();
    for (auto& [friend_number, entry] : inbound_) {
        const auto spec = limiter.effective_spec(entry.pk_hex);
        const bool active = spec.byte_limiting_engaged();
        entry.enforcing = active && spec.mode == RateLimitMode::Enforce;
        if (active != entry.throttle.active()) {
            entry.throttle.set_active(active);
            util::Logger::info("Inbound byte throttle {} for friend {}",
                               active ? "engaged" : "disengaged", friend_number);
        }
        // Drain unconditionally, whether or not `active` moved. The reload may
        // have loosened the budget or switched the friend from `enforce` to
        // `report` — both leave `active` true while meaning "stop delaying
        // this" — and the pending retry timer was scheduled under the OLD
        // rate. The drain re-consults the limiter, so the new spec applies at
        // once, and it drains in order, so nothing is reordered.
        if (!entry.throttle.empty()) {
            drain_inbound_backlog(friend_number);
        }
    }
}

void TunnelServer::sync_rate_limiter() {
    auto& limiter = rate_limiter_instance();
    std::shared_lock rules_lock(rules_mutex_);
    // A rules reload is ONE logical transition, so it must be published as one.
    // Expressed as clear_all_friend_specs() + set_default_spec() + N x
    // set_friend_spec(), each call took the limiter's mutex on its own and
    // published a half-applied generation in between: a TUNNEL_OPEN landing in
    // one of those gaps was judged against the new defaults with the
    // per-friend specs still missing, and could be admitted or rejected against
    // limits no rules file ever described. replace_all() does the whole swap
    // under a single lock hold, so a concurrent consumer observes either the
    // entire old generation or the entire new one.
    //
    // Semantics are unchanged: every bucket is still destroyed, so a friend
    // dropped from the new rules cannot retain a stale bucket, and each
    // surviving friend restarts from a full burst with zeroed rejection
    // counters (documented in docs/CONFIGURATION.md).
    std::vector<RateLimiter::FriendOverride> overrides;
    overrides.reserve(rules_engine_.rules().size());
    for (const auto& rule : rules_engine_.rules()) {
        if (!rule.rate_limit.empty()) {
            overrides.emplace_back(rule.friend_pk, rule.rate_limit);
        }
    }
    limiter.replace_all(rules_engine_.rate_limit_defaults(), overrides);
}

void TunnelServer::preseed_friends_from_rules() {
    if (!tox_adapter_) {
        return;
    }

    // Snapshot the rule keys and RELEASE rules_mutex_ before touching the Tox
    // adapter: every call below blocks on the Tox thread, and the Tox thread
    // takes rules_mutex_ itself (on_friend_request / handle_tunnel_open).
    std::vector<std::string> rule_pks;
    {
        std::shared_lock rules_lock(rules_mutex_);
        rule_pks.reserve(rules_engine_.rules().size());
        for (const auto& rule : rules_engine_.rules()) {
            rule_pks.push_back(rule.friend_pk);
        }
    }
    if (rule_pks.empty()) {
        return;
    }

    // One marshaled round trip for the whole friend list, rather than a
    // friend_by_public_key() hop per rule.
    std::vector<std::string> existing;
    const auto friends = tox_adapter_->get_friend_info_list();
    existing.reserve(friends.size());
    for (const auto& info : friends) {
        existing.push_back(tox::bytes_to_hex(info.public_key.data(), info.public_key.size()));
    }

    // NOTE (deliberate asymmetry): keys REMOVED from rules.yaml are not removed
    // from the friend list. Deleting a friend is a strictly more destructive act
    // than the access decision that motivated it: it drops any live tunnels and
    // the transport relationship for what is usually a reversible administrative
    // edit. Meanwhile a stale friend entry grants nothing — the rules engine
    // default-denies every TUNNEL_OPEN from an unlisted key, and the rate
    // limiter drops its per-friend spec on reload — so the only cost is a
    // friend-list slot.
    //
    // (To be precise about the mechanics: `tox_friend_delete` does NOT notify
    // the peer, so deletion is recoverable — restoring the rule would re-add
    // this side and the link can re-form without a new friend request. The
    // reason to avoid it is the disruption, not irreversibility.) Operators who
    // want a friend gone can stop the daemon and remove it explicitly.
    const auto missing = detail::friend_keys_to_preseed(rule_pks, existing);
    if (missing.empty()) {
        util::Logger::debug("Friend pre-seed: all {} rule key(s) already in the friend list",
                            rule_pks.size());
        return;
    }

    std::size_t added = 0;
    for (const auto& pk_hex : missing) {
        auto parsed = tox::parse_public_key(pk_hex);
        if (!parsed) {
            continue;  // filtered by friend_keys_to_preseed; belt and braces
        }
        auto result = tox_adapter_->add_friend_norequest(parsed.value());
        if (result) {
            ++added;
            util::Logger::info("Pre-seeded friend {} from rules (friend_number={})", pk_hex,
                               result.value());
        } else {
            // Not fatal: the peer can still reach us if it ever does send a
            // friend request, and every other rule key is unaffected.
            util::Logger::warn("Could not pre-seed friend {} from rules: {}", pk_hex,
                               result.error());
        }
    }
    util::Logger::info("Friend pre-seed: added {} of {} missing key(s) ({} rule key(s) total)",
                       added, missing.size(), rule_pks.size());
}

void TunnelServer::apply_tunnel_cap(tunnel::TunnelManager& manager, uint32_t friend_number,
                                    std::string_view pk_hex) {
    const std::string resolved =
        pk_hex.empty() ? get_friend_pk_hex(friend_number) : std::string(pk_hex);
    const auto spec = rate_limiter_instance().effective_spec(resolved);
    // 0 => reset to the manager's default ceiling (100) so a removed limit is
    // honoured; otherwise clamp to the absolute safety cap.
    const std::size_t cap =
        spec.max_concurrent_tunnels > 0
            ? std::min(spec.max_concurrent_tunnels, RateLimiter::kAbsoluteTunnelCap)
            : 100;
    manager.set_max_tunnels(cap);
}

void TunnelServer::reapply_tunnel_caps() {
    // Snapshot (friend -> manager) under managers_mutex_, then release it before
    // calling apply_tunnel_cap(): it resolves the friend pk via the Tox thread,
    // which itself takes managers_mutex_ on the inbound frame path, so resolving
    // under the lock could deadlock. The shared_ptr snapshot keeps each manager
    // alive across the unlocked tail. A manager mid-resurrection (in neither map)
    // is covered by setup_tunnel_manager() applying the cap on reinsertion.
    std::vector<std::pair<uint32_t, std::shared_ptr<tunnel::TunnelManager>>> snapshot;
    {
        std::lock_guard lock(managers_mutex_);
        snapshot.reserve(managers_.size() + held_managers_.size());
        for (const auto& [fn, mgr] : managers_) {
            snapshot.emplace_back(fn, mgr);
        }
        for (const auto& [fn, held] : held_managers_) {
            if (held.manager) {
                snapshot.emplace_back(fn, held.manager);
            }
        }
    }
    for (const auto& [fn, mgr] : snapshot) {
        apply_tunnel_cap(*mgr, fn);
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

void TunnelServer::setup_tunnel_manager(uint32_t friend_number, std::string_view pk_hex) {
    // Install (or refresh) this friend's inbound byte-throttle slot before any
    // frame can be routed to it. Done for every connect event, KeepExisting
    // included: an unpaired `connected` still means the spec should be
    // re-evaluated, and try_emplace leaves an existing backlog alone.
    {
        auto [it, inserted] = inbound_.try_emplace(
            friend_number,
            FriendInbound{detail::InboundByteThrottle(rate_limiter_instance(), std::string(pk_hex)),
                          std::string(pk_hex),
                          std::make_shared<asio::steady_timer>(io_context_->get_io_context()),
                          false, false});
        (void)inserted;
        const auto spec = rate_limiter_instance().effective_spec(it->second.pk_hex);
        it->second.throttle.set_active(spec.byte_limiting_engaged());
        it->second.enforcing = spec.byte_limiting_engaged() && spec.mode == RateLimitMode::Enforce;
        if (it->second.throttle.active()) {
            util::Logger::info(
                "Inbound byte throttle engaged for friend {} (rate_limit.bytes_per_sec)",
                friend_number);
        }
    }

    // Classify the event against both maps under one lock so the decision and
    // the state it was taken on cannot drift apart.
    detail::ConnectedManagerAction action;
    {
        std::lock_guard lock(managers_mutex_);
        action = detail::classify_connected_event(managers_.contains(friend_number),
                                                  held_managers_.contains(friend_number),
                                                  config_.tunnel.resume.enabled);
    }

    if (action == detail::ConnectedManagerAction::KeepExisting) {
        // toxcore delivered `connected` without a preceding `disconnected` (seen
        // after long outages). Overwriting managers_[friend] here — what this
        // function used to do unconditionally — silently destroyed the live
        // manager along with every open tunnel and its target TCP connection,
        // and left the peer's later RESUME_REQUEST to be declined with "no held
        // tunnel". Keep what we have: those tunnels are still usable and
        // handle_resume_request() finds them in managers_ just as it would find
        // a resurrected manager. Warn, because an unpaired event also means the
        // idle/half-close reapers have been running against a peer that was in
        // fact away, so some tunnels may be reaped shortly.
        util::Logger::warn(
            "Friend {} reported connected while its tunnel manager is still live "
            "(no matching disconnected event); keeping the existing manager and its tunnels",
            friend_number);
        return;
    }

    // H-07: if this friend's previous manager is being held across a brief
    // disconnect (resume), resurrect it instead of building a fresh one. Its
    // tunnels + target TCP connections are intact and the send handler captures
    // the (stable) friend_number, so a subsequent RESUME_REQUEST can reattach
    // each tunnel and continue the stream.
    if (action == detail::ConnectedManagerAction::Resurrect) {
        std::shared_ptr<tunnel::TunnelManager> resurrected;
        {
            std::lock_guard lock(managers_mutex_);
            // Re-look-up rather than trusting the classification: the lock was
            // released in between, and teardown_tunnel_manager() can run
            // concurrently on the IO pool (posted by the keepalive peer-dead
            // handler). A vanished hold simply falls through to a fresh manager.
            auto held = held_managers_.find(friend_number);
            if (held != held_managers_.end()) {
                if (held->second.prune_timer) {
                    held->second.prune_timer->cancel();
                }
                resurrected = std::move(held->second.manager);
                held_managers_.erase(held);
            }
        }
        if (resurrected) {
            // Re-arm keepalive (it was paused while held).
            if (config_.tunnel.keepalive_enabled()) {
                resurrected->set_on_peer_dead([this, friend_number]() {
                    // Onto the lifecycle strand, not the raw pool: see
                    // on_friend_connection() for why every transition is
                    // serialised.
                    asio::post(*inbound_strand_,
                               [this, friend_number]() { teardown_tunnel_manager(friend_number); });
                });
                resurrected->enable_keepalive(config_.tunnel.keepalive_interval_seconds, 0);
            }
            // Re-arm the maintenance scan (paused while held).
            resurrected->enable_reaper(config_.tunnel.idle_timeout_seconds,
                                       config_.tunnel.reaper_tick_seconds);
            resurrected->enable_half_close_reaper(config_.tunnel.half_close_timeout_seconds,
                                                  config_.tunnel.reaper_tick_seconds);
            // Re-apply the (possibly hot-reloaded) per-friend cap before the
            // manager re-enters managers_. During this handoff it is in neither
            // managers_ nor held_managers_, so a concurrent reapply_tunnel_caps()
            // would miss it; applying here guarantees it carries the current cap.
            apply_tunnel_cap(*resurrected, friend_number, pk_hex);
            bool installed = false;
            {
                std::lock_guard lock(managers_mutex_);
                // try_emplace, not operator[]: a live manager installed while we
                // were outside the lock must win over this resurrection, because
                // it is the one the peer is actually talking to.
                installed = managers_.try_emplace(friend_number, resurrected).second;
            }
            if (installed) {
                util::Logger::info("Resurrected held tunnel manager for friend {} (resume)",
                                   friend_number);
            } else {
                util::Logger::error(
                    "Friend {} gained a live tunnel manager mid-resurrection; discarding the "
                    "held one",
                    friend_number);
                // Release the loser's local state OUTSIDE managers_mutex_ (close
                // paths re-enter it). Its tunnel ids belong to a session the peer
                // has abandoned, and ids are recycled per friend, so a
                // TUNNEL_CLOSE from here could close the winner's
                // identically-numbered tunnel instead. close_all_local() emits no
                // teardown frame of its own and authorises no further send; it
                // does not retract a send some other thread authorised just
                // before the gate closed (see TunnelManager::close_all_local()).
                resurrected->close_all_local();
            }
            return;
        }
    }

    auto manager = std::make_shared<tunnel::TunnelManager>(io_context_->get_io_context());

    // Enforce the per-friend concurrent-tunnel ceiling
    // (rate_limit.max_concurrent_tunnels) via the manager's existing max_tunnels_
    // gate (checked by handle_incoming_open / add_tunnel). It was parsed into
    // RateLimitSpec but never applied anywhere. Done before managers_mutex_ is
    // taken below (apply_tunnel_cap marshals to the Tox thread).
    apply_tunnel_cap(*manager, friend_number, pk_hex);

    // Set up the send handler: serialize frame, prepend lossless packet byte,
    // send via ToxAdapter.
    manager->set_send_handler(
        [this, friend_number](const std::vector<uint8_t>& frame_data) -> tunnel::SendOutcome {
            // Prepend the lossless packet prefix byte.
            std::vector<uint8_t> packet;
            packet.reserve(1 + frame_data.size());
            packet.push_back(kLosslessPacketByte);
            packet.insert(packet.end(), frame_data.begin(), frame_data.end());

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

    // Set up tunnel created callback for logging.
    manager->set_on_tunnel_created([friend_number](uint16_t tunnel_id) {
        util::Logger::debug("Tunnel {} created for friend {}", tunnel_id, friend_number);
    });

    // Set up tunnel closed callback for logging.
    manager->set_on_tunnel_closed([friend_number](uint16_t tunnel_id) {
        util::Logger::debug("Tunnel {} closed for friend {}", tunnel_id, friend_number);
    });

    // M-02: application-level keepalive. The manager lives exactly as long as
    // the friend is online, so enabling here (and letting the destructor cancel
    // it) tracks the connection lifetime. If the peer stops answering PINGs we
    // tear down its tunnels — defer via post so we don't re-enter
    // managers_mutex_ from inside the keepalive timer handler.
    if (config_.tunnel.keepalive_enabled()) {
        manager->set_on_peer_dead([this, friend_number]() {
            util::Logger::warn("Friend {} unresponsive (keepalive); tearing down its tunnels",
                               friend_number);
            // Lifecycle strand, not the raw pool — see on_friend_connection().
            asio::post(*inbound_strand_,
                       [this, friend_number]() { teardown_tunnel_manager(friend_number); });
        });
        manager->enable_keepalive(config_.tunnel.keepalive_interval_seconds, 0);
    }

    // Idle reaper (opt-in) + half-close linger cap (on by default). Both no-op
    // when their timeout is 0. The half-close cap bounds tunnels stuck in
    // Disconnecting after a one-sided TCP close whose peer never sends the
    // reciprocal TUNNEL_CLOSE (the v0.4.4 stuck-Disconnecting fd leak).
    manager->enable_reaper(config_.tunnel.idle_timeout_seconds, config_.tunnel.reaper_tick_seconds);
    manager->enable_half_close_reaper(config_.tunnel.half_close_timeout_seconds,
                                      config_.tunnel.reaper_tick_seconds);

    std::lock_guard lock(managers_mutex_);
    // try_emplace, not operator[]: same no-clobber rule as the resurrection path
    // above. try_emplace leaves `manager` untouched when the key already exists,
    // so the loser is this freshly built (and still empty) manager, never the
    // live one holding the peer's tunnels.
    if (!managers_.try_emplace(friend_number, std::move(manager)).second) {
        util::Logger::warn(
            "Friend {} already had a live tunnel manager when a fresh one was built; "
            "keeping the existing one",
            friend_number);
    }
}

void TunnelServer::teardown_tunnel_manager(uint32_t friend_number) {
    // Drop the friend's throttle slot: cancel its retry timer and discard any
    // deferred packets. Those bytes belong to a session the peer has left, and
    // they were never acknowledged — so on a resume the client still counts
    // them as in-flight and `resume_offsets_have_gap()` reports the hole rather
    // than the stream quietly missing a chunk.
    if (auto it = inbound_.find(friend_number); it != inbound_.end()) {
        if (it->second.retry_timer) {
            it->second.retry_timer->cancel();
        }
        inbound_.erase(it);
    }

    // The live -> held transition must be ATOMIC with respect to
    // setup_tunnel_manager(). Doing the erase in one critical section and the
    // hold insertion in a later one leaves a window in which the friend appears
    // in NEITHER map; a `connected` event landing there classifies as
    // CreateFresh, and the subsequent hold insertion then produces a live
    // manager AND a held one for the same friend. Every RESUME_REQUEST would
    // route to the fresh manager and decline the tunnels that were, in fact,
    // still being held. So: build the timer first (allocation only), then do
    // the whole decision inside one lock.
    //
    // Everything called under the lock is deliberately non-reentrant with
    // respect to managers_mutex_: TunnelManager::empty() takes only its own
    // shared_lock, and disable_keepalive()/disable_reaper() only cancel asio
    // timers (cancel posts, it does not run handlers inline). The heavyweight
    // work — close_all(), arming the prune timer, logging — stays outside, per
    // the H-01 discipline.
    // Build AND arm the prune timer before it can become visible in
    // held_managers_. Publishing an unarmed timer and calling expires_after()
    // afterwards leaves a window in which a resurrection cancels a timer that
    // has no deadline yet — the cancel is a no-op and the subsequent arming
    // then schedules a prune for a manager that is live again. expires_after()
    // on a timer with no pending wait is harmless, and async_wait() is attached
    // below only on the path that actually holds.
    auto timer = std::make_shared<asio::steady_timer>(io_context_->get_io_context());
    timer->expires_after(std::chrono::seconds(config_.tunnel.resume.max_age_seconds));

    std::shared_ptr<tunnel::TunnelManager> mgr;
    bool held = false;
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it == managers_.end()) {
            return;
        }
        mgr = it->second;

        // Stop background maintenance while still holding the lock, so a
        // resurrection cannot re-arm it and then have us disable it again on a
        // manager that is live once more. Re-armed on resurrection; harmless on
        // the close path. (A reap pass already in flight can still finish, but
        // it only reaps tunnels already idle past the cap — which is exactly
        // what the cap is for, so the residual is benign.)
        mgr->disable_keepalive();
        mgr->disable_reaper();

        // H-07: if resume is enabled and this manager still has live tunnels,
        // hold it (and its target TCP connections) for up to
        // resume.max_age_seconds so a quick reconnect can reattach.
        held = config_.tunnel.resume.enabled && !mgr->empty();
        if (held) {
            held_managers_[friend_number] = HeldManager{mgr, timer};
        }
        // Erase LAST: until this line the friend is still visible as live, and
        // after it the hold (if any) is already visible. There is no gap.
        managers_.erase(it);
    }

    if (held) {
        util::Logger::info("Holding tunnel manager for friend {} for resume (up to {}s)",
                           friend_number, config_.tunnel.resume.max_age_seconds);
        std::weak_ptr<asio::steady_timer> weak_timer = timer;
        // Completion runs on the lifecycle strand so pruning cannot interleave
        // with a setup/teardown for the same friend (see on_friend_connection).
        timer->async_wait(asio::bind_executor(
            *inbound_strand_, [this, friend_number, weak_timer](const asio::error_code& ec) {
                if (ec) {
                    return;  // cancelled — the friend reconnected and we resurrected it
                }
                std::shared_ptr<tunnel::TunnelManager> expired;
                {
                    std::lock_guard lock(managers_mutex_);
                    auto h = held_managers_.find(friend_number);
                    if (h == held_managers_.end()) {
                        return;
                    }
                    // Generation guard: a cancel() that loses the race against an
                    // already-queued completion would otherwise let THIS stale
                    // handler evict a *newer* held manager (reconnect→disconnect
                    // installed a fresh hold under the same friend_number). Only act
                    // if the held entry is still the one this timer belongs to.
                    if (h->second.prune_timer != weak_timer.lock()) {
                        return;
                    }
                    expired = std::move(h->second.manager);
                    held_managers_.erase(h);
                }
                if (expired) {
                    util::Logger::info("Resume hold expired for friend {}; closing held tunnels",
                                       friend_number);
                    expired->close_all();
                }
            }));
    } else {
        mgr->close_all();
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
        // H-01: copy the manager shared_ptr out under the lock, then send_frame
        // outside it — send_frame can re-enter callbacks that take
        // managers_mutex_, so holding it across the call risks re-entrant
        // deadlock.
        std::shared_ptr<tunnel::TunnelManager> mgr;
        {
            std::lock_guard lock(managers_mutex_);
            auto it = managers_.find(friend_number);
            if (it != managers_.end()) {
                mgr = it->second;
            }
        }
        if (mgr) {
            auto error_frame =
                tunnel::ProtocolFrame::make_tunnel_error(tunnel_id, 3, "Rate limit exceeded");
            mgr->send_frame(error_frame);
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

        // Send error frame back (H-01: send_frame outside managers_mutex_).
        std::shared_ptr<tunnel::TunnelManager> mgr;
        {
            std::lock_guard lock(managers_mutex_);
            auto it = managers_.find(friend_number);
            if (it != managers_.end()) {
                mgr = it->second;
            }
        }
        if (mgr) {
            auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(tunnel_id, 1, reason);
            mgr->send_frame(error_frame);
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
    // H-S-3 (2026-05-20 fix-storm review): hold a shared_ptr to the
    // manager, not a raw pointer. The async tail (add_tunnel +
    // async_resolve + connect) can outrun a friend-offline teardown
    // that removes the manager from the server's managers_ map; the
    // shared_ptr keeps the manager alive long enough for the guard's
    // destructor to actually do its job, instead of dereferencing a
    // freed object or no-op'ing a release that should have happened.
    struct TunnelIdGuard {
        std::shared_ptr<tunnel::TunnelManager> mgr;
        uint16_t id;
        bool committed = false;
        ~TunnelIdGuard() {
            if (!committed && mgr) {
                mgr->release_tunnel_id(id);
            }
        }
    };
    TunnelIdGuard id_guard{manager_ptr, tunnel_id, false};

    auto server_tunnel = std::make_shared<tunnel::TunnelImpl>(io_context_->get_io_context(),
                                                              tunnel_id, friend_number);
    // The server's open-handshake lives here in TunnelServer, not in
    // TunnelImpl::handle_tunnel_open_frame, so set the target explicitly so
    // `toxtunnel inspect tunnels` can render the real `host:port` instead of
    // the bare ":0" placeholder.
    server_tunnel->set_target(target_host, target_port);
    server_tunnel->configure_coalesce(config_.tunnel.coalesce_max_delay_us,
                                      config_.tunnel.coalesce_max_bytes);
    apply_coalesce_and_flow_control(*server_tunnel);
    // Outbound wiring, shared with the client's three tunnel paths: manager
    // byte/frame accounting plus the outbound FIFO barrier. Sends the
    // already-serialized frame directly rather than via manager_ptr->send_frame,
    // which would force a deserialize + re-serialize round trip and a redundant
    // byte copy.
    auto senders = detail::make_tunnel_senders(
        [this](std::uint32_t friend_num, const std::uint8_t* data, std::size_t length) {
            return tox_adapter_->send_lossless_packet_typed(friend_num, data, length);
        },
        manager_ptr, friend_number);
    server_tunnel->set_on_send_to_tox(std::move(senders.span));
    server_tunnel->set_on_send_to_tox_owned(std::move(senders.owned));
    // H-05: add_tunnel can fail (manager hit max_tunnels between
    // handle_incoming_open and here). On failure leave the guard uncommitted so
    // it releases the reserved id, tell the peer, and bail — otherwise the
    // TUNNEL_OPEN would be half-accepted with no registered tunnel.
    if (!manager_ptr->add_tunnel(tunnel_id, std::move(server_tunnel))) {
        util::Logger::warn("TunnelManager full; could not add tunnel {} for friend {}", tunnel_id,
                           friend_number);
        util::MetricsRegistry::instance().inc_tunnels_opened(
            util::MetricsRegistry::OpenResult::Denied);
        auto error_frame =
            tunnel::ProtocolFrame::make_tunnel_error(tunnel_id, 3, "Tunnel limit exceeded");
        manager_ptr->send_frame(error_frame);
        return;
    }
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

                // Send error and close the tunnel (H-01: do both outside
                // managers_mutex_ — remove_tunnel() calls Tunnel::close(), whose
                // callbacks re-enter managers_mutex_).
                std::shared_ptr<tunnel::TunnelManager> mgr;
                {
                    std::lock_guard lock(managers_mutex_);
                    auto it = managers_.find(friend_number);
                    if (it != managers_.end()) {
                        mgr = it->second;
                    }
                }
                if (mgr) {
                    auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
                        tunnel_id, 2, "DNS resolution failed: " + ec.message());
                    mgr->send_frame(error_frame);
                    mgr->remove_tunnel(tunnel_id);
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

                    std::shared_ptr<tunnel::TunnelManager> mgr;
                    {
                        std::lock_guard lock(managers_mutex_);
                        auto it = managers_.find(friend_number);
                        if (it != managers_.end()) {
                            mgr = it->second;
                        }
                    }
                    if (mgr) {
                        auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
                            tunnel_id, 3, "TCP connect failed: " + connect_ec.message());
                        mgr->send_frame(error_frame);
                        mgr->remove_tunnel(tunnel_id);
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

// ---------------------------------------------------------------------------
// detail::OpenAckGate
// ---------------------------------------------------------------------------

namespace detail {

ActiveGaugeState active_gauge_state(const ActiveGaugeLatch& latch) {
    std::lock_guard<std::mutex> lock(latch->mutex);
    return latch->state;
}

bool active_gauge_count(const ActiveGaugeLatch& latch) {
    std::lock_guard<std::mutex> lock(latch->mutex);
    if (latch->state != ActiveGaugeState::NotCounted) {
        // Already released by a terminal transition that beat us here. Counting
        // now would leak the gauge, because the decrement has already run.
        return false;
    }
    // The increment happens under the lock, so a release cannot observe
    // `Counted` and decrement before the count it is meant to undo exists.
    util::MetricsRegistry::instance().inc_tunnels_active(util::MetricsRegistry::Role::Server);
    latch->state = ActiveGaugeState::Counted;
    return true;
}

void active_gauge_release(const ActiveGaugeLatch& latch) {
    std::lock_guard<std::mutex> lock(latch->mutex);
    // Settles both directions: decrements exactly when the gauge was counted,
    // and blocks any later count when it was not.
    if (latch->state == ActiveGaugeState::Counted) {
        util::MetricsRegistry::instance().dec_tunnels_active(util::MetricsRegistry::Role::Server);
    }
    latch->state = ActiveGaugeState::Released;
}

namespace {

/// Drop a server tunnel's local resources without relying on `Tunnel::close()`,
/// which is a no-op for a tunnel still in `None`.
void release_unpublished_resources(const std::shared_ptr<tunnel::TunnelImpl>& tunnel,
                                   const std::shared_ptr<core::TcpConnection>& conn) {
    if (conn) {
        // Closes the socket and cancels any peer-close watch still holding it.
        conn->force_close();
    }
    if (tunnel) {
        // Drives a terminal state and fires on_close_, so the owner's cleanup
        // runs even though the tunnel never left None.
        tunnel->force_close();
    }
}

}  // namespace

void wire_active_gauge(tunnel::TunnelImpl& tunnel, ActiveGaugeLatch gauge,
                       std::function<void()> extra_on_close) {
    tunnel.set_on_state_change([gauge](tunnel::Tunnel::State new_state) {
        if (new_state == tunnel::Tunnel::State::Closed ||
            new_state == tunnel::Tunnel::State::Error) {
            active_gauge_release(gauge);
        }
    });
    tunnel.set_on_close([gauge, extra = std::move(extra_on_close)]() {
        // Settled here as well as on the terminal transition: a graceful close
        // of a published tunnel never reaches one. The latch makes the overlap
        // harmless.
        active_gauge_release(gauge);
        if (extra) {
            extra();
        }
    });
}

OpenAckCommit commit_open_ack(const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
                              const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
                              const std::weak_ptr<core::TcpConnection>& weak_tcp,
                              std::uint16_t tunnel_id, std::uint32_t friend_number,
                              const ActiveGaugeLatch& gauge) {
    auto tunnel = weak_tunnel.lock();
    auto conn = weak_tcp.lock();
    if (!tunnel || !conn) {
        // One of them was destroyed while the ACK was in flight. The peer still
        // has the ACK, so it must be told — see abort_open_ack_after_send().
        abort_open_ack_after_send(weak_manager, weak_tunnel, weak_tcp, tunnel_id, friend_number,
                                  gauge);
        return OpenAckCommit::Gone;
    }

    // Ownership pre-filter. Identity, not just the id: ids are recycled per
    // friend, so "the manager has a tunnel numbered N" is not the same question
    // as "the manager still has THIS tunnel".
    //
    // This is NOT the claim. get_tunnel() releases the manager's lock before we
    // could act on its answer, so a removal landing in that gap would still slip
    // through — check-then-act, exactly the shape this function exists to avoid.
    // It is kept because it catches the common case early and produces the
    // accurate log line; the claim below is what makes the decision atomic.
    auto manager = weak_manager.lock();
    const auto owned = manager ? manager->get_tunnel(tunnel_id) : nullptr;
    const bool still_owned = owned.get() == static_cast<tunnel::Tunnel*>(tunnel.get());

    // THE claim: one compare-exchange on the tunnel's own state word, which is
    // the single arbiter every teardown of an unpublished tunnel also goes
    // through — TunnelManager::remove_tunnel() and close_all() force-close a
    // tunnel that is still None rather than calling close(), which would no-op
    // there and leave this nothing to lose against. Losing means somebody else
    // resolved this tunnel first.
    if (!still_owned || !tunnel->try_publish_connected()) {
        util::Logger::warn(
            "Tunnel {} (friend {}) was detached while its OPEN_ACK was in flight; "
            "releasing it instead of publishing",
            tunnel_id, friend_number);
        abort_open_ack_after_send(weak_manager, weak_tunnel, weak_tcp, tunnel_id, friend_number,
                                  gauge);
        return OpenAckCommit::Detached;
    }

    // The state claim is necessary but NOT sufficient: it covers the transition,
    // not the publication. A removal landing between the claim and the work
    // below would leave us counting a gauge and starting a target read loop for
    // a tunnel the manager has already let go of. Re-verify ownership now that
    // the state is Connected, and order the rest so nothing irreversible
    // happens first — the gauge is undone by active_gauge_release(), and
    // start_read() is last.
    if (auto owner = weak_manager.lock();
        !owner ||
        owner->get_tunnel(tunnel_id).get() != static_cast<tunnel::Tunnel*>(tunnel.get())) {
        util::Logger::warn(
            "Tunnel {} (friend {}) was detached between claiming Connected and publishing; "
            "releasing it",
            tunnel_id, friend_number);
        // force_close() sees Connected and therefore announces the CLOSE the
        // peer is owed — it has our OPEN_ACK.
        abort_open_ack_after_send(weak_manager, weak_tunnel, weak_tcp, tunnel_id, friend_number,
                                  gauge);
        return OpenAckCommit::Detached;
    }

    // Published. Connected is already set by the claim — it is what admits
    // outbound bytes at all — so the metrics and then the read loop that
    // produces those bytes follow it.
    //
    // A removal that lands from here on is harmless and self-correcting: with
    // the state already Connected it takes the graceful close path, which
    // announces to the peer, closes the socket the read loop is using, and
    // drives the terminal transition that settles the gauge latch.
    util::MetricsRegistry::instance().inc_tunnels_opened(util::MetricsRegistry::OpenResult::Ok);
    active_gauge_count(gauge);
    conn->start_read();
    util::Logger::debug("Tunnel {} wired to TCP for friend {}", tunnel_id, friend_number);
    return OpenAckCommit::Published;
}

void abort_open_ack_after_send(const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
                               const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
                               const std::weak_ptr<core::TcpConnection>& weak_tcp,
                               std::uint16_t tunnel_id, std::uint32_t friend_number,
                               const ActiveGaugeLatch& gauge) {
    util::MetricsRegistry::instance().inc_tunnels_opened(util::MetricsRegistry::OpenResult::Failed);

    auto tunnel = weak_tunnel.lock();
    if (auto manager = weak_manager.lock()) {
        // The peer already has the OPEN_ACK and is treating this tunnel as
        // open. Leaving it at that would strand it until its own reaper fires.
        auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
            tunnel_id, 3, "tunnel was torn down immediately after it was opened");
        manager->send_frame(error_frame);
        (void)manager->remove_tunnel_if(tunnel_id, tunnel.get());
    }

    release_unpublished_resources(tunnel, weak_tcp.lock());
    active_gauge_release(gauge);

    util::Logger::warn(
        "Tunnel {} (friend {}) could not be published after its OPEN_ACK was sent; "
        "peer notified with TUNNEL_ERROR",
        tunnel_id, friend_number);
}

void abandon_open_ack(const std::weak_ptr<tunnel::TunnelManager>& weak_manager,
                      const std::weak_ptr<tunnel::TunnelImpl>& weak_tunnel,
                      const std::weak_ptr<core::TcpConnection>& weak_tcp, std::uint16_t tunnel_id,
                      std::uint32_t friend_number, const ActiveGaugeLatch& gauge) {
    util::MetricsRegistry::instance().inc_tunnels_opened(util::MetricsRegistry::OpenResult::Failed);

    // Tell the peer first: it is sitting in Connecting and only a terminal
    // frame resolves that.
    auto tunnel = weak_tunnel.lock();
    if (auto manager = weak_manager.lock()) {
        auto error_frame = tunnel::ProtocolFrame::make_tunnel_error(
            tunnel_id, 3, "target connection lost before tunnel was established");
        manager->send_frame(error_frame);
        // Identity-checked: by the time this deferred cleanup runs, the id may
        // already have been recycled by a different tunnel, and removing that
        // one is the very recycled-id failure this slice exists to eliminate.
        //
        // A lapsed weak_ptr must remove NOTHING rather than fall back to an
        // id-only removal: if our tunnel is already destroyed, the manager can
        // no longer be holding it, so anything registered under this id belongs
        // to somebody else.
        if (tunnel) {
            (void)manager->remove_tunnel_if(tunnel_id, tunnel.get());
        }
    }

    // Then drop the local resources explicitly. remove_tunnel() above delegates
    // to Tunnel::close(), which no-ops in None — so on its own it would leave
    // this socket open until the target happened to close it, and the
    // peer-close watch's outstanding async_wait keeps the connection alive
    // indefinitely for a target that simply stays quiet.
    release_unpublished_resources(tunnel, weak_tcp.lock());
    active_gauge_release(gauge);

    util::Logger::warn(
        "Tunnel {} (friend {}) abandoned before its OPEN_ACK reached the peer; "
        "client notified with TUNNEL_ERROR",
        tunnel_id, friend_number);
}

OpenAckGate::OpenAckGate(asio::io_context& io_ctx, AckSender send_ack, CommitFn commit,
                         AbandonFn abandon, PostCommitCloseFn post_commit_close)
    : timer_(io_ctx),
      send_ack_(std::move(send_ack)),
      commit_(std::move(commit)),
      abandon_(std::move(abandon)),
      post_commit_close_(std::move(post_commit_close)) {}

void OpenAckGate::release_callbacks_locked() {
    // No further retry is wanted, whichever way we resolved. Every touch of
    // timer_ happens under mutex_.
    timer_.cancel();
    // Dropping the callbacks is also how a resolved gate stops keeping whatever
    // they captured alive.
    send_ack_ = nullptr;
    commit_ = nullptr;
    abandon_ = nullptr;
}

void OpenAckGate::start() {
    attempt(/*retry=*/0);
}

void OpenAckGate::attempt(unsigned retry) {
    AckSender sender;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (phase_ != Phase::Pending) {
            return;  // Resolved, or another attempt already owns the send.
        }
        // Claim the send BEFORE dropping the lock. From here until the verdict
        // is recorded, target_gone() must not resolve on its own — see Phase.
        phase_ = Phase::Sending;
        sender = send_ack_;
    }

    tunnel::SendOutcome outcome = tunnel::SendOutcome::PermanentFail;
    if (sender) {
        attempts_.fetch_add(1, std::memory_order_relaxed);
        // Called with NO lock held: the sender re-enters TunnelManager (H-01).
        outcome = sender();
    }

    CommitFn run_commit;
    std::function<void()> run_abandon;
    bool retry_again = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (target_gone_requested_) {
            // The target died while this send was inside the transport.
            // target_gone() deliberately deferred to us so no OPEN_ACK could be
            // emitted after the TUNNEL_ERROR; resolve it here, after the send
            // has definitely finished. If the ACK did go out, the peer sees
            // ACK-then-ERROR, which is an ordinary teardown it handles; what it
            // must never see is ERROR-then-ACK.
            phase_ = Phase::Abandoned;
            run_abandon = std::move(abandon_);
            release_callbacks_locked();
            post_commit_close_ = nullptr;  // Never published; nothing to close.
        } else if (outcome == tunnel::SendOutcome::Sent) {
            // Committing, not Committed: the tunnel is not published until the
            // callback below has actually run.
            phase_ = Phase::Committing;
            run_commit = std::move(commit_);
            release_callbacks_locked();
        } else if (outcome == tunnel::SendOutcome::PermanentFail) {
            // The peer will never get the ACK, so it would sit in Connecting
            // until its own timeout. Resolve it explicitly instead.
            phase_ = Phase::Abandoned;
            run_abandon = std::move(abandon_);
            release_callbacks_locked();
            post_commit_close_ = nullptr;  // Never published; nothing to close.
        } else {
            phase_ = Phase::Pending;
            retry_again = true;
        }
    }

    if (run_abandon) {
        run_abandon();
        return;
    }

    if (run_commit) {
        const bool published = run_commit();
        // Publish only now, and only if the commit actually did. A target_gone()
        // that arrived while the callback was running could not be answered
        // truthfully at the time, so it left its request behind for us to
        // honour — but only a real publication makes the ordinary close path the
        // right handler.
        std::function<void()> deferred_close;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            phase_ = published ? Phase::Committed : Phase::Abandoned;
            if (published && target_gone_requested_) {
                deferred_close = std::move(post_commit_close_);
            }
            post_commit_close_ = nullptr;
        }
        if (deferred_close) {
            deferred_close();
        }
        return;
    }

    if (retry_again) {
        arm_retry(retry);
    }
}

void OpenAckGate::arm_retry(unsigned retry) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ != Phase::Pending) {
        return;
    }
    timer_.expires_after(tunnel::sendq_retry_delay(retry));
    // Hold the gate alive across the wait; nothing else is guaranteed to.
    timer_.async_wait([self = shared_from_this(), retry](const std::error_code& ec) {
        if (ec) {
            return;  // Cancelled by a resolution.
        }
        self->attempt(retry + 1);
    });
}

bool OpenAckGate::target_gone() {
    std::function<void()> run_abandon;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        switch (phase_) {
            case Phase::Pending:
                // Nothing in flight: resolve here and now.
                phase_ = Phase::Abandoned;
                run_abandon = std::move(abandon_);
                release_callbacks_locked();
                post_commit_close_ = nullptr;
                break;

            case Phase::Sending:
            case Phase::Committing:
                // Somebody else owns this phase and is mid-callback. Hand them
                // the request rather than racing them; they consume it the
                // moment they finish. Either way the gate owns the teardown, so
                // the caller must not run its ordinary close.
                target_gone_requested_ = true;
                timer_.cancel();
                return true;

            case Phase::Committed:
                // The tunnel is live: Tunnel::close() is the right handler and
                // the caller owns it.
                return false;

            case Phase::Abandoned:
                // Already resolved by us; the ordinary close must not run.
                return true;
        }
    }
    if (run_abandon) {
        run_abandon();
    }
    return true;
}

bool OpenAckGate::committed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return phase_ == Phase::Committed;
}

}  // namespace detail

void TunnelServer::send_resume_ack(uint32_t friend_number, uint16_t tunnel_id,
                                   uint64_t server_recv_offset, uint64_t server_send_offset,
                                   tunnel::TunnelResumeStatus status) {
    tunnel::TunnelResumeAckPayload ack;
    ack.new_tunnel_id = tunnel_id;
    ack.server_recv_offset = server_recv_offset;
    ack.server_send_offset = server_send_offset;
    ack.status = status;

    auto reply = tunnel::ProtocolFrame::make_tunnel_resume_ack(ack);
    auto wire = reply.serialize();
    std::vector<uint8_t> packet;
    packet.reserve(1 + wire.size());
    packet.push_back(kLosslessPacketByte);
    packet.insert(packet.end(), wire.begin(), wire.end());
    (void)tox_adapter_->send_lossless_packet(friend_number, packet.data(), packet.size());
}

void TunnelServer::handle_resume_request(uint32_t friend_number,
                                         const tunnel::ProtocolFrame& frame) {
    auto req = frame.as_tunnel_resume_request();
    if (!req) {
        util::Logger::warn("Malformed TUNNEL_RESUME_REQUEST from friend {}", friend_number);
        return;
    }

    // Resume disabled here: decline so the client immediately re-opens.
    if (!config_.tunnel.resume.enabled) {
        send_resume_ack(friend_number, req->prior_tunnel_id, 0, 0,
                        tunnel::TunnelResumeStatus::Unknown);
        util::Logger::info("RESUME_REQUEST from friend {} (tunnel {}): resume disabled; declined",
                           friend_number, req->prior_tunnel_id);
        return;
    }

    // The friend has reconnected and setup_tunnel_manager() has resurrected its
    // held manager, so the prior tunnel (+ its target TCP) should still be
    // present. Look it up.
    std::shared_ptr<tunnel::TunnelManager> mgr;
    {
        std::lock_guard lock(managers_mutex_);
        auto it = managers_.find(friend_number);
        if (it != managers_.end()) {
            mgr = it->second;
        }
    }
    std::shared_ptr<tunnel::Tunnel> tunnel = mgr ? mgr->get_tunnel(req->prior_tunnel_id) : nullptr;
    auto* impl = dynamic_cast<tunnel::TunnelImpl*>(tunnel.get());
    if (impl == nullptr) {
        // Hold expired (or never existed): decline, client re-opens.
        send_resume_ack(friend_number, req->prior_tunnel_id, 0, 0,
                        tunnel::TunnelResumeStatus::TooOld);
        util::Logger::info(
            "RESUME_REQUEST from friend {} (tunnel {}): no held tunnel; declined (re-open)",
            friend_number, req->prior_tunnel_id);
        return;
    }

    // The held tunnel must still be resumable. A target-TCP drop during the hold
    // (which now closes the tunnel via weak_manager in wire_tcp_to_tunnel) leaves
    // it Closed/Error with stale offset counters — resuming would stream onto a
    // dead socket. Connected and Disconnecting are both still resumable:
    // Disconnecting is a half-close that still carries data in the peer->server
    // direction (handle_tunnel_data accepts DATA while Disconnecting), so it must
    // NOT be declined. Decline only the genuinely dead/incomplete states.
    if (const auto st = impl->state();
        st != tunnel::Tunnel::State::Connected && st != tunnel::Tunnel::State::Disconnecting) {
        send_resume_ack(friend_number, req->prior_tunnel_id, 0, 0,
                        tunnel::TunnelResumeStatus::TooOld);
        util::Logger::info(
            "RESUME_REQUEST friend {} tunnel {}: tunnel not resumable (state={}); declined",
            friend_number, req->prior_tunnel_id, tunnel::to_string(st));
        // We are holding the very tunnel we looked up, so name it: an id-only
        // removal here would take out whatever recycled the id instead.
        (void)mgr->remove_tunnel_if(req->prior_tunnel_id, impl);
        return;
    }

    // Offset reconciliation. A gap means bytes one side sent never reached the
    // other (dropped in the disconnect, or still buffered) — there is no
    // app-level retransmit buffer, so we cannot fill it.
    //   client->server gap: client says it sent c_sent, server received s_recv.
    //   server->client gap: server sent s_sent, client received c_recv.
    const uint64_t s_recv = impl->bytes_received();
    // Emitted (on-the-wire), NOT accepted-from-TCP — see the client side: bytes
    // still buffered in the coalescer must not count as a transmission gap.
    const uint64_t s_sent = impl->bytes_emitted();
    const uint64_t c_sent = req->last_local_send_offset;
    const uint64_t c_recv = req->last_local_recv_offset;
    const bool gap = resume_offsets_have_gap(/*local_send=*/s_sent, /*peer_recv=*/c_recv,
                                             /*local_recv=*/s_recv, /*peer_send=*/c_sent);
    const bool close_on_gap = (config_.tunnel.resume.on_gap == "close");

    if (gap && close_on_gap) {
        util::Logger::warn(
            "RESUME_REQUEST friend {} tunnel {}: gap detected (c_sent={} s_recv={} s_sent={} "
            "c_recv={}); closing per on_gap=close",
            friend_number, req->prior_tunnel_id, c_sent, s_recv, s_sent, c_recv);
        send_resume_ack(friend_number, req->prior_tunnel_id, s_recv, s_sent,
                        tunnel::TunnelResumeStatus::TooOld);
        if (mgr) {
            // Same as above: we already hold the tunnel this decision is about.
            (void)mgr->remove_tunnel_if(req->prior_tunnel_id, impl);
        }
        return;
    }
    if (gap) {
        util::Logger::warn(
            "RESUME_REQUEST friend {} tunnel {}: gap detected; continuing per on_gap=passthrough "
            "(stream will have a {}+{} byte hole)",
            friend_number, req->prior_tunnel_id, c_sent > s_recv ? c_sent - s_recv : 0,
            s_sent > c_recv ? s_sent - c_recv : 0);
    }

    // Reattach: the held tunnel keeps its state + target TCP and resumes.
    send_resume_ack(friend_number, req->prior_tunnel_id, s_recv, s_sent,
                    tunnel::TunnelResumeStatus::Ok);
    util::Logger::info("Resumed tunnel {} for friend {} (gap={})", req->prior_tunnel_id,
                       friend_number, gap);
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
    // Use weak_ptr on the TcpConnection -> TunnelImpl callback edge so the
    // socket callbacks do not form a permanent ownership cycle with the tunnel.
    const std::weak_ptr<tunnel::TunnelImpl> weak_tunnel = tunnel_impl;
    // Resolve the owning manager through a weak_ptr captured here rather than a
    // friend-keyed managers_ lookup inside the callbacks. While a friend is
    // disconnected its manager is parked in held_managers_ (resume); the same
    // shared_ptr instance moves between managers_ and held_managers_ and back on
    // resurrect, so this weak_ptr tracks it across every transition and only
    // lapses once the resume hold expires and the manager is destroyed.
    const std::weak_ptr<tunnel::TunnelManager> weak_manager = manager_ptr;

    // Associate the TCP connection with the tunnel.
    tunnel_impl->set_tcp_connection(tcp_conn);

    // TCP data -> Tox: when data arrives from TCP, forward it to the tunnel.
    tcp_conn->set_on_data([weak_tunnel](const uint8_t* data, std::size_t length) {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_data_received(data, length);
        }
    });

    tcp_conn->set_on_read_eof([weak_tunnel]() {
        if (auto tunnel = weak_tunnel.lock()) {
            tunnel->on_tcp_read_eof();
        }
    });

    // The OPEN_ACK barrier. Built before the callbacks that consult it, armed
    // last (see the bottom of this function). It captures only weak handles:
    // the TcpConnection owns the disconnect callback that owns this gate, so a
    // strong capture of the connection would be a reference cycle.
    const std::weak_ptr<core::TcpConnection> weak_tcp = tcp_conn;

    // Counted at publication, released at the first terminal transition — and
    // correct in both orders, which a bare "already decremented" flag is not:
    // an abandoned tunnel is never counted, so nothing may decrement for it.
    auto active_gauge = detail::make_active_gauge_latch();

    auto ack_gate = std::make_shared<detail::OpenAckGate>(
        io_context_->get_io_context(),
        // Attempt: send_frame_typed, NOT send_frame — the bool one reports a
        // frame parked in the manager's retry queue as "queued", which is
        // exactly the "delivered?" question this gate has to answer honestly.
        [weak_manager, tunnel_id]() -> tunnel::SendOutcome {
            auto mgr = weak_manager.lock();
            if (!mgr) {
                return tunnel::SendOutcome::PermanentFail;
            }
            auto ack = tunnel::ProtocolFrame::make_tunnel_ack(tunnel_id, 0);
            return mgr->send_frame_typed(ack);
        },
        // Commit: everything that says "this tunnel is usable", behind the one
        // edge where the peer has actually been told it is open. See
        // detail::commit_open_ack() for the ownership check it makes first.
        [weak_manager, weak_tunnel, weak_tcp, tunnel_id, friend_number, active_gauge]() {
            return detail::commit_open_ack(weak_manager, weak_tunnel, weak_tcp, tunnel_id,
                                           friend_number,
                                           active_gauge) == detail::OpenAckCommit::Published;
        },
        // Abandon: the ACK will never land, or the target died before it did.
        // TUNNEL_ERROR, not TUNNEL_CLOSE — the client is still in Connecting,
        // and a CLOSE received in that state does not complete it cleanly,
        // whereas handle_tunnel_error_frame drives it to Error and resolves the
        // waiting caller (a SOCKS5 reply, a pipe teardown) immediately.
        [this, weak_manager, weak_tunnel, weak_tcp, tunnel_id, friend_number, active_gauge]() {
            // Deferred for the same reason as the on_close teardown below:
            // this can run synchronously from inside tcp_conn->close(), and
            // remove_tunnel() re-enters the tunnel's own close callbacks.
            asio::post(io_context_->get_io_context(), [weak_manager, weak_tunnel, weak_tcp,
                                                       tunnel_id, friend_number, active_gauge]() {
                detail::abandon_open_ack(weak_manager, weak_tunnel, weak_tcp, tunnel_id,
                                         friend_number, active_gauge);
            });
        },
        // Post-commit close: the target died while the commit callback was
        // still running, so the gate could not truthfully tell the disconnect
        // handler "the tunnel is live, run your close". This is that close,
        // run once commit has finished. Identical to the ordinary path below.
        [this, weak_manager, weak_tunnel, tunnel_id]() {
            asio::post(io_context_->get_io_context(), [weak_manager, weak_tunnel, tunnel_id]() {
                auto mgr = weak_manager.lock();
                auto tunnel = weak_tunnel.lock();
                if (!mgr || !tunnel) {
                    return;
                }
                // Identity-checked for the same reason as the ordinary path.
                (void)mgr->close_tunnel_if(tunnel_id, tunnel.get());
            });
        });

    // TCP disconnect: close the tunnel gracefully.
    // Uses asio::post to defer cleanup, avoiding re-entrance into managers_mutex_
    // if on_disconnect fires synchronously from tcp_conn->close().
    tcp_conn->set_on_disconnect([this, weak_manager, weak_tunnel, ack_gate, friend_number,
                                 tunnel_id](const std::error_code& ec) {
        // ec is default-constructed for a clean half-close / EOF teardown.
        // Calling ec.message() in that case renders the platform's "no
        // error" string ("Undefined error: 0" on macOS, "Success" on
        // Linux), which reads as an error in logs even though nothing
        // went wrong. Switch the wording on whether the code is real.
        if (ec) {
            util::Logger::debug("TCP disconnected for tunnel {} (friend {}): {}", tunnel_id,
                                friend_number, ec.message());
        } else {
            util::Logger::debug("TCP closed cleanly for tunnel {} (friend {})", tunnel_id,
                                friend_number);
        }

        // The target can die while the OPEN_ACK is still backpressured. The
        // tunnel was never published in that case, so the graceful close
        // below is the wrong tool: with the client still in Connecting, a
        // TUNNEL_CLOSE does not resolve it. The gate answers with a
        // TUNNEL_ERROR instead.
        if (ack_gate->target_gone()) {
            return;
        }

        asio::post(io_context_->get_io_context(), [weak_manager, weak_tunnel, tunnel_id]() {
            // Resolve via weak_manager (works whether the manager is live or
            // held for resume) instead of managers_.find(friend) — a held
            // manager is absent from managers_, so a lookup would miss the
            // target-TCP drop and strand the tunnel in a phantom-Connected
            // state that a later RESUME_REQUEST would ACK Ok on a dead socket.
            auto mgr = weak_manager.lock();
            auto tunnel = weak_tunnel.lock();
            if (!mgr || !tunnel) {
                return;
            }
            // close_tunnel_if, not get_tunnel() + close(): this cleanup is
            // deferred, and looking the id up and then closing unlocked let a
            // replacement land in between, after which the old object's
            // TUNNEL_CLOSE carried the NEW tunnel's id.
            //
            // Gracefully closes (outside managers_mutex_): flushes any buffered
            // / backpressured bytes to the peer *before* emitting TUNNEL_CLOSE —
            // deferring CLOSE until the coalesce buffer drains — then fires
            // on_close_, which removes the tunnel. Emitting CLOSE and removing
            // immediately (the old behaviour) discarded the still-in-flight
            // data, truncating the transfer when the origin closed first.
            (void)mgr->close_tunnel_if(tunnel_id, tunnel.get());
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
        [tcp_conn](core::OwnedBufferView buf) -> bool { return tcp_conn->write(std::move(buf)); });
    tunnel_impl->set_on_data_for_tcp([tcp_conn](std::span<const uint8_t> data) -> bool {
        return tcp_conn->write(data.data(), data.size());
    });
    // C-03: flush a deferred ACK once the target TCP write queue drains, so the
    // client's send window reopens instead of stalling on a slow target.
    tcp_conn->set_on_writable([weak_tunnel]() -> bool {
        if (auto t = weak_tunnel.lock()) {
            return t->notify_tcp_writable();
        }
        return true;  // tunnel gone — nothing to flush
    });

    // Tunnel close callback: fired once the tunnel is fully closed (after any
    // buffered data has drained and TUNNEL_CLOSE has been emitted, or when the
    // peer closed us). Close the local TCP connection and remove the tunnel.
    // The removal is deferred (asio::post) so it never re-enters managers_mutex_
    // or destroys the tunnel from within its own callback.
    // Gauge settlement plus this server's own teardown, in one place — see
    // detail::wire_active_gauge() for why on_close_ is needed as well as the
    // terminal transition.
    detail::wire_active_gauge(
        *tunnel_impl, active_gauge, [this, weak_manager, weak_tunnel, tunnel_id, tcp_conn]() {
            tcp_conn->close();
            asio::post(io_context_->get_io_context(), [weak_manager, weak_tunnel, tunnel_id]() {
                // Same rationale as on_disconnect: remove via the weak_ptr so a
                // tunnel closed while its manager is held for resume is still
                // dropped from that (held) manager rather than leaking.
                //
                // Identity-checked, because this removal is deferred: an id-only
                // remove_tunnel() here can tear down the replacement that
                // recycled the id while this cleanup was still queued. A lapsed
                // weak_ptr removes nothing: a destroyed tunnel cannot still be
                // registered, so whatever holds this id is not ours.
                auto mgr = weak_manager.lock();
                auto owner = weak_tunnel.lock();
                if (mgr && owner) {
                    (void)mgr->remove_tunnel_if(tunnel_id, owner.get());
                }
            });
        });

    // Watch for the target dying before the read loop exists. `start_read()` is
    // held back until the OPEN_ACK is on the wire, and a socket with no
    // outstanding read never notices a FIN — so without this the abandon path
    // below could not actually be reached by a real target death, only by a
    // transport failure. Stood down automatically by `start_read()` inside the
    // commit callback.
    tcp_conn->watch_peer_close();

    // Send TUNNEL_ACK, and publish the tunnel only once it is actually on the
    // wire. Connected, the open metrics and start_read() all live in the gate's
    // commit callback for that reason — see detail::OpenAckGate.
    ack_gate->start();
}

std::string TunnelServer::get_friend_pk_hex(uint32_t friend_number) const {
    auto pk_result = tox_adapter_->get_friend_public_key(friend_number);
    if (pk_result) {
        return tox::bytes_to_hex(pk_result.value().data(), pk_result.value().size());
    }
    return "unknown";
}

}  // namespace toxtunnel::app
