#include "toxtunnel/tox/tox_adapter.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <thread>

#include "toxtunnel/tox/bootstrap_source.hpp"
#include "toxtunnel/tox/tox_watchdog.hpp"
#include "toxtunnel/util/atomic_file.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/metrics.hpp"
#include "toxtunnel/util/path_security.hpp"

namespace toxtunnel::tox {

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

util::Expected<std::string, std::string> ToxAdapter::get_tox_id_only(
    const std::filesystem::path& data_dir) {
    ToxAdapter adapter;
    ToxAdapterConfig config;
    config.data_dir = data_dir;
    config.udp_enabled = false;
    config.local_discovery_enabled = false;
    config.bootstrap_mode = BootstrapMode::Lan;

    auto init_result = adapter.initialize(config);
    if (!init_result.has_value()) {
        return util::unexpected(init_result.error());
    }

    return adapter.get_address().to_hex();
}

// ===========================================================================
// Lifecycle
// ===========================================================================

util::Expected<void, std::string> ToxAdapter::initialize(const ToxAdapterConfig& config) {
    if (initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter is already initialized"));
    }

    config_ = config;

    if (!util::is_plain_filename(config_.save_filename)) {
        return util::unexpected(std::string("invalid Tox save filename: must be a plain filename"));
    }

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

    // A fixed DHT port is start == end: toxcore walks [start, end] and stops
    // at the first free one, so a single-port range binds exactly that port
    // or fails (issue #32). Zero keeps the default walk.
    if (config_.udp_port != 0) {
        tox_options_set_start_port(opts, config_.udp_port);
        tox_options_set_end_port(opts, config_.udp_port);
    }

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

    // Try to load existing save data. A load *error* (present but
    // unreadable / oversized / I/O failure) aborts startup: continuing would
    // mint a fresh identity and orphan every client that knows this one.
    auto load_result = load_save_data();
    if (!load_result) {
        tox_options_free(opts);
        return util::unexpected(load_result.error());
    }
    std::vector<uint8_t> save_data = std::move(load_result.value());
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
                // The single most common startup failure on a host that already
                // runs a toxtunnel. toxcore does not say WHICH socket failed,
                // so name both candidates with their config keys: the TCP
                // relay port never auto-selects, and the UDP port only walks
                // when tox.udp_port is unset (issue #32).
                msg += "could not bind a Tox listening port: TCP relay port " +
                       std::to_string(config_.tcp_port) + " (tox.tcp_port; never auto-selects)";
                if (config_.udp_enabled) {
                    msg += config_.udp_port != 0
                               ? ", or fixed UDP port " + std::to_string(config_.udp_port) +
                                     " (tox.udp_port; set 0 to let toxcore walk 33445..33545)"
                               : ", or every UDP port in 33445..33545";
                }
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

    // Log the actually-bound UDP port so an operator can see which port
    // toxcore took (it walks 33445..33545 if the default is busy). Without
    // this an operator has no way to know the port, which makes the DHT-port
    // collision in docs/FIELD_NOTES_SSH_TUNNEL.md #8 invisible. Safe to call
    // directly: the dedicated Tox iterate thread has not been started yet, so
    // this init context is the only thread touching tox_.
    if (config_.udp_enabled) {
        Tox_Err_Get_Port port_err;
        uint16_t udp_port = tox_self_get_udp_port(tox_.get(), &port_err);
        if (port_err == TOX_ERR_GET_PORT_OK) {
            util::Logger::info("Tox UDP socket bound to port {} (IPv6 {})", udp_port,
                               config_.ipv6_enabled ? "enabled" : "disabled");
        } else {
            util::Logger::warn(
                "Could not determine bound Tox UDP port (udp_enabled but no UDP socket?)");
        }
    }

    // Persist the (possibly new) identity — and refuse to run if that
    // fails. An identity that only exists in memory disappears on restart,
    // orphaning every client that learned it (exactly the v0.4.8 Linux
    // package failure mode). write_save_data_locked() already logged the
    // underlying atomic-write error. An empty save path (no data_dir) means
    // deliberate in-memory operation and is exempt.
    if (!save_file_path().empty() && !write_save_data()) {
        tox_.reset();
        return util::unexpected(std::string("failed to persist the Tox identity to '") +
                                save_file_path().string() +
                                "' (see log for the underlying write error); refusing to run "
                                "with an identity that would not survive a restart");
    }

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

    // Finding-3 (user-reported, 2026-05-21): the bootstrap-refresh
    // cancel flag is process-global; a prior stop() left it set, and
    // without re-arming here every detached refresh thread spawned by
    // bootstrap() below would short-circuit on its first check —
    // permanently silencing background cache refresh for any subsequent
    // start-stop-start cycle.
    BootstrapSource::arm_refreshes();

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
    // Wake the iterate loop so shutdown doesn't sit through the final
    // wake_cv_.wait_for() window before joining.
    wake_cv_.notify_all();

    // H-S-6 (2026-05-20) / H-11 (2026-05-26): stop and JOIN any in-flight
    // bootstrap-cache refresh worker before we tear down application globals.
    // cancel_pending_refreshes() sets the stop flag (observed at fetch/parse/
    // write_cache boundaries) and joins the owned worker. The join is bounded
    // by the curl --max-time in fetch_default_nodes_json (a few seconds): popen
    // cannot be interrupted mid-fetch, so a refresh fetching at shutdown delays
    // stop() until that curl returns.
    BootstrapSource::cancel_pending_refreshes();

    // Same for the adapter-owned bootstrap-retry fetch worker (issue #34):
    // disarm the retry, flag the worker, join it. After this no thread can
    // deposit a node list into this adapter.
    stop_bootstrap_retry_worker();

    if (iterate_thread_.joinable()) {
        iterate_thread_.join();
    }

    // Drain any tasks that slipped in during the join race (posted after the
    // loop's final process_tox_tasks() but before running_ was observed false
    // by the poster). The iterate thread is gone, so it is now safe to run
    // them inline on this thread; the Tox instance is still alive until our
    // own destruction. Without this, a blocked run_on_tox_thread() caller
    // would wait on a future that is never fulfilled.
    process_tox_tasks();

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
    auto resolved = resolve_bootstrap_nodes_for_config(config_, config_.bootstrap_fetcher);
    if (resolved) {
        bootstrap_nodes = resolved.value();
        if (config_.bootstrap_mode == BootstrapMode::Lan && bootstrap_nodes.empty()) {
            util::Logger::info("LAN bootstrap mode enabled; relying on local discovery");
            util::Logger::warn(
                "LAN bootstrap only discovers peers on the local network; a peer behind NAT "
                "or on a different network will never become reachable. Use "
                "'bootstrap_mode: auto' for DHT/NAT traversal across networks.");
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

    std::size_t success_count = run_on_tox_thread([&]() -> std::size_t {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        return contact_bootstrap_nodes_locked(bootstrap_nodes);
    });

    // Arm the lifetime retry (issue #34). LAN mode deliberately has no public
    // node list to fetch and relies on local discovery, so it is left alone.
    if (config_.bootstrap_mode != BootstrapMode::Lan &&
        config_.bootstrap_retry_initial_delay.count() > 0) {
        std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
        bootstrap_retry_.armed = true;
        bootstrap_retry_.nodes = bootstrap_nodes;
        bootstrap_retry_.attempts = 0;
        bootstrap_retry_.delay = config_.bootstrap_retry_initial_delay;
        bootstrap_retry_.next_attempt = std::chrono::steady_clock::now() + bootstrap_retry_.delay;
        bootstrap_retry_.disconnected_since = std::chrono::steady_clock::now();
        bootstrap_retry_.last_status_log = bootstrap_retry_.disconnected_since;
    }

    if (success_count == 0) {
        // "Bootstrap complete: 0/0 nodes contacted" at info level reads as
        // success; it is total failure. With no node contacted the daemon
        // cannot reach the DHT at all, yet everything else about it — metrics,
        // inspect, "Server started" — looks perfectly healthy, so the operator
        // is left debugging the peer instead of this process (issue #34).
        // Say plainly what happened and what to do about it.
        util::Logger::error(
            "Bootstrap contacted 0 of {} node(s): this daemon has NO DHT connectivity and "
            "cannot reach any peer. Set tox.bootstrap_nodes explicitly (IP literals) if "
            "{} is unreachable from this host.",
            bootstrap_nodes.size(), std::string(BootstrapSource::kDefaultNodesUrl));
    } else {
        util::Logger::info("Bootstrap complete: {}/{} nodes contacted", success_count,
                           bootstrap_nodes.size());
    }
    return success_count;
}

std::size_t ToxAdapter::contact_bootstrap_nodes_locked(const std::vector<BootstrapNode>& nodes) {
    std::size_t count = 0;
    for (const auto& node : nodes) {
        TOX_ERR_BOOTSTRAP err;
        bool ok =
            tox_bootstrap(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(), &err);

        if (ok && err == TOX_ERR_BOOTSTRAP_OK) {
            ++count;
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
    return count;
}

unsigned ToxAdapter::bootstrap_retry_attempts() const {
    std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
    return bootstrap_retry_.attempts;
}

std::size_t ToxAdapter::bootstrap_node_count() const {
    std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
    return bootstrap_retry_.nodes.size();
}

void ToxAdapter::bootstrap_retry_tick() {
    // Runs on the Tox thread once per iteration. Everything below is a few
    // loads and one mutex when armed; the expensive part (the fetch) lives on
    // the worker.
    const auto now = std::chrono::steady_clock::now();
    std::vector<BootstrapNode> to_contact;
    bool log_status = false;
    bool spawn_fetch = false;
    unsigned attempt = 0;
    unsigned attempts_so_far = 0;
    std::chrono::seconds disconnected_for{0};
    std::chrono::seconds next_in{0};
    std::size_t known_nodes = 0;
    {
        std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
        auto& r = bootstrap_retry_;
        if (!r.armed) {
            return;
        }
        // Reap a finished worker so a later spawn never blocks on join().
        if (!r.fetch_in_flight && r.worker.joinable()) {
            r.worker.join();
        }
        if (connected_.load(std::memory_order_acquire)) {
            // Connected: toxcore keeps its own node tables alive from here.
            // Reset so a LATER disconnect restarts the schedule from the
            // short delay, and keep whatever list the retry last fetched.
            r.attempts = 0;
            r.delay = config_.bootstrap_retry_initial_delay;
            r.next_attempt = now + r.delay;
            r.disconnected_since = now;
            r.last_status_log = now;
            return;
        }
        if (r.has_fetched) {
            // The worker deposited a fresh list: contact it right away, on this
            // (the Tox) thread — the worker itself never touches tox_.
            r.nodes = std::move(r.fetched);
            r.fetched.clear();
            r.has_fetched = false;
            to_contact = r.nodes;
        }
        known_nodes = r.nodes.size();
        disconnected_for =
            std::chrono::duration_cast<std::chrono::seconds>(now - r.disconnected_since);
        if (to_contact.empty() && now >= r.next_attempt) {
            ++r.attempts;
            attempt = r.attempts;
            r.delay = std::min(r.delay * 2, config_.bootstrap_retry_max_delay);
            r.next_attempt = now + r.delay;
            if (r.nodes.empty()) {
                // Nothing to contact: the startup fetch failed with no cache.
                // Fetch again — on the worker, which may block for curl's
                // full timeout — unless a fetch is still running.
                if (!r.fetch_in_flight) {
                    spawn_fetch = true;
                }
            } else {
                to_contact = r.nodes;
            }
        }
        next_in = std::chrono::duration_cast<std::chrono::seconds>(r.next_attempt - now);
        if (next_in.count() < 0) {
            next_in = std::chrono::seconds{0};
        }
        // Periodic status while never connected, so a log tail shows the state
        // instead of only the single startup error (issue #34).
        if (now - r.last_status_log >= std::chrono::seconds(60)) {
            r.last_status_log = now;
            log_status = true;
        }
        attempts_so_far = r.attempts;
        if (spawn_fetch) {
            r.fetch_in_flight = true;
            r.worker_stop = std::make_shared<std::atomic<bool>>(false);
            auto stop = r.worker_stop;
            auto fetcher = config_.bootstrap_fetcher;
            auto data_dir = config_.data_dir;
            r.worker = std::thread([this, stop, fetcher, data_dir]() mutable {
                auto result = BootstrapSource::fetch_and_cache_default_nodes(data_dir, fetcher);
                std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
                bootstrap_retry_.fetch_in_flight = false;
                if (stop->load(std::memory_order_acquire)) {
                    return;  // stop() won; the adapter is going away.
                }
                if (result) {
                    bootstrap_retry_.fetched = std::move(result.value());
                    bootstrap_retry_.has_fetched = true;
                } else {
                    util::Logger::warn("Bootstrap node list fetch retry failed: {}",
                                       result.error());
                }
            });
        }
    }

    if (!to_contact.empty()) {
        std::size_t contacted = 0;
        {
            std::lock_guard<std::mutex> lock(tox_mutex_);
            contacted = contact_bootstrap_nodes_locked(to_contact);
        }
        util::Logger::info("Bootstrap retry {}: contacted {}/{} node(s)", attempt, contacted,
                           to_contact.size());
    } else if (spawn_fetch) {
        util::Logger::info("Bootstrap retry {}: re-fetching the node list from {}", attempt,
                           std::string(BootstrapSource::kDefaultNodesUrl));
    }

    if (log_status) {
        util::Logger::warn(
            "Not connected to the Tox DHT for {}s (known bootstrap nodes: {}, retry attempts: {}, "
            "next retry in {}s); this daemon cannot reach any peer until it connects",
            disconnected_for.count(), known_nodes, attempts_so_far, next_in.count());
    }
}

void ToxAdapter::stop_bootstrap_retry_worker() {
    std::thread worker;
    std::shared_ptr<std::atomic<bool>> stop;
    {
        std::lock_guard<std::mutex> lock(bootstrap_retry_.mutex);
        bootstrap_retry_.armed = false;
        bootstrap_retry_.has_fetched = false;
        bootstrap_retry_.fetched.clear();
        worker = std::move(bootstrap_retry_.worker);
        stop = std::move(bootstrap_retry_.worker_stop);
    }
    if (stop) {
        stop->store(true, std::memory_order_release);
    }
    if (worker.joinable()) {
        // Bounded by the fetcher's own timeout (curl --max-time 8).
        worker.join();
    }
}

bool ToxAdapter::add_bootstrap_node(const BootstrapNode& node) {
    if (!initialized_.load()) {
        return false;
    }

    return run_on_tox_thread([&]() -> bool {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_BOOTSTRAP err;
        bool ok =
            tox_bootstrap(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(), &err);

        if (ok && err == TOX_ERR_BOOTSTRAP_OK) {
            // Also add as TCP relay.
            TOX_ERR_BOOTSTRAP relay_err;
            tox_add_tcp_relay(tox_.get(), node.ip.c_str(), node.port, node.public_key.data(),
                              &relay_err);
            return true;
        }

        return false;
    });
}

// ===========================================================================
// Identity
// ===========================================================================

ToxId ToxAdapter::get_address() const {
    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> ToxId {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        ToxIdArray addr{};
        tox_self_get_address(tox_.get(), addr.data());
        return ToxId::from_bytes_unchecked(addr);
    });
}

PublicKeyArray ToxAdapter::get_public_key() const {
    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> PublicKeyArray {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        PublicKeyArray pk{};
        tox_self_get_public_key(tox_.get(), pk.data());
        return pk;
    });
}

uint32_t ToxAdapter::get_nospam() const {
    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> uint32_t {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        return tox_self_get_nospam(tox_.get());
    });
}

void ToxAdapter::set_nospam(uint32_t nospam) {
    run_on_tox_thread([this, nospam]() {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        tox_self_set_nospam(tox_.get(), nospam);
    });
}

// ===========================================================================
// Friend management
// ===========================================================================

util::Expected<uint32_t, std::string> ToxAdapter::add_friend(const ToxId& tox_id,
                                                             std::string_view message) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    return run_on_tox_thread([&]() -> util::Expected<uint32_t, std::string> {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_ADD err;
        uint32_t friend_number =
            tox_friend_add(tox_.get(), tox_id.bytes().data(),
                           reinterpret_cast<const uint8_t*>(message.data()), message.size(), &err);

        if (err != TOX_ERR_FRIEND_ADD_OK) {
            return util::unexpected(std::string("failed to add friend: ") +
                                    friend_add_error_string(err));
        }

        // Persist the updated friend list. write_save_data_locked() assumes
        // the caller already holds tox_mutex_ (we do) and is on the Tox
        // thread (we are).
        (void)write_save_data_locked();

        util::Logger::info("Friend added: number={}, id={}", friend_number,
                           tox_id.public_key_hex().substr(0, 16) + "...");
        return util::Expected<uint32_t, std::string>(friend_number);
    });
}

util::Expected<uint32_t, std::string> ToxAdapter::add_friend_norequest(
    const PublicKeyArray& public_key) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    return run_on_tox_thread([&]() -> util::Expected<uint32_t, std::string> {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_ADD err;
        uint32_t friend_number = tox_friend_add_norequest(tox_.get(), public_key.data(), &err);

        if (err != TOX_ERR_FRIEND_ADD_OK) {
            return util::unexpected(std::string("failed to add friend (norequest): ") +
                                    friend_add_error_string(err));
        }

        (void)write_save_data_locked();

        util::Logger::info("Friend added (norequest): number={}", friend_number);
        return util::Expected<uint32_t, std::string>(friend_number);
    });
}

bool ToxAdapter::remove_friend(uint32_t friend_number) {
    if (!initialized_.load()) {
        return false;
    }

    return run_on_tox_thread([&]() -> bool {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_DELETE err;
        bool ok = tox_friend_delete(tox_.get(), friend_number, &err);

        if (ok && err == TOX_ERR_FRIEND_DELETE_OK) {
            (void)write_save_data_locked();
            util::Logger::info("Friend removed: number={}", friend_number);
            return true;
        }

        util::Logger::warn("Failed to remove friend {}: error {}", friend_number,
                           static_cast<int>(err));
        return false;
    });
}

bool ToxAdapter::is_friend_connected(uint32_t friend_number) const {
    return get_friend_connection_status(friend_number) != FriendState::None;
}

FriendState ToxAdapter::get_friend_connection_status(uint32_t friend_number) const {
    if (!initialized_.load()) {
        return FriendState::None;
    }

    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([&]() -> FriendState {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_QUERY err;
        TOX_CONNECTION conn = tox_friend_get_connection_status(tox_.get(), friend_number, &err);

        if (err != TOX_ERR_FRIEND_QUERY_OK) {
            return FriendState::None;
        }

        return connection_to_state(conn);
    });
}

util::Expected<PublicKeyArray, std::string> ToxAdapter::get_friend_public_key(
    uint32_t friend_number) const {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    return const_cast<ToxAdapter*>(this)->run_on_tox_thread(
        [&]() -> util::Expected<PublicKeyArray, std::string> {
            std::lock_guard<std::mutex> lock(tox_mutex_);

            PublicKeyArray pk{};
            TOX_ERR_FRIEND_GET_PUBLIC_KEY err;
            bool ok = tox_friend_get_public_key(tox_.get(), friend_number, pk.data(), &err);

            if (!ok || err != TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK) {
                return util::unexpected(std::string("failed to get public key for friend ") +
                                        std::to_string(friend_number));
            }

            return util::Expected<PublicKeyArray, std::string>(pk);
        });
}

util::Expected<uint32_t, std::string> ToxAdapter::friend_by_public_key(
    const PublicKeyArray& public_key) const {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    return const_cast<ToxAdapter*>(this)->run_on_tox_thread(
        [&]() -> util::Expected<uint32_t, std::string> {
            std::lock_guard<std::mutex> lock(tox_mutex_);

            TOX_ERR_FRIEND_BY_PUBLIC_KEY err;
            uint32_t friend_number = tox_friend_by_public_key(tox_.get(), public_key.data(), &err);

            if (err != TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
                return util::unexpected(std::string("friend not found for given public key"));
            }

            return util::Expected<uint32_t, std::string>(friend_number);
        });
}

std::vector<uint32_t> ToxAdapter::get_friend_list() const {
    if (!initialized_.load()) {
        return {};
    }

    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> std::vector<uint32_t> {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        std::size_t count = tox_self_get_friend_list_size(tox_.get());
        std::vector<uint32_t> list(count);
        if (count > 0) {
            tox_self_get_friend_list(tox_.get(), list.data());
        }
        return list;
    });
}

std::vector<FriendInfo> ToxAdapter::get_friend_info_list() const {
    if (!initialized_.load()) {
        return {};
    }

    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> std::vector<FriendInfo> {
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
    });
}

// ===========================================================================
// Data transfer
// ===========================================================================

ToxAdapter::LosslessSendOutcome ToxAdapter::send_lossless_packet_typed(uint32_t friend_number,
                                                                       const uint8_t* data,
                                                                       std::size_t length) {
    if (!initialized_.load() || !data || length == 0) {
        return LosslessSendOutcome::PermanentFail;
    }

    // Hot data path. The dominant caller is the Tox thread itself (the lossless
    // packet / friend-connection handlers run from run_loop() and call back
    // into send), which takes the inline fast path in run_on_tox_thread() — no
    // promise/future, no allocation. TCP I/O-thread callers marshal a single
    // closure across to the Tox thread and block on a future; that round-trip
    // is the unavoidable cost of toxcore's single-thread requirement.
    return run_on_tox_thread([&]() -> LosslessSendOutcome {
        TOX_ERR_FRIEND_CUSTOM_PACKET err;
        bool ok;
        {
            std::lock_guard<std::mutex> lock(tox_mutex_);
            ok = tox_friend_send_lossless_packet(tox_.get(), friend_number, data, length, &err);
        }

        if (ok && err == TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
            // Wake the iterate loop so the packet hits the network now rather
            // than at the next idle tick. Harmless no-op on the Tox thread.
            wake_cv_.notify_one();
            return LosslessSendOutcome::Sent;
        }

        // Rate-limited: a friend going offline turns this into a retry-loop
        // flood (measured: 952 lines / 20 s, ~48 Hz, from a loop that retries
        // with no backoff). Kept at debug rather than demoted to trace so the
        // failure is still visible at the level operators actually run, but
        // capped at one line per second — the suffix on that line carries how
        // many identical failures were folded into it.
        //
        // Bucketed by (friend, error code) rather than one throttle for the
        // whole site: those two fields are exactly what distinguishes one
        // failure from another here, and a single bucket let the loudest pair
        // eat the entire budget. With one offline friend spinning at ~48 Hz, a
        // *second* friend's first FRIEND_NOT_CONNECTED — or the same friend's
        // transition from SENDQ (transient, retried) to NOT_CONNECTED
        // (permanent, gives up) — was folded into a `[+N suppressed]` tally and
        // never printed, which is the one correlation an operator reads this
        // line to find. 64 buckets: the key space is friends × the 7 distinct
        // TOX_ERR_FRIEND_CUSTOM_PACKET values, and in practice only a couple of
        // error codes ever fire, so a server with a few dozen friends still
        // spreads thinly; a collision merely restores the old shared-budget
        // behaviour for that one pair. Cost is ~2.5 KiB of static atomics.
        static util::KeyedLogThrottle<64> send_fail_throttle{std::chrono::seconds(1)};
        util::Logger::debug_throttled(
            send_fail_throttle.for_key(util::log_key(friend_number, static_cast<uint32_t>(err))),
            "Send lossless packet failed for friend {}: error {}", friend_number,
            static_cast<int>(err));
        // SENDQ-full is the only error class we want callers to retry: toxcore's
        // outbound queue is bounded and drains as packets transit. Every other
        // error (NULL / EMPTY / INVALID / TOO_LONG / FRIEND_NOT_FOUND /
        // FRIEND_NOT_CONNECTED) is a permanent decision — retrying would just
        // burn CPU and, in the multi-server failover case, eventually replay
        // the frame on the *new* server when the old one stays offline.
        if (err == TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ) {
            return LosslessSendOutcome::SendqFull;
        }
        return LosslessSendOutcome::PermanentFail;
    });
}

bool ToxAdapter::send_lossless_packet(uint32_t friend_number, const uint8_t* data,
                                      std::size_t length) {
    return send_lossless_packet_typed(friend_number, data, length) == LosslessSendOutcome::Sent;
}

bool ToxAdapter::send_lossless_packet(uint32_t friend_number, const std::vector<uint8_t>& data) {
    return send_lossless_packet(friend_number, data.data(), data.size());
}

bool ToxAdapter::send_lossy_packet(uint32_t friend_number, const uint8_t* data,
                                   std::size_t length) {
    if (!initialized_.load() || !data || length == 0) {
        return false;
    }

    return run_on_tox_thread([&]() -> bool {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_CUSTOM_PACKET err;
        bool ok = tox_friend_send_lossy_packet(tox_.get(), friend_number, data, length, &err);
        if (ok) {
            wake_cv_.notify_one();
        }

        if (!ok || err != TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
            util::Logger::debug("Send lossy packet failed for friend {}: error {}", friend_number,
                                static_cast<int>(err));
            return false;
        }

        return true;
    });
}

util::Expected<uint32_t, std::string> ToxAdapter::send_message(uint32_t friend_number,
                                                               std::string_view message) {
    if (!initialized_.load()) {
        return util::unexpected(std::string("ToxAdapter not initialized"));
    }

    return run_on_tox_thread([&]() -> util::Expected<uint32_t, std::string> {
        std::lock_guard<std::mutex> lock(tox_mutex_);

        TOX_ERR_FRIEND_SEND_MESSAGE err;
        uint32_t msg_id = tox_friend_send_message(
            tox_.get(), friend_number, TOX_MESSAGE_TYPE_NORMAL,
            reinterpret_cast<const uint8_t*>(message.data()), message.size(), &err);

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

        return util::Expected<uint32_t, std::string>(msg_id);
    });
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
    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> uint32_t {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        return tox_iteration_interval(tox_.get());
    });
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

    // Publish the iterate-thread id so run_on_tox_thread() can detect
    // re-entrant calls (toxcore callbacks calling back into the public API)
    // and run them inline instead of self-deadlocking on a cross-thread post.
    iterate_thread_id_ = std::this_thread::get_id();
    iterate_thread_id_valid_.store(true, std::memory_order_release);

    // Phase reporting for the watchdog: cheap relaxed stores, so a stall
    // names the step it is stuck in instead of just "no heartbeat".
    const auto note_phase = [this](ToxWatchdog::Phase phase) {
        if (auto* wd = watchdog_.load(std::memory_order_acquire)) {
            wd->note_phase(phase);
        }
    };

    while (running_.load()) {
        uint32_t interval;
        {
            note_phase(ToxWatchdog::Phase::Iterate);
            std::lock_guard<std::mutex> lock(tox_mutex_);
            const auto iterate_start = std::chrono::steady_clock::now();
            tox_iterate(tox_.get(), this);
            // Watchdog heartbeat: bumped immediately on return so a hang
            // inside `tox_iterate` is detected by the main-thread observer.
            if (auto* wd = watchdog_.load(std::memory_order_acquire)) {
                wd->heartbeat();
            }
            // Feed the iterate-lag summary. This observation used to live only
            // in a second, never-instantiated Tox event loop (since deleted),
            // so toxtunnel_tox_iterate_lag_milliseconds_{count,sum,max} were
            // permanently 0 — and the alert rule documented in
            // docs/ADVANCED_SCENARIOS.md (`..._max > 100`) could never fire.
            // This is the loop that actually runs.
            util::MetricsRegistry::instance().observe_iterate_lag_ms(
                std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() -
                                                          iterate_start)
                    .count());
            interval = tox_iteration_interval(tox_.get());
        }

        // Execute any toxcore work posted from other threads. Runs outside the
        // tox_mutex_ lock above; each task re-acquires the mutex itself.
        note_phase(ToxWatchdog::Phase::Tasks);
        process_tox_tasks();

        note_phase(ToxWatchdog::Phase::Dispatch);
        dispatch_pending_events();

        // DHT-bootstrap retry while disconnected (issue #34). Cheap when
        // nothing is due; any toxcore call it makes takes tox_mutex_ itself.
        note_phase(ToxWatchdog::Phase::Maintenance);
        bootstrap_retry_tick();
        note_phase(ToxWatchdog::Phase::Idle);

        // tox_iteration_interval() returns up to ~50ms when idle. wake_cv_
        // already short-circuits the wait when we have outbound work, but
        // there is no equivalent signal for inbound network activity —
        // toxcore reads its sockets inside tox_iterate, so any inbound
        // friend packet sits unread until the next cycle. For an SSH-style
        // ping-pong both directions pay this cost, producing ~50ms per
        // round-trip even on localhost. Cap the idle wait so interactive
        // workloads stay snappy; iterate-when-idle is cheap (a few µs).
        constexpr uint32_t kMaxIdleIntervalMs = 5;
        if (interval > kMaxIdleIntervalMs) {
            interval = kMaxIdleIntervalMs;
        }

        std::unique_lock<std::mutex> wake_lock(wake_mutex_);
        wake_cv_.wait_for(wake_lock, std::chrono::milliseconds(interval), [this]() {
            std::lock_guard<std::mutex> task_lock(tox_tasks_mutex_);
            return !running_.load() || !tox_tasks_.empty();
        });
    }

    // Run any tasks posted during the final iteration so their futures resolve
    // before the iterate thread is gone (stop() also drains, but doing it here
    // keeps the common case off the joining thread).
    process_tox_tasks();

    iterate_thread_id_valid_.store(false, std::memory_order_release);
    util::Logger::debug("Tox iterate loop stopped");
}

bool ToxAdapter::on_tox_thread() const noexcept {
    return iterate_thread_id_valid_.load(std::memory_order_acquire) &&
           std::this_thread::get_id() == iterate_thread_id_;
}

void ToxAdapter::process_tox_tasks() {
    std::deque<std::function<void()>> local;
    {
        std::lock_guard<std::mutex> lock(tox_tasks_mutex_);
        if (tox_tasks_.empty()) {
            return;
        }
        local.swap(tox_tasks_);
    }
    for (auto& task : local) {
        task();
    }
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

    // Snapshot all callbacks once instead of relocking callback_mutex_ for every
    // event. With bursty inbound traffic (many TUNNEL_DATA frames per dispatch)
    // this avoids N mutex acquisitions per dispatch cycle.
    FriendRequestCallback on_friend_request;
    FriendConnectionCallback on_friend_connection;
    FriendLosslessPacketCallback on_lossless_packet;
    FriendLossyPacketCallback on_lossy_packet;
    FriendMessageCallback on_friend_message;
    SelfConnectionCallback on_self_connection;
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        on_friend_request = on_friend_request_;
        on_friend_connection = on_friend_connection_;
        on_lossless_packet = on_lossless_packet_;
        on_lossy_packet = on_lossy_packet_;
        on_friend_message = on_friend_message_;
        on_self_connection = on_self_connection_;
    }

    for (auto& event : events) {
        std::visit(
            [&](auto&& current) {
                using Event = std::decay_t<decltype(current)>;

                if constexpr (std::is_same_v<Event, FriendRequestEvent>) {
                    if (on_friend_request) {
                        on_friend_request(current.public_key, current.message);
                    }
                } else if constexpr (std::is_same_v<Event, FriendConnectionEvent>) {
                    if (on_friend_connection) {
                        on_friend_connection(current.friend_number, current.connected);
                    }
                } else if constexpr (std::is_same_v<Event, FriendLosslessPacketEvent>) {
                    if (on_lossless_packet) {
                        on_lossless_packet(current.friend_number, current.data.data(),
                                           current.data.size());
                    }
                } else if constexpr (std::is_same_v<Event, FriendLossyPacketEvent>) {
                    if (on_lossy_packet) {
                        on_lossy_packet(current.friend_number, current.data.data(),
                                        current.data.size());
                    }
                } else if constexpr (std::is_same_v<Event, FriendMessageEvent>) {
                    if (on_friend_message) {
                        on_friend_message(current.friend_number, current.message);
                    }
                } else if constexpr (std::is_same_v<Event, SelfConnectionEvent>) {
                    if (on_self_connection) {
                        on_self_connection(current.connected);
                    }
                }
            },
            event);
    }
}

// ===========================================================================
// Internal: save/load
// ===========================================================================

util::Expected<std::vector<uint8_t>, std::string> ToxAdapter::load_save_data() const {
    const auto path = save_file_path();
    if (path.empty()) {
        return std::vector<uint8_t>{};
    }

    // Only a regular, reasonably sized Tox save is valid here. This keeps a
    // directory or corrupt file at tox_save.dat from turning tellg() into a
    // huge allocation and crashing every startup.
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        return util::unexpected("could not inspect save file " + path.string() + ": " +
                                ec.message());
    }
    if (!exists) {
        return std::vector<uint8_t>{};
    }

    const bool is_regular = std::filesystem::is_regular_file(path, ec);
    if (ec) {
        return util::unexpected("could not inspect save file " + path.string() + ": " +
                                ec.message());
    }
    if (!is_regular) {
        // Deliberately NOT an error: v0.4.8 Linux packages left an empty
        // directory here (manylinux fs::path bug); continuing with a fresh
        // identity lets the next save self-heal via atomic_write_file's
        // empty-directory removal. A non-empty directory keeps failing the
        // save with a clear error instead.
        util::Logger::warn("Save file path is not a regular file; ignoring it: {}", path.string());
        return std::vector<uint8_t>{};
    }

    const std::uintmax_t file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return util::unexpected("could not stat save file " + path.string() + ": " + ec.message());
    }
    if (file_size == 0) {
        return std::vector<uint8_t>{};
    }

    constexpr std::uintmax_t kMaxSaveBytes = 64ULL * 1024 * 1024;  // 64 MiB
    if (file_size > kMaxSaveBytes) {
        return util::unexpected("save file is implausibly large (" + std::to_string(file_size) +
                                " bytes); refusing to overwrite it: " + path.string());
    }

    // `data_dir` is intentionally operator-selected local storage; save_filename
    // is validated as a plain filename before this path is constructed.
    // codeql[cpp/path-injection]
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        // Existing-but-unreadable is the print-id/service-account handoff
        // trap: the file was created by a different user (root, or an
        // Administrator on Windows) and the daemon account cannot read it.
        // Starting with a fresh identity here would silently orphan every
        // client configured with the old Tox ID — fail loudly instead.
        return util::unexpected(
            "save file " + path.string() +
            " exists but cannot be opened (permission denied?); refusing to create a fresh "
            "identity. Fix ownership so the daemon account can read it (e.g. chown to the "
            "service user), or remove the file to intentionally start a new identity");
    }

    auto size = file.tellg();
    if (size <= 0 || static_cast<std::uintmax_t>(size) != file_size) {
        return util::unexpected("could not read save file size: " + path.string());
    }

    std::vector<uint8_t> data(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

    if (!file) {
        return util::unexpected("failed to read save file: " + path.string());
    }

    return data;
}

bool ToxAdapter::write_save_data() const {
    // Route the toxcore read (tox_get_savedata*) onto the Tox thread and take
    // tox_mutex_ there. Previously these calls ran on the caller's thread with
    // no lock held when invoked via save(), violating toxcore's single-thread
    // requirement.
    return const_cast<ToxAdapter*>(this)->run_on_tox_thread([this]() -> bool {
        std::lock_guard<std::mutex> lock(tox_mutex_);
        return write_save_data_locked();
    });
}

bool ToxAdapter::write_save_data_locked() const {
    auto path = save_file_path();
    if (path.empty()) {
        return false;
    }

    std::size_t save_size = tox_get_savedata_size(tox_.get());
    std::vector<uint8_t> data(save_size);
    tox_get_savedata(tox_.get(), data.data());

    // The Tox identity is the most security-critical file we own; loss of it
    // breaks every existing tunnel forever, and a read by another local
    // user is an identity theft. Use the strongest durability setting
    // (parent-dir fsync + F_FULLFSYNC on macOS) AND tighten the file mode
    // to owner-only — the default 0644 from AtomicFileOptions is fine for
    // bootstrap caches but unacceptable for a private key. The inspect
    // socket is chmod 0600 for the same reason; the identity file ought to
    // be at least as restrictive.
    util::AtomicFileOptions opts{};
    opts.fsync_parent_dir = true;
    opts.use_full_fsync_macos = true;
    opts.mode = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;

    auto written = util::atomic_write_file(path, std::span<const std::uint8_t>(data), opts);
    if (!written) {
        util::Logger::error("Failed to atomically write save file {}: {}", path.string(),
                            written.error());
        return false;
    }

    util::Logger::trace("Tox state saved to {} ({} bytes)", path.string(), save_size);
    return true;
}

std::filesystem::path ToxAdapter::save_file_path() const {
    if (config_.data_dir.empty()) {
        return {};
    }
    if (!util::is_plain_filename(config_.save_filename)) {
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
    util::MetricsRegistry::instance().set_dht_connected(connected);

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
