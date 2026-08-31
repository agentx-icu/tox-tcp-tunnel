#pragma once

// SIGHUP / reload-IPC hot-reload helpers.
//
// The daemon's "reload" path re-reads the YAML from disk, validates it, and
// then applies the subset of fields the running process knows how to swap in
// at runtime. Anything outside that subset is rejected up-front with a clear
// error message — partial reloads would leave the daemon in a confusing state
// where some fields took effect and others silently didn't, so reload is
// strictly all-or-nothing.
//
// Reloadable subset (everything else requires a restart):
//   * server.rules_file        — the *content* of the file is re-read; the
//                                 path itself may change too.
//   * client.forwards          — listener set is diffed by
//                                 (effective local_address, local_port,
//                                 remote_host, remote_port). "Effective" means
//                                 an absent `local_address` and an explicit
//                                 `0.0.0.0` are the SAME rule: adding the key
//                                 to a forward that was already binding the
//                                 wildcard must not drop a live listener.
//                                 Changing it to a different address is a
//                                 different rule, and does stop and rebind.
//
//                                 FAILURE MODE WORTH KNOWING: that rebind is
//                                 stop-then-bind, not bind-then-stop. A new
//                                 address that parses but is not available on
//                                 this host (not assigned to an interface, or
//                                 the port is taken there) leaves that forward
//                                 DOWN — the old listener is already gone and
//                                 the new bind fails. Reload is best-effort
//                                 per forward, so the daemon and its other
//                                 forwards keep running, the failure is
//                                 reported, and a later reload retries it.
//                                 Tunnels already established through the old
//                                 listener are unaffected: they are accepted
//                                 connections, not listeners.
//   * logging.level            — forwarded straight to spdlog.
//
// `check_reloadable` is the gate. `diff_forwards` is the helper the client
// uses to compute the (add, remove) sets of forwarding rules.

#include <string>
#include <vector>

#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

/// Verify that `next` only differs from `current` in fields the daemon
/// supports hot-reloading. Returns void on success, or a human-readable
/// description naming the offending field on failure.
///
/// The caller is expected to call this *before* swapping in any state from
/// `next`; on error the running daemon must keep `current` untouched.
[[nodiscard]] Expected<void, std::string> check_reloadable(const Config& current,
                                                           const Config& next);

/// Sets of ForwardRules added vs removed between a current and new config.
///
/// Equality of two rules is "same EFFECTIVE local_address, same local_port,
/// same remote_host, same remote_port" — i.e. the natural key of a listener.
/// "Effective" means an absent `local_address` and an explicit `0.0.0.0` are
/// the same rule, so adding the key to a forward that already bound the
/// wildcard does not stop and rebind a live listener; a different address
/// does. Reordering the same set of rules in YAML produces an empty diff.
struct ForwardDiff {
    std::vector<ForwardRule> added;
    std::vector<ForwardRule> removed;

    [[nodiscard]] bool empty() const noexcept { return added.empty() && removed.empty(); }
};

/// Compute (added, removed) sets between two ForwardRule lists. Order of
/// elements in the input lists does not matter; the result is suitable for
/// driving listener teardown / setup.
[[nodiscard]] ForwardDiff diff_forwards(const std::vector<ForwardRule>& current,
                                        const std::vector<ForwardRule>& next);

}  // namespace toxtunnel::util
