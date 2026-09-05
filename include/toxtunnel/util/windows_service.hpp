#pragma once

#include <functional>
#include <string>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

/// Human-readable reason the last install/uninstall failed, including the Win32
/// error code and, for the common cases, what to do about it. Empty on
/// non-Windows or when nothing has failed yet.
[[nodiscard]] std::string last_windows_service_error();

/// Install a Windows service via the Service Control Manager, or — when a
/// service of that name is already registered — update it in place (binary
/// path, auto-start, and the restart-on-failure recovery policy). Idempotent:
/// re-running it after an upgrade brings an old registration up to date.
/// @param extra_arguments Optional arguments appended after the quoted executable path
///                        (e.g. `-c "C:\\ProgramData\\ToxTunnel\\config.yaml" --service`).
/// Returns true on success, false on failure (see last_windows_service_error()).
/// On non-Windows platforms, always returns false.
bool install_windows_service(const std::string& service_name, const std::string& display_name,
                             const std::string& binary_path,
                             const std::string& extra_arguments = {});

/// True when the last successful install_windows_service() found the service
/// already registered and updated it rather than creating it.
[[nodiscard]] bool last_windows_service_install_updated_existing();

/// Make sure @p service_name carries the ToxTunnel recovery policy (restart on
/// failure, including non-crash error exits). Meant to be called by the daemon
/// itself at service start, so a registration made by an older build — or by
/// hand — repairs itself without anyone re-running the installer (issue #38).
/// Returns true if the policy was applied now, false if it was already
/// present, or an error string if the SCM could not be queried / updated
/// (the running account lacks SERVICE_CHANGE_CONFIG, say). Best-effort by
/// design: the caller logs the outcome and carries on either way.
/// On non-Windows platforms, always returns false.
[[nodiscard]] util::Expected<bool, std::string> ensure_windows_service_recovery_policy(
    const std::string& service_name);

/// Uninstall a Windows service.
/// Returns true on success, false on failure.
/// On non-Windows platforms, always returns false.
bool uninstall_windows_service(const std::string& service_name);

/// Install ToxTunnel using this executable with `-c <config> --service`.
[[nodiscard]] bool register_packaged_toxtunnel_service(const std::string& config_yaml_path);

/// Remove the ToxTunnel Windows service installed via register_packaged_toxtunnel_service.
[[nodiscard]] bool unregister_packaged_toxtunnel_service();

/// Check if the Windows service is being stopped.
/// Used by the application to check if it should exit.
bool is_windows_service_stopping();

/// Run the application as a Windows service.
///
/// This function connects to the Windows Service Control Manager and
/// runs the provided function as a service. If not running under SCM
/// (e.g., started from command line), it falls back to running directly.
///
/// On non-Windows platforms, simply calls run_fn directly.
///
/// @param service_name The internal name of the service
/// @param run_fn The main application function to run
/// @return Exit code (0 on success)
int run_windows_service_main(const std::string& service_name, const std::function<int()>& run_fn);

}  // namespace toxtunnel::util
