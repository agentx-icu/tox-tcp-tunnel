#pragma once

#include <functional>
#include <string>

namespace toxtunnel::util {

/// Install a Windows service via the Service Control Manager.
/// Returns true on success, false on failure.
/// On non-Windows platforms, always returns false.
bool install_windows_service(const std::string& service_name, const std::string& display_name,
                             const std::string& binary_path);

/// Uninstall a Windows service.
/// Returns true on success, false on failure.
/// On non-Windows platforms, always returns false.
bool uninstall_windows_service(const std::string& service_name);

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
