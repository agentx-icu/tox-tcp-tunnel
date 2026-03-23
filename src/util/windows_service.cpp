#include "toxtunnel/util/windows_service.hpp"

#if defined(_WIN32)
#include <windows.h>

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace toxtunnel::util {
namespace {

// Global state for Windows service (guarded by being set before service start)
std::atomic<bool> g_service_stopping{false};
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
std::function<int()> g_run_fn;
std::string g_service_name;
std::wstring g_service_name_wide;
int g_service_exit_code = 0;

void set_service_status(DWORD current_state, DWORD win32_exit_code = NO_ERROR,
                        DWORD wait_hint = 0) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = current_state;
    status.dwControlsAccepted = (current_state == SERVICE_START_PENDING)
                                    ? 0
                                    : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = win32_exit_code;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = wait_hint;

    if (g_status_handle) {
        SetServiceStatus(g_status_handle, &status);
    }
}

VOID WINAPI service_control_handler(DWORD ctrl_code) {
    switch (ctrl_code) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_service_stopping.store(true);
            set_service_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            break;
        default:
            break;
    }
}

VOID WINAPI service_main(DWORD argc, LPWSTR* argv) {
    (void)argc;
    (void)argv;

    g_status_handle =
        RegisterServiceCtrlHandlerW(g_service_name_wide.c_str(), service_control_handler);

    if (!g_status_handle) {
        return;
    }

    set_service_status(SERVICE_START_PENDING);

    // Run the main function
    if (g_run_fn) {
        set_service_status(SERVICE_RUNNING);
        g_service_exit_code = g_run_fn();
    }

    set_service_status(SERVICE_STOPPED,
                       g_service_exit_code == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

// Convert UTF-8 string to wide string (Windows UTF-16)
std::wstring utf8_to_wide(const std::string& utf8) {
    if (utf8.empty()) {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size_needed <= 0) {
        return std::wstring();
    }

    std::wstring wide(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], size_needed);
    return wide;
}

}  // namespace
}  // namespace toxtunnel::util
#endif

namespace toxtunnel::util {

bool install_windows_service(const std::string& service_name, const std::string& display_name,
                             const std::string& binary_path) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return false;
    }

    SC_HANDLE service =
        CreateServiceA(scm, service_name.c_str(), display_name.c_str(), SERVICE_ALL_ACCESS,
                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                       binary_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
#else
    (void)service_name;
    (void)display_name;
    (void)binary_path;
    return false;
#endif
}

bool uninstall_windows_service(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceA(scm, service_name.c_str(), DELETE);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    const bool ok = DeleteService(service) != 0;
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
#else
    (void)service_name;
    return false;
#endif
}

bool is_windows_service_stopping() {
#if defined(_WIN32)
    return g_service_stopping.load();
#else
    return false;
#endif
}

int run_windows_service_main(const std::string& service_name, const std::function<int()>& run_fn) {
#if defined(_WIN32)
    // Store the run function and service name for the service main callback
    g_run_fn = run_fn;
    g_service_name = service_name;
    g_service_name_wide = utf8_to_wide(service_name);
    g_service_stopping.store(false);

    // Prepare the service table
    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(g_service_name_wide.c_str()),
         reinterpret_cast<LPSERVICE_MAIN_FUNCTIONW>(service_main)},
        {nullptr, nullptr}};

    // Try to connect to the service control manager
    // This will fail if we're not running as a service (e.g., debug mode)
    if (!StartServiceCtrlDispatcherW(service_table)) {
        // Not running as a service - run directly (for debugging)
        return run_fn ? run_fn() : 1;
    }

    return 0;
#else
    (void)service_name;
    return run_fn ? run_fn() : 1;
#endif
}

}  // namespace toxtunnel::util
