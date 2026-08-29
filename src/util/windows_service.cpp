#include "toxtunnel/util/windows_service.hpp"

#if defined(_WIN32)
#include <windows.h>

#include <atomic>
#include <functional>
#include <string>
#include <string_view>

namespace toxtunnel::util {
namespace {

#if defined(_WIN32)
/// Reason the last install/uninstall failed, so the CLI can say what actually
/// went wrong. "The service already exists" and "you are not an administrator"
/// need completely different fixes, and reporting both as "run as
/// Administrator" sends people down the wrong path.
std::string& last_service_error() {
    static std::string err;
    return err;
}

void set_last_service_error(std::string_view what, unsigned long code) {
    std::string msg(what);
    msg += " (error " + std::to_string(code);
    switch (code) {
        case ERROR_ACCESS_DENIED:
            msg += ": access denied — run from an elevated (Administrator) prompt";
            break;
        case ERROR_SERVICE_EXISTS:
            msg +=
                ": a service with this name is already registered — remove it first "
                "(`uninstall-windows-service`, or `sc delete ToxTunnel`)";
            break;
        case ERROR_SERVICE_MARKED_FOR_DELETE:
            msg += ": the previous service is still shutting down — retry in a moment";
            break;
        case ERROR_SERVICE_DOES_NOT_EXIST:
            msg += ": no such service is registered";
            break;
        default:
            break;
    }
    msg += ")";
    last_service_error() = std::move(msg);
}
#endif

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

    // size_needed includes the null terminator; allocate full buffer then resize
    std::wstring wide(static_cast<size_t>(size_needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], size_needed);
    wide.resize(static_cast<size_t>(size_needed - 1));  // trim null terminator
    return wide;
}

}  // namespace
}  // namespace toxtunnel::util
#endif

namespace toxtunnel::util {

bool install_windows_service(const std::string& service_name, const std::string& display_name,
                             const std::string& binary_path, const std::string& extra_arguments) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        set_last_service_error("OpenSCManager failed", GetLastError());
        return false;
    }

    std::string bin_line = std::string("\"") + binary_path + "\"";
    if (!extra_arguments.empty()) {
        bin_line += " ";
        bin_line += extra_arguments;
    }

    SC_HANDLE service =
        CreateServiceA(scm, service_name.c_str(), display_name.c_str(), SERVICE_ALL_ACCESS,
                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                       bin_line.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service) {
        set_last_service_error("CreateService failed", GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    // Configure recovery actions. Without them the SCM does nothing when the
    // daemon stops with an error, so a startup failure that a retry would fix
    // — most importantly "the data directory is still held by the previous
    // instance" during a restart — leaves the service simply stopped. systemd
    // (`Restart=on-failure`) and launchd (`KeepAlive{SuccessfulExit:false}`)
    // already retry; this gives Windows the same behaviour.
    //
    // SERVICE_CONFIG_FAILURE_ACTIONS_FLAG is required as well: by default the
    // SCM only counts a *crash* as a failure, not a clean exit reporting an
    // error code, which is exactly how this daemon reports one.
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 10'000;  // 10 s
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 30'000;  // 30 s
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 60'000;  // then every minute
    SERVICE_FAILURE_ACTIONSA failure_actions{};
    failure_actions.dwResetPeriod = 86'400;  // forget the failure count after a day
    failure_actions.lpRebootMsg = nullptr;
    failure_actions.lpCommand = nullptr;
    failure_actions.cActions = 3;
    failure_actions.lpsaActions = actions;
    // Best-effort: a service that runs but has no recovery policy is still far
    // better than failing the whole installation over it.
    (void)ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure_actions);

    SERVICE_FAILURE_ACTIONS_FLAG failure_flag{};
    failure_flag.fFailureActionsOnNonCrashFailures = TRUE;
    (void)ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failure_flag);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
#else
    (void)service_name;
    (void)display_name;
    (void)binary_path;
    (void)extra_arguments;
    return false;
#endif
}

bool uninstall_windows_service(const std::string& service_name) {
#if defined(_WIN32)
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        set_last_service_error("OpenSCManager failed", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceA(scm, service_name.c_str(), DELETE);
    if (!service) {
        set_last_service_error("OpenService failed", GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    const bool ok = DeleteService(service) != 0;
    if (!ok) {
        set_last_service_error("DeleteService failed", GetLastError());
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
#else
    (void)service_name;
    return false;
#endif
}

bool register_packaged_toxtunnel_service(const std::string& config_yaml_path) {
#if defined(_WIN32)
    char exe[MAX_PATH]{};
    if (GetModuleFileNameA(nullptr, exe, MAX_PATH) == 0) {
        return false;
    }
    std::string args = std::string("-c \"") + config_yaml_path + "\" --service";
    return install_windows_service("ToxTunnel", "ToxTunnel", exe, args);
#else
    (void)config_yaml_path;
    return false;
#endif
}

bool unregister_packaged_toxtunnel_service() {
#if defined(_WIN32)
    return uninstall_windows_service("ToxTunnel");
#else
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

std::string last_windows_service_error() {
#if defined(_WIN32)
    return last_service_error();
#else
    return {};
#endif
}

}  // namespace toxtunnel::util
