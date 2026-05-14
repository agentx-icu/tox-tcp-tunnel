#include "toxtunnel/util/system_info.hpp"

#include <yaml-cpp/yaml.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "toxtunnel/util/config.hpp"  // for ServerInfoDisclose

#if defined(_WIN32)
// clang-format off
// windows.h must come before sysinfoapi.h on some Windows SDK headers.
#include <windows.h>
#include <sysinfoapi.h>
// clang-format on
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/time.h>
#endif

#ifndef TOXTUNNEL_VERSION
#define TOXTUNNEL_VERSION "0.0.0-dev"
#endif

namespace toxtunnel::util {

namespace {

std::optional<std::string> get_hostname() {
#if defined(_WIN32)
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size)) {
        return std::string(buf, size);
    }
    return std::nullopt;
#else
    char buf[256];
    if (gethostname(buf, sizeof(buf)) != 0) {
        return std::nullopt;
    }
    buf[sizeof(buf) - 1] = '\0';
    return std::string(buf);
#endif
}

#if !defined(_WIN32)
std::optional<utsname> get_utsname() {
    utsname u{};
    if (uname(&u) != 0) {
        return std::nullopt;
    }
    return u;
}
#endif

std::optional<std::string> get_os_name() {
#if defined(_WIN32)
    return std::string("Windows");
#else
    auto u = get_utsname();
    if (!u)
        return std::nullopt;
    return std::string(u->sysname);
#endif
}

std::optional<std::string> get_os_version() {
#if defined(_WIN32)
    // GetVersionEx is deprecated and lies post-Win8.1; use the registry-style
    // ProductVersion via RtlGetVersion would need a separate kernel32 import.
    // For now, surface the OSVERSIONINFOEXW build number which is honest.
    OSVERSIONINFOEXW info{};
    info.dwOSVersionInfoSize = sizeof(info);
#pragma warning(push)
#pragma warning(disable : 4996)
    // GetVersionExW is officially deprecated but still functional and the
    // reported numbers match what `winver` shows for our needs.
    const BOOL ok = GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&info));
#pragma warning(pop)
    if (!ok) {
        return std::nullopt;
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu.%lu.%lu", static_cast<unsigned long>(info.dwMajorVersion),
                  static_cast<unsigned long>(info.dwMinorVersion),
                  static_cast<unsigned long>(info.dwBuildNumber));
    return std::string(buf);
#else
    auto u = get_utsname();
    if (!u)
        return std::nullopt;
    return std::string(u->release);
#endif
}

std::optional<std::string> get_arch() {
#if defined(_WIN32)
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return std::string("x86_64");
        case PROCESSOR_ARCHITECTURE_ARM64:
            return std::string("aarch64");
        case PROCESSOR_ARCHITECTURE_INTEL:
            return std::string("x86");
        case PROCESSOR_ARCHITECTURE_ARM:
            return std::string("arm");
        default:
            return std::string("unknown");
    }
#else
    auto u = get_utsname();
    if (!u)
        return std::nullopt;
    return std::string(u->machine);
#endif
}

std::optional<uint64_t> get_uptime_seconds() {
#if defined(_WIN32)
    return static_cast<uint64_t>(GetTickCount64() / 1000ULL);
#elif defined(__linux__)
    std::ifstream ifs("/proc/uptime");
    if (!ifs)
        return std::nullopt;
    double up = 0.0;
    if (!(ifs >> up))
        return std::nullopt;
    if (up < 0)
        return std::nullopt;
    return static_cast<uint64_t>(up);
#elif defined(__APPLE__)
    timeval boottime{};
    size_t size = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottime, &size, nullptr, 0) != 0 || boottime.tv_sec == 0) {
        return std::nullopt;
    }
    timeval now{};
    gettimeofday(&now, nullptr);
    if (now.tv_sec < boottime.tv_sec)
        return std::nullopt;
    return static_cast<uint64_t>(now.tv_sec - boottime.tv_sec);
#else
    return std::nullopt;
#endif
}

}  // namespace

SystemInfoSnapshot gather_system_info(const ServerInfoDisclose& policy) {
    SystemInfoSnapshot snap;
    if (policy.hostname)
        snap.hostname = get_hostname();
    if (policy.os)
        snap.os = get_os_name();
    if (policy.os_version)
        snap.os_version = get_os_version();
    if (policy.arch)
        snap.arch = get_arch();
    if (policy.uptime)
        snap.uptime_seconds = get_uptime_seconds();
    if (policy.toxtunnel_version)
        snap.toxtunnel_version = std::string(TOXTUNNEL_VERSION);
    return snap;
}

std::string snapshot_to_yaml(const SystemInfoSnapshot& snapshot) {
    YAML::Emitter out;
    out << YAML::BeginMap;
    if (snapshot.hostname)
        out << YAML::Key << "hostname" << YAML::Value << *snapshot.hostname;
    if (snapshot.os)
        out << YAML::Key << "os" << YAML::Value << *snapshot.os;
    if (snapshot.os_version) {
        out << YAML::Key << "os_version" << YAML::Value << *snapshot.os_version;
    }
    if (snapshot.arch)
        out << YAML::Key << "arch" << YAML::Value << *snapshot.arch;
    if (snapshot.uptime_seconds) {
        out << YAML::Key << "uptime_seconds" << YAML::Value << *snapshot.uptime_seconds;
    }
    if (snapshot.toxtunnel_version) {
        out << YAML::Key << "toxtunnel_version" << YAML::Value << *snapshot.toxtunnel_version;
    }
    out << YAML::EndMap;
    return std::string(out.c_str());
}

SystemInfoSnapshot snapshot_from_yaml(std::string_view yaml) {
    SystemInfoSnapshot snap;
    try {
        auto root = YAML::Load(std::string(yaml));
        if (!root.IsMap())
            return snap;
        if (root["hostname"])
            snap.hostname = root["hostname"].as<std::string>();
        if (root["os"])
            snap.os = root["os"].as<std::string>();
        if (root["os_version"])
            snap.os_version = root["os_version"].as<std::string>();
        if (root["arch"])
            snap.arch = root["arch"].as<std::string>();
        if (root["uptime_seconds"]) {
            snap.uptime_seconds = root["uptime_seconds"].as<uint64_t>();
        }
        if (root["toxtunnel_version"]) {
            snap.toxtunnel_version = root["toxtunnel_version"].as<std::string>();
        }
    } catch (const YAML::Exception&) {
        // Return whatever we managed to fill; caller treats nullopt fields as absent.
    }
    return snap;
}

}  // namespace toxtunnel::util
