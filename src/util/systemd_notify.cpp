#include "toxtunnel/util/systemd_notify.hpp"

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#endif

namespace toxtunnel::util {

#if defined(__linux__)
namespace {

void notify_state(const char* state) {
    const char* socket_path = std::getenv("NOTIFY_SOCKET");
    if (!socket_path || socket_path[0] == '\0') {
        return;
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    socklen_t addr_len = 0;
    if (socket_path[0] == '@') {
        // Abstract socket: sun_path[0] is '\0', name follows without trailing '\0'
        addr.sun_path[0] = '\0';
        size_t name_len = std::strlen(socket_path + 1);
        if (name_len > sizeof(addr.sun_path) - 2) {
            name_len = sizeof(addr.sun_path) - 2;
        }
        std::memcpy(addr.sun_path + 1, socket_path + 1, name_len);
        addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_len);
    } else {
        std::strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
        addr_len = sizeof(addr);
    }

    const std::string payload = std::string(state) + "\n";
    (void)sendto(fd, payload.data(), payload.size(), 0, reinterpret_cast<const sockaddr*>(&addr),
                 addr_len);
    close(fd);
}

}  // namespace
#endif

void notify_service_ready() {
#if defined(__linux__)
    notify_state("READY=1");
#endif
}

void notify_service_stopping() {
#if defined(__linux__)
    notify_state("STOPPING=1");
#endif
}

}  // namespace toxtunnel::util
