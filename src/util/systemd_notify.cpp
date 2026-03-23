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
    if (socket_path[0] == '@') {
        addr.sun_path[0] = '\0';
        std::strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
    } else {
        std::strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    }

    const std::string payload = std::string(state) + "\n";
    (void)sendto(fd,
                 payload.data(),
                 payload.size(),
                 0,
                 reinterpret_cast<const sockaddr*>(&addr),
                 sizeof(addr));
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
