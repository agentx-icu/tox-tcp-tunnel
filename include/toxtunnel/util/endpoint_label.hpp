#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace toxtunnel {

/// Render `address:port` for logs, bracketing IPv6 so the boundary between
/// address and port is unambiguous (`[::1]:2222`, not `::1:2222`).
///
/// This lives in its own header rather than in `util/config.hpp` because the
/// TCP I/O layer needs it to describe a bound endpoint. `core/` may depend on
/// small `util/` helpers — it already takes `util/logger.hpp` — but it must not
/// depend on the configuration layer above it, and pulling in all of
/// `util/config.hpp` for ten lines of string formatting was exactly that
/// inversion.
[[nodiscard]] inline std::string format_endpoint_label(std::string_view address,
                                                       std::uint16_t port) {
    // An IPv6 literal is exactly the case where "addr:port" stops being
    // readable, because the address is full of colons itself.
    const bool is_v6 = address.find(':') != std::string_view::npos;
    std::string out;
    if (is_v6) {
        out = "[" + std::string(address) + "]";
    } else {
        out = std::string(address);
    }
    return out + ":" + std::to_string(port);
}

}  // namespace toxtunnel
