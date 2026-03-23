#pragma once

#include <string>
#include <string_view>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::util {

// Generates a terminal-friendly QR code using Unicode block characters.
[[nodiscard]] Expected<std::string, std::string> generate_qr_terminal(std::string_view text,
                                                                       bool use_color = false);

}  // namespace toxtunnel::util
