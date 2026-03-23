#include "toxtunnel/tox/types.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <sstream>

namespace toxtunnel::tox {

// ===========================================================================
// Hex conversion helpers
// ===========================================================================

namespace {

/// Map a single hex character to its 4-bit value, or -1 on error.
int hex_char_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

/// Compute the XOR checksum for a Tox ID.
///
/// The checksum is computed by XOR-ing the (public_key + nospam) bytes in
/// kChecksumBytes-wide blocks.
std::array<uint8_t, kChecksumBytes> compute_checksum(const uint8_t* data, std::size_t len) {
    std::array<uint8_t, kChecksumBytes> cs{};
    for (std::size_t i = 0; i < len; ++i) {
        cs[i % kChecksumBytes] ^= data[i];
    }
    return cs;
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// bytes_to_hex / hex_to_bytes
// ---------------------------------------------------------------------------

std::string bytes_to_hex(const uint8_t* data, std::size_t len) {
    static constexpr char kHexDigits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        result.push_back(kHexDigits[(data[i] >> 4) & 0x0F]);
        result.push_back(kHexDigits[data[i] & 0x0F]);
    }
    return result;
}

bool hex_to_bytes(std::string_view hex, uint8_t* out, std::size_t out_len) {
    if (hex.size() != out_len * 2) {
        return false;
    }
    for (std::size_t i = 0; i < out_len; ++i) {
        int hi = hex_char_value(hex[i * 2]);
        int lo = hex_char_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// ---------------------------------------------------------------------------
// parse_public_key
// ---------------------------------------------------------------------------

util::Expected<PublicKeyArray, std::string> parse_public_key(std::string_view hex) {
    if (hex.size() != kPublicKeyHexLen) {
        return util::unexpected(std::string("public key hex must be exactly ") +
                                std::to_string(kPublicKeyHexLen) + " characters, got " +
                                std::to_string(hex.size()));
    }

    PublicKeyArray pk{};
    if (!hex_to_bytes(hex, pk.data(), pk.size())) {
        return util::unexpected(std::string("public key contains invalid hex characters"));
    }
    return pk;
}

// ===========================================================================
// ToxId
// ===========================================================================

util::Expected<ToxId, std::string> ToxId::from_hex(std::string_view hex) {
    if (hex.size() != kToxIdHexLen) {
        return util::unexpected(std::string("Tox ID hex must be exactly ") +
                                std::to_string(kToxIdHexLen) + " characters, got " +
                                std::to_string(hex.size()));
    }

    ToxIdArray bytes{};
    if (!hex_to_bytes(hex, bytes.data(), bytes.size())) {
        return util::unexpected(std::string("Tox ID contains invalid hex characters"));
    }

    ToxId id(bytes);
    if (!id.is_checksum_valid()) {
        return util::unexpected(std::string("Tox ID checksum is invalid"));
    }

    return id;
}

util::Expected<ToxId, std::string> ToxId::from_bytes(const ToxIdArray& bytes) {
    ToxId id(bytes);
    if (!id.is_checksum_valid()) {
        return util::unexpected(std::string("Tox ID checksum is invalid"));
    }
    return id;
}

ToxId ToxId::from_bytes_unchecked(const ToxIdArray& bytes) {
    return ToxId(bytes);
}

PublicKeyArray ToxId::public_key() const {
    PublicKeyArray pk{};
    std::copy_n(bytes_.begin(), kPublicKeyBytes, pk.begin());
    return pk;
}

uint32_t ToxId::nospam() const {
    // Nospam is stored in big-endian order in bytes 32..35.
    uint32_t value = 0;
    value |= static_cast<uint32_t>(bytes_[kPublicKeyBytes + 0]) << 24;
    value |= static_cast<uint32_t>(bytes_[kPublicKeyBytes + 1]) << 16;
    value |= static_cast<uint32_t>(bytes_[kPublicKeyBytes + 2]) << 8;
    value |= static_cast<uint32_t>(bytes_[kPublicKeyBytes + 3]);
    return value;
}

std::array<uint8_t, kChecksumBytes> ToxId::checksum() const {
    std::array<uint8_t, kChecksumBytes> cs{};
    constexpr std::size_t offset = kPublicKeyBytes + kNospamBytes;
    std::copy_n(bytes_.begin() + offset, kChecksumBytes, cs.begin());
    return cs;
}

std::string ToxId::to_hex() const {
    return bytes_to_hex(bytes_.data(), bytes_.size());
}

std::string ToxId::public_key_hex() const {
    return bytes_to_hex(bytes_.data(), kPublicKeyBytes);
}

bool ToxId::is_checksum_valid() const {
    constexpr std::size_t payload_len = kPublicKeyBytes + kNospamBytes;
    auto expected = compute_checksum(bytes_.data(), payload_len);
    auto actual = checksum();
    return expected == actual;
}

// ===========================================================================
// BootstrapNode
// ===========================================================================

util::Expected<BootstrapNode, std::string> BootstrapNode::parse(std::string_view str) {
    // Expected format: "ip:port:hex_public_key"
    // For IPv6 addresses enclosed in brackets: "[::1]:port:hex_public_key"

    if (str.empty()) {
        return util::unexpected(std::string("bootstrap node string is empty"));
    }

    std::string_view remaining = str;
    std::string ip_part;
    std::string_view port_part;
    std::string_view key_part;

    // Handle IPv6 bracket notation: [addr]:port:key
    if (remaining.front() == '[') {
        auto bracket_end = remaining.find(']');
        if (bracket_end == std::string_view::npos) {
            return util::unexpected(std::string("unterminated '[' in IPv6 address"));
        }
        ip_part = std::string(remaining.substr(1, bracket_end - 1));
        remaining = remaining.substr(bracket_end + 1);

        // Expect ':' after ']'
        if (remaining.empty() || remaining.front() != ':') {
            return util::unexpected(std::string("expected ':' after IPv6 address bracket"));
        }
        remaining = remaining.substr(1);
    } else {
        // IPv4 or hostname: find the first ':'
        auto colon = remaining.find(':');
        if (colon == std::string_view::npos) {
            return util::unexpected(std::string("expected format 'ip:port:public_key'"));
        }
        ip_part = std::string(remaining.substr(0, colon));
        remaining = remaining.substr(colon + 1);
    }

    // Split remaining into port and public key
    auto colon = remaining.find(':');
    if (colon == std::string_view::npos) {
        return util::unexpected(std::string("expected format 'ip:port:public_key'"));
    }
    port_part = remaining.substr(0, colon);
    key_part = remaining.substr(colon + 1);

    // Validate IP is not empty
    if (ip_part.empty()) {
        return util::unexpected(std::string("IP address is empty"));
    }

    // Parse port
    uint16_t port = 0;
    auto [ptr, ec] = std::from_chars(port_part.data(), port_part.data() + port_part.size(), port);
    if (ec != std::errc{} || ptr != port_part.data() + port_part.size()) {
        return util::unexpected(std::string("invalid port number: ") + std::string(port_part));
    }
    if (port == 0) {
        return util::unexpected(std::string("port must be non-zero"));
    }

    // Parse public key
    auto pk_result = parse_public_key(key_part);
    if (!pk_result) {
        return util::unexpected(std::string("invalid bootstrap public key: ") + pk_result.error());
    }

    BootstrapNode node;
    node.ip = std::move(ip_part);
    node.port = port;
    node.public_key = pk_result.value();
    return node;
}

std::string BootstrapNode::public_key_hex() const {
    return bytes_to_hex(public_key.data(), public_key.size());
}

std::string BootstrapNode::to_string() const {
    // Use bracket notation for IPv6 addresses (heuristic: contains ':')
    std::string result;
    if (ip.find(':') != std::string::npos) {
        result = "[" + ip + "]";
    } else {
        result = ip;
    }
    result += ":" + std::to_string(port) + ":" + public_key_hex();
    return result;
}

bool BootstrapNode::operator==(const BootstrapNode& other) const {
    return ip == other.ip && port == other.port && public_key == other.public_key;
}

bool BootstrapNode::operator!=(const BootstrapNode& other) const {
    return !(*this == other);
}

}  // namespace toxtunnel::tox
