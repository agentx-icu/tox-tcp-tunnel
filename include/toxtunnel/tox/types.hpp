#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tox {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a Tox public key in bytes.
inline constexpr std::size_t kPublicKeyBytes = 32;

/// Size of the nospam value in bytes.
inline constexpr std::size_t kNospamBytes = 4;

/// Size of the checksum in bytes.
inline constexpr std::size_t kChecksumBytes = 2;

/// Total size of a Tox ID in bytes (public key + nospam + checksum).
inline constexpr std::size_t kToxIdBytes = kPublicKeyBytes + kNospamBytes + kChecksumBytes;

/// Length of a hex-encoded Tox public key string.
inline constexpr std::size_t kPublicKeyHexLen = kPublicKeyBytes * 2;

/// Length of a hex-encoded Tox ID string (76 characters).
inline constexpr std::size_t kToxIdHexLen = kToxIdBytes * 2;

// ---------------------------------------------------------------------------
// Byte-array type aliases
// ---------------------------------------------------------------------------

using PublicKeyArray = std::array<uint8_t, kPublicKeyBytes>;
using ToxIdArray = std::array<uint8_t, kToxIdBytes>;

// ---------------------------------------------------------------------------
// ToxId
// ---------------------------------------------------------------------------

/// Represents a 38-byte (76-hex-character) Tox ID.
///
/// A Tox ID is composed of:
///   - 32-byte public key
///   -  4-byte nospam value
///   -  2-byte checksum
///
/// Typical usage:
/// @code
///   auto result = ToxId::from_hex("ABCDEF01...");
///   if (result) {
///       auto pk = result.value().public_key();
///       auto hex = result.value().to_hex();
///   }
/// @endcode
class ToxId {
   public:
    /// Parse a ToxId from a 76-character hexadecimal string.
    ///
    /// The string is case-insensitive.  Leading/trailing whitespace is **not**
    /// tolerated; the caller should trim first.
    ///
    /// @return The parsed ToxId on success, or an error description string.
    [[nodiscard]] static util::Expected<ToxId, std::string> from_hex(std::string_view hex);

    /// Construct a ToxId directly from a 38-byte array.
    ///
    /// @return The ToxId on success, or an error description if the checksum
    ///         is invalid.
    [[nodiscard]] static util::Expected<ToxId, std::string> from_bytes(const ToxIdArray& bytes);

    /// Construct a ToxId directly from raw bytes without validation.
    ///
    /// This is useful when the bytes are known to be valid (e.g. received
    /// directly from toxcore).
    [[nodiscard]] static ToxId from_bytes_unchecked(const ToxIdArray& bytes);

    /// Return the full 38-byte Tox ID.
    [[nodiscard]] const ToxIdArray& bytes() const noexcept { return bytes_; }

    /// Return the 32-byte public key portion.
    [[nodiscard]] PublicKeyArray public_key() const;

    /// Return the 4-byte nospam portion as a uint32_t (big-endian).
    [[nodiscard]] uint32_t nospam() const;

    /// Return the 2-byte checksum portion.
    [[nodiscard]] std::array<uint8_t, kChecksumBytes> checksum() const;

    /// Return the full Tox ID as an uppercase 76-character hex string.
    [[nodiscard]] std::string to_hex() const;

    /// Return the public key as an uppercase 64-character hex string.
    [[nodiscard]] std::string public_key_hex() const;

    /// Validate that the checksum matches the public key and nospam.
    [[nodiscard]] bool is_checksum_valid() const;

    // Comparison operators
    [[nodiscard]] bool operator==(const ToxId& other) const { return bytes_ == other.bytes_; }
    [[nodiscard]] bool operator!=(const ToxId& other) const { return bytes_ != other.bytes_; }
    [[nodiscard]] bool operator<(const ToxId& other) const { return bytes_ < other.bytes_; }

   private:
    /// Private constructor; use the static factory methods.
    explicit ToxId(const ToxIdArray& bytes) : bytes_(bytes) {}

    ToxIdArray bytes_{};
};

// ---------------------------------------------------------------------------
// BootstrapNode
// ---------------------------------------------------------------------------

/// Bootstrap resolution policy for discovering DHT entry points.
enum class BootstrapMode : uint8_t {
    Auto,  ///< Use configured nodes or fall back to public discovery/cache.
    Lan,   ///< Use local discovery and optional manually configured nodes only.
};

/// Represents a Tox DHT bootstrap node.
///
/// A bootstrap node is used to join the Tox DHT network and is specified by
/// its IP address, port, and public key.
///
/// Typical usage:
/// @code
///   auto result = BootstrapNode::parse("198.199.98.108:33445:ABCDEF01...");
///   if (result) {
///       auto& node = result.value();
///       // use node.ip, node.port, node.public_key
///   }
/// @endcode
struct BootstrapNode {
    /// IP address (IPv4 or IPv6) as a string.
    std::string ip;

    /// UDP port number.
    uint16_t port = 0;

    /// 32-byte public key of the bootstrap node.
    PublicKeyArray public_key{};

    /// Parse a bootstrap node from the string format:
    ///   "ip:port:hex_public_key"
    ///
    /// The public key must be a 64-character hex string.
    ///
    /// @return The parsed BootstrapNode on success, or an error string.
    [[nodiscard]] static util::Expected<BootstrapNode, std::string> parse(std::string_view str);

    /// Return the public key as an uppercase 64-character hex string.
    [[nodiscard]] std::string public_key_hex() const;

    /// Format the node back to "ip:port:hex_public_key".
    [[nodiscard]] std::string to_string() const;

    // Comparison operators
    [[nodiscard]] bool operator==(const BootstrapNode& other) const;
    [[nodiscard]] bool operator!=(const BootstrapNode& other) const;
};

// ---------------------------------------------------------------------------
// Free-function helpers
// ---------------------------------------------------------------------------

/// Convert a byte array to an uppercase hex string.
[[nodiscard]] std::string bytes_to_hex(const uint8_t* data, std::size_t len);

/// Convert a hex string to bytes.
///
/// @return true on success, false if the string contains invalid hex
///         characters or has an odd length.
[[nodiscard]] bool hex_to_bytes(std::string_view hex, uint8_t* out, std::size_t out_len);

/// Parse a 64-character hex string into a PublicKeyArray.
///
/// @return The parsed public key, or an error string.
[[nodiscard]] util::Expected<PublicKeyArray, std::string> parse_public_key(std::string_view hex);

}  // namespace toxtunnel::tox
