#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the fixed frame header: [type:1][tunnel_id:2][length:2].
inline constexpr std::size_t kFrameHeaderSize = 5;

/// Maximum payload length that can be expressed in the 2-byte length field.
inline constexpr std::size_t kMaxPayloadSize = 65535;

// ---------------------------------------------------------------------------
// FrameType
// ---------------------------------------------------------------------------

/// Identifies the kind of control or data message carried by a ProtocolFrame.
enum class FrameType : uint8_t {
    TUNNEL_OPEN = 0x01,   ///< Request to open a new tunnel to a host:port.
    TUNNEL_DATA = 0x02,   ///< Carry raw TCP payload for an existing tunnel.
    TUNNEL_CLOSE = 0x03,  ///< Gracefully close a tunnel.
    TUNNEL_ACK = 0x04,    ///< Acknowledge receipt of bytes (flow control).
    TUNNEL_ERROR = 0x05,  ///< Report an error associated with a tunnel.
    PING = 0x10,          ///< Keep-alive request.
    PONG = 0x11,          ///< Keep-alive response.
};

/// Return a human-readable label for a frame type, or "UNKNOWN" if the
/// value is not recognised.
[[nodiscard]] std::string_view to_string(FrameType type) noexcept;

// ---------------------------------------------------------------------------
// Payload structs
// ---------------------------------------------------------------------------

/// Parsed payload for a TUNNEL_OPEN frame.
struct TunnelOpenPayload {
    std::string host;  ///< Target hostname or IP address (max 255 bytes).
    uint16_t port{0};  ///< Target TCP port in host byte order.
};

/// Parsed payload for a TUNNEL_ACK frame.
struct TunnelAckPayload {
    uint32_t bytes_acked{0};  ///< Number of bytes being acknowledged.
};

/// Parsed payload for a TUNNEL_ERROR frame.
struct TunnelErrorPayload {
    uint8_t error_code{0};    ///< Application-defined error code.
    std::string description;  ///< Human-readable error description.
};

// ---------------------------------------------------------------------------
// ProtocolFrame
// ---------------------------------------------------------------------------

/// A single framed message in the toxtunnel binary protocol.
///
/// Wire format (all multi-byte integers are big-endian / network order):
/// @code
///   Offset  Size  Field
///   ------  ----  -----
///   0       1     type       (FrameType)
///   1       2     tunnel_id  (uint16_t, big-endian)
///   3       2     length     (uint16_t, big-endian, payload byte count)
///   5       N     payload    (variable, depends on frame type)
/// @endcode
///
/// Payload layouts per frame type:
///
/// - **TUNNEL_OPEN**: `[host_len:1][host:host_len][port:2]`
///   - `host_len` -- single byte, length of the hostname string (max 255).
///   - `host`     -- UTF-8 hostname / IP address.
///   - `port`     -- uint16_t, big-endian.
///
/// - **TUNNEL_DATA**: `[data:N]`
///   Raw tunnel data bytes (N == length field).
///
/// - **TUNNEL_CLOSE**: empty payload.
///
/// - **TUNNEL_ACK**: `[bytes_acked:4]`
///   uint32_t, big-endian.
///
/// - **TUNNEL_ERROR**: `[error_code:1][description:N-1]`
///   - `error_code`  -- single byte.
///   - `description` -- UTF-8 error message (remaining payload bytes).
///
/// - **PING / PONG**: empty payload, tunnel_id is 0.
///
/// Typical usage:
/// @code
///   // Create and serialize
///   auto frame = ProtocolFrame::make_tunnel_open(42, "localhost", 8080);
///   auto wire  = frame.serialize();
///
///   // Deserialize
///   auto result = ProtocolFrame::deserialize(wire);
///   if (result) {
///       auto open = result.value().as_tunnel_open();
///       // open->host == "localhost", open->port == 8080
///   }
/// @endcode
class ProtocolFrame {
   public:
    // -----------------------------------------------------------------
    // Construction (prefer the factory methods below)
    // -----------------------------------------------------------------

    /// Construct a frame with a given type and tunnel ID.
    /// The payload is initially empty.
    ProtocolFrame(FrameType type, uint16_t tunnel_id);

    // -----------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------

    /// Create a TUNNEL_OPEN frame.
    ///
    /// @param tunnel_id  Logical tunnel identifier.
    /// @param host       Target hostname or IP (truncated to 255 bytes).
    /// @param port       Target TCP port.
    [[nodiscard]] static ProtocolFrame make_tunnel_open(uint16_t tunnel_id, const std::string& host,
                                                        uint16_t port);

    /// Create a TUNNEL_DATA frame carrying raw bytes.
    ///
    /// @param tunnel_id  Logical tunnel identifier.
    /// @param data       Raw TCP payload to forward.
    [[nodiscard]] static ProtocolFrame make_tunnel_data(uint16_t tunnel_id,
                                                        std::span<const uint8_t> data);

    /// Create a TUNNEL_CLOSE frame.
    [[nodiscard]] static ProtocolFrame make_tunnel_close(uint16_t tunnel_id);

    /// Create a TUNNEL_ACK frame for flow-control acknowledgement.
    ///
    /// @param tunnel_id    Logical tunnel identifier.
    /// @param bytes_acked  Number of bytes being acknowledged.
    [[nodiscard]] static ProtocolFrame make_tunnel_ack(uint16_t tunnel_id, uint32_t bytes_acked);

    /// Create a TUNNEL_ERROR frame.
    ///
    /// @param tunnel_id    Logical tunnel identifier.
    /// @param error_code   Application-defined error code.
    /// @param description  Human-readable error message.
    [[nodiscard]] static ProtocolFrame make_tunnel_error(uint16_t tunnel_id, uint8_t error_code,
                                                         const std::string& description);

    /// Create a PING frame (tunnel_id is 0).
    [[nodiscard]] static ProtocolFrame make_ping();

    /// Create a PONG frame (tunnel_id is 0).
    [[nodiscard]] static ProtocolFrame make_pong();

    // -----------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------

    /// Serialize the frame into a byte vector suitable for transmission.
    ///
    /// The returned buffer includes the 5-byte header followed by the
    /// payload.  All multi-byte integers are in network (big-endian) order.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a frame from a byte buffer.
    ///
    /// @param data  Buffer that must contain at least the 5-byte header.
    ///              Extra trailing bytes after the frame are ignored.
    ///
    /// @return The parsed frame on success, or a `std::error_code` on
    ///         failure (e.g. buffer too short, unknown type).
    [[nodiscard]] static util::Expected<ProtocolFrame, std::error_code> deserialize(
        std::span<const uint8_t> data);

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the frame type.
    [[nodiscard]] FrameType type() const noexcept { return type_; }

    /// Return the tunnel identifier.
    [[nodiscard]] uint16_t tunnel_id() const noexcept { return tunnel_id_; }

    /// Return a read-only view of the raw payload bytes.
    [[nodiscard]] std::span<const uint8_t> payload() const noexcept { return payload_; }

    /// Return the total serialized size (header + payload).
    [[nodiscard]] std::size_t serialized_size() const noexcept {
        return kFrameHeaderSize + payload_.size();
    }

    // -----------------------------------------------------------------
    // Typed payload extraction
    // -----------------------------------------------------------------

    /// Parse the payload as a TUNNEL_OPEN message.
    ///
    /// @return The parsed payload, or `std::nullopt` if this is not a
    ///         TUNNEL_OPEN frame or the payload is malformed.
    [[nodiscard]] std::optional<TunnelOpenPayload> as_tunnel_open() const;

    /// Return the raw data payload for a TUNNEL_DATA frame.
    ///
    /// @return A span over the payload bytes, or an empty span if this
    ///         is not a TUNNEL_DATA frame.
    [[nodiscard]] std::span<const uint8_t> as_tunnel_data() const;

    /// Parse the payload as a TUNNEL_ACK message.
    ///
    /// @return The parsed payload, or `std::nullopt` if this is not a
    ///         TUNNEL_ACK frame or the payload is malformed.
    [[nodiscard]] std::optional<TunnelAckPayload> as_tunnel_ack() const;

    /// Parse the payload as a TUNNEL_ERROR message.
    ///
    /// @return The parsed payload, or `std::nullopt` if this is not a
    ///         TUNNEL_ERROR frame or the payload is malformed.
    [[nodiscard]] std::optional<TunnelErrorPayload> as_tunnel_error() const;

   private:
    FrameType type_;
    uint16_t tunnel_id_;
    std::vector<uint8_t> payload_;
};

}  // namespace toxtunnel::tunnel
