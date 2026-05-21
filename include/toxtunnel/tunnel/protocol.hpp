#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "toxtunnel/core/owned_buffer.hpp"
#include "toxtunnel/tunnel/owned_frame_buffer.hpp"
#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the fixed frame header: [type:1][tunnel_id:2][length:2].
inline constexpr std::size_t kFrameHeaderSize = 5;

/// Maximum payload length that can be expressed in the 2-byte length field.
inline constexpr std::size_t kMaxPayloadSize = 65535;

/// First byte prepended to every ProtocolFrame when sent as a toxcore lossless
/// custom packet. Toxcore reserves the 0xA0..0xFF range for application-defined
/// lossless packets; we use 0xA0 across client and server.
///
/// Wire-format convention (matters for any code touching the serialise/
/// deserialise pair — see C-16 in the 2026-05-20 review):
///
/// * `serialize()` returns the **5-byte tunnel header + payload**, WITHOUT
///   the 0xA0 lossless byte. Callers (TunnelServer / TunnelClient
///   `set_on_send_to_tox`) prepend `kLosslessPacketByte` before handing the
///   packet to `ToxAdapter::send_lossless_packet`.
///
/// * `serialize_tunnel_data_in_place()` writes the **0xA0 + 5-byte header**
///   directly into the OwnedFrameBuffer's reserved prefix so the zero-copy
///   outbound path can feed `wire_view()` straight to toxcore without an
///   extra allocation. This is the only function that emits 6 prefix bytes;
///   any other zero-copy call site must follow the same convention.
///
/// * `deserialize()` consumes the **5-byte tunnel header + payload**, with
///   no 0xA0 byte. Inbound callers (lossless-packet handlers in
///   TunnelServer / TunnelClient) skip `data[0]` (the lossless byte from
///   toxcore) before invoking deserialize.
inline constexpr uint8_t kLosslessPacketByte = 0xA0;

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
    /// Client → Server: ask the peer for system info (tunnel_id == 0,
    /// empty payload). Server replies with INFO_REPLY filtered by its
    /// `server.disclose.*` opt-in flags.
    INFO_REQUEST = 0x06,
    /// Server → Client response to INFO_REQUEST. tunnel_id == 0;
    /// payload is a small UTF-8 YAML map. An empty payload (`length == 0`)
    /// is valid and means "policy is to disclose nothing".
    INFO_REPLY = 0x07,
    /// Client → Server: request to fast-reattach a prior tunnel after a
    /// server restart. Carries the prior tunnel_id, target host:port, and
    /// the client-observed offsets. Feature-flag-gated by
    /// `tunnel.resume.enabled`; old servers ignore unknown opcodes and the
    /// client times out the resume attempt and falls back to TUNNEL_OPEN.
    TUNNEL_RESUME_REQUEST = 0x08,
    /// Server → Client response to TUNNEL_RESUME_REQUEST. Carries the new
    /// (or recycled) tunnel_id, server-side offsets, and a status byte.
    TUNNEL_RESUME_ACK = 0x09,
    PING = 0x10,  ///< Keep-alive request.
    PONG = 0x11,  ///< Keep-alive response.
};

// ---------------------------------------------------------------------------
// Tunnel-resume payload structs
// ---------------------------------------------------------------------------

/// Status codes for `TUNNEL_RESUME_ACK`.
enum class TunnelResumeStatus : std::uint8_t {
    Ok = 0,
    TargetUnreachable = 1,
    RulesDenied = 2,
    TooOld = 3,
    Unknown = 4,
};

/// Parsed payload for a TUNNEL_RESUME_REQUEST frame.
struct TunnelResumeRequestPayload {
    std::uint16_t prior_tunnel_id{0};
    std::uint64_t last_local_recv_offset{0};
    std::uint64_t last_local_send_offset{0};
    std::string host;
    std::uint16_t target_port{0};
};

/// Parsed payload for a TUNNEL_RESUME_ACK frame.
struct TunnelResumeAckPayload {
    std::uint16_t new_tunnel_id{0};
    std::uint64_t server_recv_offset{0};
    std::uint64_t server_send_offset{0};
    TunnelResumeStatus status{TunnelResumeStatus::Unknown};
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

    /// Create an INFO_REQUEST frame (tunnel_id is 0, empty payload).
    [[nodiscard]] static ProtocolFrame make_info_request();

    /// Create a TUNNEL_RESUME_REQUEST frame. The payload is binary
    /// (big-endian):
    ///   `[version:1=0x01][prior_id:2][recv:8][send:8][host_len:1][host:N][port:2]`
    [[nodiscard]] static ProtocolFrame make_tunnel_resume_request(
        const TunnelResumeRequestPayload& payload);

    /// Create a TUNNEL_RESUME_ACK frame.
    ///   `[version:1=0x01][new_id:2][server_recv:8][server_send:8][status:1]`
    [[nodiscard]] static ProtocolFrame make_tunnel_resume_ack(
        const TunnelResumeAckPayload& payload);

    /// Parse a TUNNEL_RESUME_REQUEST payload.
    [[nodiscard]] std::optional<TunnelResumeRequestPayload> as_tunnel_resume_request() const;

    /// Parse a TUNNEL_RESUME_ACK payload.
    [[nodiscard]] std::optional<TunnelResumeAckPayload> as_tunnel_resume_ack() const;

    /// Create an INFO_REPLY frame carrying a UTF-8 YAML payload (tunnel_id is 0).
    /// `yaml_payload` may be empty, signalling "no fields disclosed".
    [[nodiscard]] static ProtocolFrame make_info_reply(std::string_view yaml_payload);

    /// Convenience: when this is an INFO_REPLY, return the payload as a UTF-8
    /// string view over the underlying bytes. Empty if not INFO_REPLY.
    [[nodiscard]] std::string_view as_info_reply_yaml() const;

    // -----------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------

    /// Serialize the frame into a byte vector suitable for transmission.
    ///
    /// The returned buffer includes the 5-byte header followed by the
    /// payload.  All multi-byte integers are in network (big-endian) order.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Serialise a TUNNEL_DATA frame in place into a pre-allocated
    /// `OwnedFrameBuffer`.
    ///
    /// The buffer must already carry the payload bytes in its payload region
    /// (the TCP read path writes there directly). This call writes the 0xA0
    /// lossless byte plus the 5-byte tunnel frame header into the reserved
    /// prefix and returns a wire-ready view (`OwnedFrameBuffer::wire_view()`).
    /// The returned buffer's lifetime is governed entirely by the
    /// `OwnedFrameBuffer`'s shared allocation — once the async-send completion
    /// handler drops the last reference, the allocation goes away.
    ///
    /// **Wire-prefix convention** — see also `kLosslessPacketByte` doc. This
    /// function writes 6 bytes (0xA0 + 5-byte header); `serialize()` writes 5
    /// (no 0xA0). They are NOT round-trippable through `deserialize()`
    /// directly: zero-copy emitted bytes are consumed by toxcore, never by
    /// our own deserialize.
    static void serialize_tunnel_data_in_place(OwnedFrameBuffer& buf, uint16_t tunnel_id) noexcept;

    /// Deserialize a frame from a byte buffer.
    ///
    /// @param data  Buffer that must contain at least the 5-byte tunnel
    ///              header, **with the 0xA0 lossless byte already
    ///              stripped** (inbound callers slice `data + 1`).
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
    [[nodiscard]] std::span<const uint8_t> payload() const noexcept {
        if (payload_shared_) {
            return std::span<const uint8_t>(payload_shared_->data(), payload_shared_->size());
        }
        return payload_;
    }

    /// Return the total serialized size (header + payload).
    [[nodiscard]] std::size_t serialized_size() const noexcept {
        return kFrameHeaderSize + payload_size();
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

    /// Zero-copy view onto the TUNNEL_DATA payload backed by a `shared_ptr`.
    ///
    /// For frames produced by `deserialize()`, this returns the same buffer
    /// that holds the payload — handing the view onwards (e.g. to
    /// `TcpConnection::write(OwnedBufferView)`) avoids any additional payload
    /// copy. For frames built via factory methods such as `make_tunnel_data`,
    /// the payload was synthesized into an owned `vector<uint8_t>` and the
    /// returned view aliases it (one `shared_ptr` is allocated on demand).
    ///
    /// @return An owned view over the payload bytes, or an empty view if
    ///         this is not a TUNNEL_DATA frame.
    [[nodiscard]] core::OwnedBufferView as_tunnel_data_owned() const;

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
    [[nodiscard]] std::size_t payload_size() const noexcept {
        return payload_shared_ ? payload_shared_->size() : payload_.size();
    }

    FrameType type_;
    uint16_t tunnel_id_;
    std::vector<uint8_t> payload_;

    /// Optional shared-ownership wrapper around `payload_`, populated lazily
    /// (and only) by `deserialize()`. When present, `as_tunnel_data_owned()`
    /// returns a view directly onto this buffer — no additional payload copy
    /// is ever made on the inbound TUNNEL_DATA path. Outbound factory
    /// methods leave this null and fall back to `payload_`.
    std::shared_ptr<const std::vector<uint8_t>> payload_shared_;
};

}  // namespace toxtunnel::tunnel
