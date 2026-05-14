#include "toxtunnel/tunnel/protocol.hpp"

#include <algorithm>
#include <cstring>

namespace toxtunnel::tunnel {

// ===========================================================================
// Byte-order helpers (portable, no platform headers required)
// ===========================================================================

namespace {

/// Write a uint16_t in big-endian (network) order into @p out.
/// @pre out must point to at least 2 writable bytes.
void write_u16_be(uint8_t* out, uint16_t value) noexcept {
    out[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(value & 0xFF);
}

/// Read a uint16_t from big-endian (network) order bytes.
/// @pre src must point to at least 2 readable bytes.
[[nodiscard]] uint16_t read_u16_be(const uint8_t* src) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(src[0]) << 8) | src[1]);
}

/// Write a uint32_t in big-endian (network) order into @p out.
/// @pre out must point to at least 4 writable bytes.
void write_u32_be(uint8_t* out, uint32_t value) noexcept {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(value & 0xFF);
}

/// Read a uint32_t from big-endian (network) order bytes.
/// @pre src must point to at least 4 readable bytes.
[[nodiscard]] uint32_t read_u32_be(const uint8_t* src) noexcept {
    return (static_cast<uint32_t>(src[0]) << 24) | (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) | static_cast<uint32_t>(src[3]);
}

/// Validate that a raw byte value corresponds to a known FrameType.
[[nodiscard]] bool is_valid_frame_type(uint8_t raw) noexcept {
    switch (static_cast<FrameType>(raw)) {
        case FrameType::TUNNEL_OPEN:
        case FrameType::TUNNEL_DATA:
        case FrameType::TUNNEL_CLOSE:
        case FrameType::TUNNEL_ACK:
        case FrameType::TUNNEL_ERROR:
        case FrameType::INFO_REQUEST:
        case FrameType::INFO_REPLY:
        case FrameType::PING:
        case FrameType::PONG:
            return true;
        default:
            return false;
    }
}

}  // anonymous namespace

// ===========================================================================
// to_string(FrameType)
// ===========================================================================

std::string_view to_string(FrameType type) noexcept {
    switch (type) {
        case FrameType::TUNNEL_OPEN:
            return "TUNNEL_OPEN";
        case FrameType::TUNNEL_DATA:
            return "TUNNEL_DATA";
        case FrameType::TUNNEL_CLOSE:
            return "TUNNEL_CLOSE";
        case FrameType::TUNNEL_ACK:
            return "TUNNEL_ACK";
        case FrameType::TUNNEL_ERROR:
            return "TUNNEL_ERROR";
        case FrameType::INFO_REQUEST:
            return "INFO_REQUEST";
        case FrameType::INFO_REPLY:
            return "INFO_REPLY";
        case FrameType::PING:
            return "PING";
        case FrameType::PONG:
            return "PONG";
        default:
            return "UNKNOWN";
    }
}

// ===========================================================================
// ProtocolFrame -- construction
// ===========================================================================

ProtocolFrame::ProtocolFrame(FrameType type, uint16_t tunnel_id)
    : type_(type), tunnel_id_(tunnel_id) {}

// ===========================================================================
// Factory methods
// ===========================================================================

ProtocolFrame ProtocolFrame::make_tunnel_open(uint16_t tunnel_id, const std::string& host,
                                              uint16_t port) {
    ProtocolFrame frame(FrameType::TUNNEL_OPEN, tunnel_id);

    // Payload: [host_len:1][host:host_len][port:2]
    auto host_len = static_cast<uint8_t>(std::min<std::size_t>(host.size(), 255));
    frame.payload_.reserve(1 + host_len + 2);

    frame.payload_.push_back(host_len);
    frame.payload_.insert(frame.payload_.end(), host.begin(), host.begin() + host_len);

    uint8_t port_buf[2];
    write_u16_be(port_buf, port);
    frame.payload_.push_back(port_buf[0]);
    frame.payload_.push_back(port_buf[1]);

    return frame;
}

ProtocolFrame ProtocolFrame::make_tunnel_data(uint16_t tunnel_id, std::span<const uint8_t> data) {
    ProtocolFrame frame(FrameType::TUNNEL_DATA, tunnel_id);
    frame.payload_.assign(data.begin(), data.end());
    return frame;
}

ProtocolFrame ProtocolFrame::make_tunnel_close(uint16_t tunnel_id) {
    return ProtocolFrame(FrameType::TUNNEL_CLOSE, tunnel_id);
}

ProtocolFrame ProtocolFrame::make_tunnel_ack(uint16_t tunnel_id, uint32_t bytes_acked) {
    ProtocolFrame frame(FrameType::TUNNEL_ACK, tunnel_id);

    // Payload: [bytes_acked:4]
    frame.payload_.resize(4);
    write_u32_be(frame.payload_.data(), bytes_acked);

    return frame;
}

ProtocolFrame ProtocolFrame::make_tunnel_error(uint16_t tunnel_id, uint8_t error_code,
                                               const std::string& description) {
    ProtocolFrame frame(FrameType::TUNNEL_ERROR, tunnel_id);

    // Payload: [error_code:1][description:N]
    frame.payload_.reserve(1 + description.size());
    frame.payload_.push_back(error_code);
    frame.payload_.insert(frame.payload_.end(), description.begin(), description.end());

    return frame;
}

ProtocolFrame ProtocolFrame::make_ping() {
    return ProtocolFrame(FrameType::PING, 0);
}

ProtocolFrame ProtocolFrame::make_pong() {
    return ProtocolFrame(FrameType::PONG, 0);
}

ProtocolFrame ProtocolFrame::make_info_request() {
    return ProtocolFrame(FrameType::INFO_REQUEST, 0);
}

ProtocolFrame ProtocolFrame::make_info_reply(std::string_view yaml_payload) {
    ProtocolFrame frame(FrameType::INFO_REPLY, 0);
    frame.payload_.assign(yaml_payload.begin(), yaml_payload.end());
    return frame;
}

std::string_view ProtocolFrame::as_info_reply_yaml() const {
    if (type_ != FrameType::INFO_REPLY)
        return {};
    return std::string_view(reinterpret_cast<const char*>(payload_.data()), payload_.size());
}

// ===========================================================================
// Serialization
// ===========================================================================

std::vector<uint8_t> ProtocolFrame::serialize() const {
    auto payload_len =
        static_cast<uint16_t>(std::min<std::size_t>(payload_.size(), kMaxPayloadSize));

    // One allocation + direct writes; previously a string of push_back/insert
    // calls re-walked the size guards each time. Hot path on every outbound
    // frame, so keep it tight.
    std::vector<uint8_t> result(kFrameHeaderSize + payload_len);
    result[0] = static_cast<uint8_t>(type_);
    write_u16_be(&result[1], tunnel_id_);
    write_u16_be(&result[3], payload_len);
    if (payload_len > 0) {
        std::memcpy(&result[kFrameHeaderSize], payload_.data(), payload_len);
    }
    return result;
}

util::Expected<ProtocolFrame, std::error_code> ProtocolFrame::deserialize(
    std::span<const uint8_t> data) {
    // Need at least the 5-byte header.
    if (data.size() < kFrameHeaderSize) {
        return util::unexpected(std::make_error_code(std::errc::message_size));
    }

    // [type:1]
    uint8_t raw_type = data[0];
    if (!is_valid_frame_type(raw_type)) {
        return util::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    auto type = static_cast<FrameType>(raw_type);

    // [tunnel_id:2] -- big-endian
    uint16_t tunnel_id = read_u16_be(&data[1]);

    // [length:2] -- big-endian
    uint16_t payload_len = read_u16_be(&data[3]);

    // Verify that the buffer actually contains the full payload.
    if (data.size() < kFrameHeaderSize + payload_len) {
        return util::unexpected(std::make_error_code(std::errc::message_size));
    }

    ProtocolFrame frame(type, tunnel_id);
    if (payload_len > 0) {
        frame.payload_.assign(data.begin() + kFrameHeaderSize,
                              data.begin() + kFrameHeaderSize + payload_len);
    }

    return frame;
}

// ===========================================================================
// Typed payload extraction
// ===========================================================================

std::optional<TunnelOpenPayload> ProtocolFrame::as_tunnel_open() const {
    if (type_ != FrameType::TUNNEL_OPEN || payload_.empty()) {
        return std::nullopt;
    }

    // Payload: [host_len:1][host:host_len][port:2]
    uint8_t host_len = payload_[0];
    std::size_t min_size = 1 + static_cast<std::size_t>(host_len) + 2;
    if (payload_.size() < min_size) {
        return std::nullopt;
    }

    TunnelOpenPayload result;
    result.host.assign(reinterpret_cast<const char*>(payload_.data() + 1), host_len);
    result.port = read_u16_be(payload_.data() + 1 + host_len);

    return result;
}

std::span<const uint8_t> ProtocolFrame::as_tunnel_data() const {
    if (type_ != FrameType::TUNNEL_DATA) {
        return {};
    }
    return payload_;
}

std::optional<TunnelAckPayload> ProtocolFrame::as_tunnel_ack() const {
    if (type_ != FrameType::TUNNEL_ACK || payload_.size() < 4) {
        return std::nullopt;
    }

    TunnelAckPayload result;
    result.bytes_acked = read_u32_be(payload_.data());
    return result;
}

std::optional<TunnelErrorPayload> ProtocolFrame::as_tunnel_error() const {
    if (type_ != FrameType::TUNNEL_ERROR || payload_.empty()) {
        return std::nullopt;
    }

    TunnelErrorPayload result;
    result.error_code = payload_[0];
    if (payload_.size() > 1) {
        result.description.assign(reinterpret_cast<const char*>(payload_.data() + 1),
                                  payload_.size() - 1);
    }
    return result;
}

}  // namespace toxtunnel::tunnel
