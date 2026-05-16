#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reserved prefix size at the front of every `OwnedFrameBuffer`. Carries the
/// 1-byte Tox lossless-packet byte (0xA0) plus the 5-byte tunnel frame header
/// (`[type:1][tunnel_id:2][length:2]`). Reserving these bytes in the same
/// allocation lets the outbound path serialise the wire format in place
/// without an extra copy or vector reallocation.
inline constexpr std::size_t kFrameHeaderReserved = 6;

/// Maximum number of payload bytes that can live in a single TUNNEL_DATA
/// frame. Mirrors `kMaxTcpPayloadPerToxFrame` in tunnel.cpp — kept local to
/// avoid pulling in the broader tunnel header just for one constant.
inline constexpr std::size_t kMaxFramePayload = 1367;

// ---------------------------------------------------------------------------
// OwnedFrameBuffer (Wave B outbound zero-copy)
// ---------------------------------------------------------------------------

/// Single-allocation outbound buffer carrying reserved header room at the
/// front and a payload window after it. The payload region is written by the
/// TCP read path and the prefix is filled in by
/// `ProtocolFrame::serialize_in_place()` when the frame is handed to the Tox
/// adapter — no separate header buffer is allocated, and no payload `memcpy`
/// happens between the TCP socket and the toxcore lossless call.
///
/// Memory layout (for a buffer with `payload_capacity == N`):
/// @code
///   [ kFrameHeaderReserved bytes prefix ][ N bytes payload region ]
///                                       ^
///                                       offset() == kFrameHeaderReserved
/// @endcode
///
/// `payload_used()` tracks how many of the N payload bytes have actually been
/// filled in; it is always `<= payload_capacity()` and starts at zero. The
/// outbound write coalescer is allowed to append more payload bytes in place
/// up to `payload_capacity` — this is the only legitimate mutation after
/// construction.
///
/// Lifetime is managed by a `shared_ptr<std::vector<uint8_t>>`. Async send
/// completion handlers keep a copy of the `OwnedFrameBuffer` alive until the
/// underlying toxcore call returns; the allocation is released only then.
///
/// `OwnedFrameBuffer` is copyable (cheap — bumps the shared refcount) and
/// movable; copies share the same underlying allocation. Mutating one copy's
/// payload mutates the others, so by convention only the producing thread
/// holds a non-const copy. Callers downstream of the producer should keep
/// it as `const`.
class OwnedFrameBuffer {
   public:
    /// Default-constructed buffer holds no allocation. Useful as an
    /// "empty / not-yet-built" sentinel.
    OwnedFrameBuffer() = default;

    /// Allocate a buffer big enough to carry `payload_capacity` payload bytes
    /// plus the reserved header prefix. The payload region starts empty
    /// (`payload_used() == 0`).
    static OwnedFrameBuffer allocate(std::size_t payload_capacity) {
        OwnedFrameBuffer buf;
        buf.storage_ =
            std::make_shared<std::vector<uint8_t>>(kFrameHeaderReserved + payload_capacity);
        buf.payload_capacity_ = payload_capacity;
        buf.payload_used_ = 0;
        return buf;
    }

    /// Allocate a buffer and populate the payload region with the given bytes.
    /// `payload.size()` becomes both the capacity and the used-size.
    static OwnedFrameBuffer with_payload(std::span<const std::uint8_t> payload) {
        auto buf = allocate(payload.size());
        if (!payload.empty()) {
            std::memcpy(buf.payload_data(), payload.data(), payload.size());
            buf.payload_used_ = payload.size();
        }
        return buf;
    }

    [[nodiscard]] bool empty() const noexcept { return !storage_; }

    [[nodiscard]] std::size_t payload_capacity() const noexcept { return payload_capacity_; }

    [[nodiscard]] std::size_t payload_used() const noexcept { return payload_used_; }

    [[nodiscard]] std::size_t payload_remaining() const noexcept {
        return payload_capacity_ - payload_used_;
    }

    /// Mutable pointer into the start of the payload region. Used by the TCP
    /// read path to write incoming bytes directly into the buffer.
    [[nodiscard]] std::uint8_t* payload_data() noexcept {
        return storage_ ? storage_->data() + kFrameHeaderReserved : nullptr;
    }

    [[nodiscard]] const std::uint8_t* payload_data() const noexcept {
        return storage_ ? storage_->data() + kFrameHeaderReserved : nullptr;
    }

    /// Mutable view over the currently-used payload bytes.
    [[nodiscard]] std::span<std::uint8_t> payload() noexcept {
        return {payload_data(), payload_used_};
    }

    /// Read-only view over the currently-used payload bytes.
    [[nodiscard]] std::span<const std::uint8_t> payload() const noexcept {
        return {payload_data(), payload_used_};
    }

    /// Mutable view over the *unused* tail of the payload region (capacity
    /// minus used). Used by coalescers to append to this buffer in place.
    [[nodiscard]] std::span<std::uint8_t> payload_tail() noexcept {
        return {payload_data() + payload_used_, payload_remaining()};
    }

    /// Mark `n` additional bytes of the payload region as used. The caller is
    /// responsible for ensuring `n <= payload_remaining()`. Returns the new
    /// `payload_used()`.
    std::size_t advance_payload(std::size_t n) noexcept {
        // Clamp instead of asserting so a fuzzed-input or buggy caller cannot
        // walk off the end of the allocation. The unit tests pin the contract
        // so legitimate callers never overflow.
        n = std::min(n, payload_remaining());
        payload_used_ += n;
        return payload_used_;
    }

    /// Set `payload_used()` directly. Intended for the path that reads
    /// directly into the payload buffer via async_read_some and learns the
    /// transferred length only in the completion handler. Clamped to capacity.
    void set_payload_used(std::size_t used) noexcept {
        payload_used_ = std::min(used, payload_capacity_);
    }

    /// Attempt to append `bytes` to the payload region in place. Returns the
    /// number of bytes actually appended (== `bytes.size()` on success, less
    /// or zero on overflow). The "less" case never occurs in practice because
    /// callers check `payload_remaining()` first; this is conservative.
    std::size_t append_payload(std::span<const std::uint8_t> bytes) noexcept {
        const auto take = std::min(bytes.size(), payload_remaining());
        if (take == 0) {
            return 0;
        }
        std::memcpy(payload_data() + payload_used_, bytes.data(), take);
        payload_used_ += take;
        return take;
    }

    /// Mutable pointer into the reserved header prefix. Used by
    /// `ProtocolFrame::serialize_in_place` to write the 0xA0 + 5-byte header
    /// without an extra allocation.
    [[nodiscard]] std::uint8_t* header_data() noexcept {
        return storage_ ? storage_->data() : nullptr;
    }

    [[nodiscard]] const std::uint8_t* header_data() const noexcept {
        return storage_ ? storage_->data() : nullptr;
    }

    /// Return a span over the full wire bytes (`header + payload`) suitable
    /// for handing to `ToxAdapter::send_custom_packet` once
    /// `serialize_in_place` has written the header.
    [[nodiscard]] std::span<const std::uint8_t> wire_view() const noexcept {
        if (!storage_) {
            return {};
        }
        return {storage_->data(), kFrameHeaderReserved + payload_used_};
    }

    /// Access to the underlying shared allocation. Lets callers extend buffer
    /// lifetime past `OwnedFrameBuffer` itself (e.g. async send completion
    /// handlers capturing only the `shared_ptr` instead of the wrapper).
    [[nodiscard]] const std::shared_ptr<std::vector<std::uint8_t>>& storage() const noexcept {
        return storage_;
    }

   private:
    std::shared_ptr<std::vector<std::uint8_t>> storage_;
    std::size_t payload_capacity_{0};
    std::size_t payload_used_{0};
};

}  // namespace toxtunnel::tunnel
