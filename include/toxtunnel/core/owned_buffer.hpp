#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace toxtunnel::core {

/// A zero-copy view over a heap-allocated byte buffer whose lifetime is
/// managed by a `shared_ptr`. The view is a (buffer, offset, length) triple:
/// the underlying buffer may be larger than the visible window, and multiple
/// `OwnedBufferView`s can share the same buffer with non-overlapping ranges.
///
/// The buffer survives for as long as any `OwnedBufferView` referencing it
/// (or its underlying `shared_ptr`) exists. This makes it safe to hand the
/// view to an async operation (e.g. `asio::async_write`) and capture the
/// `OwnedBufferView` in the completion handler — the bytes remain valid
/// until the handler runs.
///
/// This is the workhorse of the zero-copy inbound read path: payload bytes
/// allocated when a Tox lossless packet is deserialized are propagated all
/// the way to the TCP send queue without further copies; only the shared_ptr
/// refcount is bumped at each hand-off.
///
/// Empty / default-constructed `OwnedBufferView`s carry a null buffer pointer
/// and an empty `data()` span.
class OwnedBufferView {
   public:
    /// Construct an empty view (no underlying buffer).
    OwnedBufferView() = default;

    /// Construct a view spanning the entire buffer.
    explicit OwnedBufferView(std::shared_ptr<const std::vector<uint8_t>> buf)
        : buf_(std::move(buf)), offset_(0), length_(buf_ ? buf_->size() : 0) {}

    /// Construct a view over a sub-range of the buffer. The caller is
    /// responsible for ensuring `offset + length <= buf->size()`.
    OwnedBufferView(std::shared_ptr<const std::vector<uint8_t>> buf, std::size_t offset,
                    std::size_t length)
        : buf_(std::move(buf)), offset_(offset), length_(length) {}

    /// Return a span over the visible bytes. Valid for as long as this
    /// `OwnedBufferView` (or any copy of it) is alive.
    [[nodiscard]] std::span<const uint8_t> data() const noexcept {
        if (!buf_ || length_ == 0) {
            return {};
        }
        return std::span<const uint8_t>(buf_->data() + offset_, length_);
    }

    /// Number of visible bytes.
    [[nodiscard]] std::size_t size() const noexcept { return length_; }

    /// True when no buffer is held or the visible window is zero bytes.
    [[nodiscard]] bool empty() const noexcept { return length_ == 0 || !buf_; }

    /// Access the underlying `shared_ptr`. Mostly useful for tests that need
    /// to observe the refcount or capture the buffer's lifetime separately.
    [[nodiscard]] const std::shared_ptr<const std::vector<uint8_t>>& buffer() const noexcept {
        return buf_;
    }

    /// Offset of the visible window within the underlying buffer.
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

   private:
    std::shared_ptr<const std::vector<uint8_t>> buf_;
    std::size_t offset_{0};
    std::size_t length_{0};
};

}  // namespace toxtunnel::core
