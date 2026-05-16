#pragma once

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace toxtunnel::tunnel {

// ---------------------------------------------------------------------------
// TunnelIdAllocator
// ---------------------------------------------------------------------------

/// Per-friend allocator for the 16-bit tunnel ID space.
///
/// IDs 1..65535 are usable; `0` is permanently reserved for control frames
/// (PING, PONG, INFO_REQUEST, INFO_REPLY). The allocator backs the in-use
/// set with a `std::bitset<65536>` plus a roving cursor for cache-friendly
/// allocation in the typical sparse-occupancy case.
///
/// Allocation is O(1) average; in the pathological "65534 in use" case it
/// is O(N) worst-case, which is well-bounded for a 65536-slot bitset.
///
/// Thread safety: all public methods acquire a single mutex. Used only on
/// control-plane operations (TUNNEL_OPEN / TUNNEL_CLOSE), so the mutex
/// contention is irrelevant compared to the data path.
class TunnelIdAllocator {
   public:
    /// Maximum valid tunnel ID (inclusive).
    static constexpr std::uint16_t kMaxId = 65535;
    /// Reserved control-frame ID.
    static constexpr std::uint16_t kReserved = 0;

    TunnelIdAllocator() {
        // Slot 0 is permanently in use so allocate() can never hand it out.
        used_.set(kReserved);
    }

    /// Allocate the next free ID. Returns `0` if the space is fully
    /// exhausted. Wraps around at `kMaxId`.
    [[nodiscard]] std::uint16_t allocate() {
        std::lock_guard<std::mutex> lock(mu_);
        // Cursor walks 1..kMaxId, wrapping once.
        for (std::size_t i = 0; i < static_cast<std::size_t>(kMaxId); ++i) {
            const std::uint16_t candidate = cursor_;
            if (cursor_ == kMaxId) {
                cursor_ = 1;
            } else {
                ++cursor_;
            }
            if (candidate == kReserved) {
                continue;
            }
            if (!used_.test(candidate)) {
                used_.set(candidate);
                ++in_use_;
                return candidate;
            }
        }
        return 0;
    }

    /// Release an ID back to the pool. Releasing `0` or an unallocated ID is
    /// a no-op (defensive — matches the existing ad-hoc allocator).
    void release(std::uint16_t id) {
        if (id == kReserved) {
            return;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (used_.test(id)) {
            used_.reset(id);
            --in_use_;
        }
    }

    /// Mark an ID as in-use without going through `allocate()`. Used during
    /// state recovery (tunnel resume) where the server-side ID is dictated
    /// by the client.
    bool reserve(std::uint16_t id) {
        if (id == kReserved) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (used_.test(id)) {
            return false;
        }
        used_.set(id);
        ++in_use_;
        return true;
    }

    [[nodiscard]] bool in_use(std::uint16_t id) const {
        std::lock_guard<std::mutex> lock(mu_);
        return used_.test(id);
    }

    [[nodiscard]] std::size_t in_use_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return in_use_;
    }

   private:
    mutable std::mutex mu_;
    std::bitset<static_cast<std::size_t>(kMaxId) + 1> used_;
    std::uint16_t cursor_ = 1;
    std::size_t in_use_ = 0;
};

}  // namespace toxtunnel::tunnel
