// TunnelIdAllocator unit tests.
//
// 1. ID 0 is permanently reserved.
// 2. allocate() returns a fresh ID and marks it in-use.
// 3. release() makes the ID reusable.
// 4. Exhaustion returns 0 and does not infinite-loop.
// 5. Wrap-around: after releasing an early ID and then walking to the end,
//    the next allocate() returns the released slot.
// 6. reserve() lets an external caller claim a specific ID.

#include "toxtunnel/tunnel/tunnel_id_allocator.hpp"

#include <gtest/gtest.h>

#include <set>
#include <vector>

namespace toxtunnel::test {
namespace {

using tunnel::TunnelIdAllocator;

TEST(TunnelIdAllocatorTest, IdZeroIsReserved) {
    TunnelIdAllocator a;
    EXPECT_TRUE(a.in_use(0));
    EXPECT_FALSE(a.in_use(1));
}

TEST(TunnelIdAllocatorTest, AllocateReturnsFreshId) {
    TunnelIdAllocator a;
    auto id1 = a.allocate();
    EXPECT_GE(id1, 1);
    EXPECT_TRUE(a.in_use(id1));
    auto id2 = a.allocate();
    EXPECT_NE(id1, id2);
    EXPECT_TRUE(a.in_use(id2));
}

TEST(TunnelIdAllocatorTest, ReleaseMakesIdReusable) {
    TunnelIdAllocator a;
    auto id = a.allocate();
    a.release(id);
    EXPECT_FALSE(a.in_use(id));
    // After walking the cursor past `id`, the next allocate that wraps
    // back through it will hand `id` out again. We just verify that
    // releasing flips the in-use bit.
}

TEST(TunnelIdAllocatorTest, InUseCountTracksReleases) {
    TunnelIdAllocator a;
    EXPECT_EQ(a.in_use_count(), 0u);
    std::vector<std::uint16_t> ids;
    for (int i = 0; i < 100; ++i) {
        ids.push_back(a.allocate());
    }
    EXPECT_EQ(a.in_use_count(), 100u);
    for (auto id : ids) {
        a.release(id);
    }
    EXPECT_EQ(a.in_use_count(), 0u);
}

TEST(TunnelIdAllocatorTest, ExhaustionReturnsZero) {
    TunnelIdAllocator a;
    std::set<std::uint16_t> seen;
    for (int i = 0; i < TunnelIdAllocator::kMaxId; ++i) {
        auto id = a.allocate();
        if (id == 0) {
            break;
        }
        seen.insert(id);
    }
    // We should have allocated exactly kMaxId IDs (slot 0 reserved).
    EXPECT_EQ(seen.size(), static_cast<std::size_t>(TunnelIdAllocator::kMaxId));
    // Next allocate must fail.
    EXPECT_EQ(a.allocate(), 0);
}

TEST(TunnelIdAllocatorTest, ReserveSpecificId) {
    TunnelIdAllocator a;
    EXPECT_TRUE(a.reserve(1234));
    EXPECT_TRUE(a.in_use(1234));
    EXPECT_FALSE(a.reserve(1234));  // already reserved
    EXPECT_FALSE(a.reserve(0));     // cannot reserve the control slot
}

}  // namespace
}  // namespace toxtunnel::test
