#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "toxtunnel/util/circular_buffer.hpp"

using toxtunnel::util::CircularBuffer;

// ============================================================================
// Test Fixture
// ============================================================================

class CircularBufferTest : public ::testing::Test {
   protected:
    CircularBuffer<int> buffer{5};  // Small capacity for testing
};

// ============================================================================
// 1. InitialState - verify empty buffer state
// ============================================================================

TEST_F(CircularBufferTest, InitialState_IsEmpty) {
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, InitialState_SizeIsZero) {
    EXPECT_EQ(buffer.size(), 0u);
}

TEST_F(CircularBufferTest, InitialState_NotFull) {
    EXPECT_FALSE(buffer.full());
}

TEST_F(CircularBufferTest, InitialState_CapacityIsCorrect) {
    EXPECT_EQ(buffer.capacity(), 5u);
}

TEST_F(CircularBufferTest, InitialState_ReadReturnsNullopt) {
    EXPECT_EQ(buffer.read(), std::nullopt);
}

TEST_F(CircularBufferTest, InitialState_PeekReturnsNullopt) {
    EXPECT_EQ(buffer.peek(), std::nullopt);
}

TEST_F(CircularBufferTest, InitialState_PeekWithIndexReturnsNullopt) {
    EXPECT_EQ(buffer.peek(0), std::nullopt);
    EXPECT_EQ(buffer.peek(1), std::nullopt);
}

// ============================================================================
// 2. WriteAndRead - write data, read it back
// ============================================================================

TEST_F(CircularBufferTest, WriteAndRead_SingleElement) {
    buffer.write(42);
    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(buffer.size(), 1u);

    auto value = buffer.read();
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 42);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, WriteAndRead_MultipleElements) {
    buffer.write(1);
    buffer.write(2);
    buffer.write(3);

    EXPECT_EQ(buffer.size(), 3u);

    EXPECT_EQ(buffer.read(), 1);
    EXPECT_EQ(buffer.read(), 2);
    EXPECT_EQ(buffer.read(), 3);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, WriteAndRead_MoveSemantics) {
    // Test with move-enabled write
    int value = 100;
    buffer.write(std::move(value));
    EXPECT_EQ(buffer.read(), 100);
}

TEST_F(CircularBufferTest, WriteAndRead_FIFOOrder) {
    // Verify First-In-First-Out ordering
    for (int i = 0; i < 3; ++i) {
        buffer.write(i);
    }

    for (int i = 0; i < 3; ++i) {
        auto value = buffer.read();
        ASSERT_TRUE(value.has_value());
        EXPECT_EQ(*value, i) << "FIFO order violated at index " << i;
    }
}

// ============================================================================
// 3. Wraparound - test circular behavior when write position wraps
// ============================================================================

TEST_F(CircularBufferTest, Wraparound_WriteWrapsAround) {
    // Fill buffer completely and read some elements
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }

    // Read first 2 elements
    EXPECT_EQ(buffer.read(), 0);
    EXPECT_EQ(buffer.read(), 1);

    // Now write more elements - these should wrap around
    buffer.write(100);
    buffer.write(101);

    // Read remaining in order: 2, 3, 4, 100, 101
    EXPECT_EQ(buffer.read(), 2);
    EXPECT_EQ(buffer.read(), 3);
    EXPECT_EQ(buffer.read(), 4);
    EXPECT_EQ(buffer.read(), 100);
    EXPECT_EQ(buffer.read(), 101);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, Wraparound_MultipleWraparounds) {
    // Perform multiple wraparound cycles
    for (int cycle = 0; cycle < 3; ++cycle) {
        // Fill buffer
        for (int i = 0; i < 5; ++i) {
            buffer.write(cycle * 10 + i);
        }
        EXPECT_TRUE(buffer.full());

        // Drain buffer
        for (int i = 0; i < 5; ++i) {
            auto value = buffer.read();
            ASSERT_TRUE(value.has_value());
            EXPECT_EQ(*value, cycle * 10 + i);
        }
        EXPECT_TRUE(buffer.empty());
    }
}

TEST_F(CircularBufferTest, Wraparound_ContinuousReadWrite) {
    // Interleaved read/write with wraparound
    for (int i = 0; i < 20; ++i) {
        buffer.write(i);
        auto value = buffer.read();
        ASSERT_TRUE(value.has_value());
        EXPECT_EQ(*value, i);
    }
    EXPECT_TRUE(buffer.empty());
}

// ============================================================================
// 4. PeekDoesNotConsume - peek should not modify buffer state
// ============================================================================

TEST_F(CircularBufferTest, PeekDoesNotConsume_SingleElement) {
    buffer.write(42);

    // Peek multiple times
    EXPECT_EQ(buffer.peek(), 42);
    EXPECT_EQ(buffer.peek(), 42);
    EXPECT_EQ(buffer.peek(), 42);

    // Size should be unchanged
    EXPECT_EQ(buffer.size(), 1u);

    // Read should still return the same value
    EXPECT_EQ(buffer.read(), 42);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, PeekDoesNotConsume_WithIndex) {
    buffer.write(10);
    buffer.write(20);
    buffer.write(30);

    // Peek at various indices
    EXPECT_EQ(buffer.peek(0), 10);
    EXPECT_EQ(buffer.peek(1), 20);
    EXPECT_EQ(buffer.peek(2), 30);

    // Size should be unchanged
    EXPECT_EQ(buffer.size(), 3u);

    // All elements should still be readable
    EXPECT_EQ(buffer.read(), 10);
    EXPECT_EQ(buffer.read(), 20);
    EXPECT_EQ(buffer.read(), 30);
}

TEST_F(CircularBufferTest, PeekDoesNotConsume_OutOfBoundsReturnsNullopt) {
    buffer.write(1);

    EXPECT_EQ(buffer.peek(0), 1);               // Valid
    EXPECT_EQ(buffer.peek(1), std::nullopt);    // Out of bounds
    EXPECT_EQ(buffer.peek(100), std::nullopt);  // Way out of bounds
}

TEST_F(CircularBufferTest, PeekDoesNotConsume_EmptyBuffer) {
    EXPECT_EQ(buffer.peek(), std::nullopt);
    EXPECT_EQ(buffer.peek(0), std::nullopt);
    EXPECT_TRUE(buffer.empty());
}

// ============================================================================
// 5. Clear - clear should reset buffer
// ============================================================================

TEST_F(CircularBufferTest, Clear_ResetsToEmpty) {
    buffer.write(1);
    buffer.write(2);
    buffer.write(3);

    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(buffer.size(), 3u);

    buffer.clear();

    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(buffer.read(), std::nullopt);
}

TEST_F(CircularBufferTest, Clear_CapacityUnchanged) {
    buffer.write(1);
    buffer.clear();
    EXPECT_EQ(buffer.capacity(), 5u);
}

TEST_F(CircularBufferTest, Clear_FullBufferCanBeRefilled) {
    // Fill to capacity
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }
    EXPECT_TRUE(buffer.full());

    buffer.clear();

    // Fill again
    for (int i = 0; i < 5; ++i) {
        buffer.write(i * 10);
    }
    EXPECT_TRUE(buffer.full());

    // Verify contents
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(buffer.read(), i * 10);
    }
}

TEST_F(CircularBufferTest, Clear_EmptyBufferIsStillEmpty) {
    EXPECT_TRUE(buffer.empty());
    buffer.clear();
    EXPECT_TRUE(buffer.empty());
}

// ============================================================================
// 6. FullBuffer - behavior when buffer is full
// ============================================================================

TEST_F(CircularBufferTest, FullBuffer_FullReturnsTrue) {
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }
    EXPECT_TRUE(buffer.full());
}

TEST_F(CircularBufferTest, FullBuffer_OverwriteOldest) {
    // Fill to capacity
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }
    EXPECT_TRUE(buffer.full());

    // Write one more - should overwrite oldest (0)
    buffer.write(100);

    // Size should still be at capacity
    EXPECT_EQ(buffer.size(), 5u);
    EXPECT_TRUE(buffer.full());

    // First element should be 1 (0 was overwritten)
    EXPECT_EQ(buffer.read(), 1);
    EXPECT_EQ(buffer.read(), 2);
    EXPECT_EQ(buffer.read(), 3);
    EXPECT_EQ(buffer.read(), 4);
    EXPECT_EQ(buffer.read(), 100);
}

TEST_F(CircularBufferTest, FullBuffer_MultipleOverwrites) {
    // Fill to capacity
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }

    // Overwrite all elements
    for (int i = 100; i < 105; ++i) {
        buffer.write(i);
    }

    // All original elements should be gone
    for (int i = 100; i < 105; ++i) {
        EXPECT_EQ(buffer.read(), i);
    }
    EXPECT_TRUE(buffer.empty());
}

TEST_F(CircularBufferTest, FullBuffer_PartialOverwrite) {
    // Fill to capacity
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }

    // Overwrite only 2 elements
    buffer.write(100);
    buffer.write(101);

    // Verify: 2, 3, 4, 100, 101
    EXPECT_EQ(buffer.read(), 2);
    EXPECT_EQ(buffer.read(), 3);
    EXPECT_EQ(buffer.read(), 4);
    EXPECT_EQ(buffer.read(), 100);
    EXPECT_EQ(buffer.read(), 101);
}

// ============================================================================
// 7. PartialWrite - write less than requested when buffer is nearly full
// (Note: The current CircularBuffer API doesn't have bulk write operations,
// but we can test the overwrite behavior)
// ============================================================================

TEST_F(CircularBufferTest, PartialWrite_NearlyFull) {
    // Fill buffer leaving one slot
    for (int i = 0; i < 4; ++i) {
        buffer.write(i);
    }

    EXPECT_EQ(buffer.size(), 4u);
    EXPECT_FALSE(buffer.full());

    // Write the last element
    buffer.write(4);
    EXPECT_TRUE(buffer.full());

    // Next write overwrites
    buffer.write(5);
    EXPECT_EQ(buffer.size(), 5u);

    // Verify FIFO order with overwrite
    EXPECT_EQ(buffer.read(), 1);
    EXPECT_EQ(buffer.read(), 2);
    EXPECT_EQ(buffer.read(), 3);
    EXPECT_EQ(buffer.read(), 4);
    EXPECT_EQ(buffer.read(), 5);
}

// ============================================================================
// 8. ThreadSafety - concurrent read/write
// ============================================================================

TEST_F(CircularBufferTest, ThreadSafety_ConcurrentWriteRead) {
    constexpr int num_items = 1000;
    CircularBuffer<int> thread_buffer{static_cast<std::size_t>(num_items)};

    // Writer thread
    std::thread writer([&thread_buffer]() {
        for (int i = 0; i < num_items; ++i) {
            thread_buffer.write(i);
        }
    });

    // Reader thread
    std::vector<int> read_values;
    std::thread reader([&thread_buffer, &read_values]() {
        int items_read = 0;
        while (items_read < num_items) {
            auto value = thread_buffer.read();
            if (value.has_value()) {
                read_values.push_back(*value);
                ++items_read;
            }
        }
    });

    writer.join();
    reader.join();

    // Verify all values were read
    EXPECT_EQ(read_values.size(), static_cast<size_t>(num_items));

    // Verify all values are present (may not be in order due to race conditions
    // but the buffer should maintain FIFO order per write sequence)
    // We can at least verify all values from 0 to num_items-1 are present
    std::vector<bool> found(num_items, false);
    for (int val : read_values) {
        if (val >= 0 && val < num_items) {
            found[val] = true;
        }
    }
    for (int i = 0; i < num_items; ++i) {
        EXPECT_TRUE(found[i]) << "Value " << i << " was not read";
    }
}

TEST_F(CircularBufferTest, ThreadSafety_MultipleWriters) {
    constexpr int items_per_thread = 500;
    constexpr int num_writers = 4;
    CircularBuffer<int> thread_buffer{static_cast<std::size_t>(items_per_thread * num_writers)};

    std::vector<std::thread> writers;
    for (int w = 0; w < num_writers; ++w) {
        writers.emplace_back([&thread_buffer, w]() {
            for (int i = 0; i < items_per_thread; ++i) {
                thread_buffer.write(w * items_per_thread + i);
            }
        });
    }

    // Read all items
    std::atomic<int> items_read{0};
    std::thread reader([&thread_buffer, &items_read]() {
        constexpr int total_items = items_per_thread * num_writers;
        while (items_read < total_items) {
            auto value = thread_buffer.read();
            if (value.has_value()) {
                ++items_read;
            }
        }
    });

    for (auto& w : writers) {
        w.join();
    }
    reader.join();

    EXPECT_EQ(items_read.load(), items_per_thread * num_writers);
}

TEST_F(CircularBufferTest, ThreadSafety_StressTest) {
    constexpr int num_operations = 10000;
    CircularBuffer<int> stress_buffer{static_cast<std::size_t>(num_operations)};
    std::atomic<int> writes_completed{0};
    std::atomic<int> reads_completed{0};

    std::thread writer1([&stress_buffer, &writes_completed]() {
        for (int i = 0; i < num_operations / 2; ++i) {
            stress_buffer.write(i);
            writes_completed++;
        }
    });

    std::thread writer2([&stress_buffer, &writes_completed]() {
        for (int i = num_operations / 2; i < num_operations; ++i) {
            stress_buffer.write(i);
            writes_completed++;
        }
    });

    std::thread reader1([&stress_buffer, &reads_completed]() {
        int count = 0;
        while (count < num_operations / 2) {
            if (stress_buffer.read().has_value()) {
                ++count;
                reads_completed++;
            }
        }
    });

    std::thread reader2([&stress_buffer, &reads_completed]() {
        int count = 0;
        while (count < num_operations / 2) {
            if (stress_buffer.read().has_value()) {
                ++count;
                reads_completed++;
            }
        }
    });

    writer1.join();
    writer2.join();
    reader1.join();
    reader2.join();

    EXPECT_EQ(writes_completed.load(), num_operations);
    EXPECT_EQ(reads_completed.load(), num_operations);
    EXPECT_TRUE(stress_buffer.empty());
}

// ============================================================================
// Additional Tests: Edge Cases
// ============================================================================

TEST_F(CircularBufferTest, EdgeCase_CapacityOne) {
    CircularBuffer<int> tiny_buffer{1};

    EXPECT_TRUE(tiny_buffer.empty());
    EXPECT_FALSE(tiny_buffer.full());

    tiny_buffer.write(42);
    EXPECT_TRUE(tiny_buffer.full());
    EXPECT_EQ(tiny_buffer.size(), 1u);

    // Overwrite
    tiny_buffer.write(100);
    EXPECT_TRUE(tiny_buffer.full());
    EXPECT_EQ(tiny_buffer.size(), 1u);

    // Should have the last written value
    EXPECT_EQ(tiny_buffer.read(), 100);
    EXPECT_TRUE(tiny_buffer.empty());
}

TEST_F(CircularBufferTest, EdgeCase_LargeCapacity) {
    CircularBuffer<int> large_buffer{10000};

    // Fill to capacity
    for (int i = 0; i < 10000; ++i) {
        large_buffer.write(i);
    }
    EXPECT_TRUE(large_buffer.full());

    // Verify all elements
    for (int i = 0; i < 10000; ++i) {
        auto value = large_buffer.read();
        ASSERT_TRUE(value.has_value());
        EXPECT_EQ(*value, i);
    }
    EXPECT_TRUE(large_buffer.empty());
}

// Test with non-trivial types
TEST(CircularBufferNonTrivialTest, WorksStdString) {
    CircularBuffer<std::string> str_buffer{3};

    str_buffer.write("hello");
    str_buffer.write("world");
    str_buffer.write("!");

    EXPECT_EQ(str_buffer.read(), "hello");
    EXPECT_EQ(str_buffer.read(), "world");
    EXPECT_EQ(str_buffer.read(), "!");
}

TEST(CircularBufferNonTrivialTest, WorksVector) {
    CircularBuffer<std::vector<int>> vec_buffer{3};

    vec_buffer.write({1, 2, 3});
    vec_buffer.write({4, 5, 6});
    vec_buffer.write({7, 8, 9});

    auto v1 = vec_buffer.read();
    ASSERT_TRUE(v1.has_value());
    EXPECT_EQ(*v1, (std::vector<int>{1, 2, 3}));

    auto v2 = vec_buffer.read();
    ASSERT_TRUE(v2.has_value());
    EXPECT_EQ(*v2, (std::vector<int>{4, 5, 6}));
}

// Test move operations - Note: CircularBuffer is non-movable due to std::mutex
// Move tests removed - class cannot be moved due to mutex member

// Test peek with wrapped buffer
TEST_F(CircularBufferTest, PeekWithIndex_WrappedBuffer) {
    // Fill and partially drain to create wrap situation
    for (int i = 0; i < 5; ++i) {
        buffer.write(i);
    }
    (void)buffer.read();  // Remove 0
    (void)buffer.read();  // Remove 1

    // Now add more elements that will wrap
    buffer.write(100);
    buffer.write(101);

    // Verify peek with index works correctly
    EXPECT_EQ(buffer.peek(0), 2);
    EXPECT_EQ(buffer.peek(1), 3);
    EXPECT_EQ(buffer.peek(2), 4);
    EXPECT_EQ(buffer.peek(3), 100);
    EXPECT_EQ(buffer.peek(4), 101);
    EXPECT_EQ(buffer.peek(5), std::nullopt);  // Out of bounds
}
