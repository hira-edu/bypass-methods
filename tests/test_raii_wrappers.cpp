#include <gtest/gtest.h>
#include "utils/raii_wrappers.h"
#include "utils/error_handler.h"
#include <memory>
#include <thread>
#include <chrono>

class RAIIWrappersTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize error handler for testing
        utils::ErrorHandler::Initialize();
    }
    
    void TearDown() override {
        // Cleanup error handler
        utils::ErrorHandler::Shutdown();
    }
};

// Test HandleWrapper
TEST_F(RAIIWrappersTest, HandleWrapperBasic) {
    // Test with invalid handle
    utils::HandleWrapper wrapper(INVALID_HANDLE_VALUE);
    EXPECT_FALSE(wrapper.is_valid());
    EXPECT_EQ(wrapper.get(), INVALID_HANDLE_VALUE);
    
    // Test move constructor
    utils::HandleWrapper wrapper2(std::move(wrapper));
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

TEST_F(RAIIWrappersTest, HandleWrapperValidHandle) {
    // Create a valid handle (event)
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    ASSERT_NE(event, INVALID_HANDLE_VALUE);
    
    {
        utils::HandleWrapper wrapper(event);
        EXPECT_TRUE(wrapper.is_valid());
        EXPECT_EQ(wrapper.get(), event);
        
        // Test release
        HANDLE released = wrapper.release();
        EXPECT_EQ(released, event);
        EXPECT_FALSE(wrapper.is_valid());
    }
    
    // Handle should be closed after wrapper goes out of scope
    // Note: We can't easily test this without more complex setup
}

// Test ModuleWrapper
TEST_F(RAIIWrappersTest, ModuleWrapperBasic) {
    // Test with null module
    utils::ModuleWrapper wrapper(nullptr);
    EXPECT_FALSE(wrapper.is_valid());
    EXPECT_EQ(wrapper.get(), nullptr);
    
    // Test move assignment
    utils::ModuleWrapper wrapper2(nullptr);
    wrapper2 = std::move(wrapper);
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test DeviceContextWrapper
TEST_F(RAIIWrappersTest, DeviceContextWrapperBasic) {
    // Test with null DC
    utils::DeviceContextWrapper wrapper(nullptr);
    EXPECT_FALSE(wrapper.is_valid());
    EXPECT_EQ(wrapper.get(), nullptr);
    
    // Test move constructor
    utils::DeviceContextWrapper wrapper2(std::move(wrapper));
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test VirtualMemoryWrapper
TEST_F(RAIIWrappersTest, VirtualMemoryWrapperBasic) {
    // Test with null address
    utils::VirtualMemoryWrapper wrapper(nullptr, 0);
    EXPECT_FALSE(wrapper.is_valid());
    EXPECT_EQ(wrapper.get(), nullptr);
    EXPECT_EQ(wrapper.size(), 0);
    
    // Test move assignment
    utils::VirtualMemoryWrapper wrapper2(nullptr, 0);
    wrapper2 = std::move(wrapper);
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test CriticalSectionWrapper
TEST_F(RAIIWrappersTest, CriticalSectionWrapperBasic) {
    utils::CriticalSectionWrapper wrapper;
    EXPECT_TRUE(wrapper.is_valid());
    
    // Test enter/leave
    wrapper.enter();
    wrapper.leave();
    
    // Test move constructor
    utils::CriticalSectionWrapper wrapper2(std::move(wrapper));
    EXPECT_TRUE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test MutexWrapper
TEST_F(RAIIWrappersTest, MutexWrapperBasic) {
    // Test with named mutex
    utils::MutexWrapper wrapper("TestMutex", false);
    EXPECT_TRUE(wrapper.is_valid());
    
    // Test wait (should succeed immediately for non-owned mutex)
    EXPECT_TRUE(wrapper.wait(100));
    
    // Test move assignment
    utils::MutexWrapper wrapper2("TestMutex2", false);
    wrapper2 = std::move(wrapper);
    EXPECT_TRUE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test EventWrapper
TEST_F(RAIIWrappersTest, EventWrapperBasic) {
    // Test with manual reset event
    utils::EventWrapper wrapper("TestEvent", true, false);
    EXPECT_TRUE(wrapper.is_valid());
    
    // Test wait (should timeout since event is not signaled)
    EXPECT_FALSE(wrapper.wait(100));
    
    // Test move constructor
    utils::EventWrapper wrapper2(std::move(wrapper));
    EXPECT_TRUE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test SemaphoreWrapper
TEST_F(RAIIWrappersTest, SemaphoreWrapperBasic) {
    // Test with semaphore
    utils::SemaphoreWrapper wrapper("TestSemaphore", 1, 1);
    EXPECT_TRUE(wrapper.is_valid());
    
    // Test wait (should succeed immediately)
    EXPECT_TRUE(wrapper.wait(100));
    
    // Test release
    EXPECT_TRUE(wrapper.release(1));
    
    // Test move assignment
    utils::SemaphoreWrapper wrapper2("TestSemaphore2", 1, 1);
    wrapper2 = std::move(wrapper);
    EXPECT_TRUE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test ThreadWrapper
TEST_F(RAIIWrappersTest, ThreadWrapperBasic) {
    bool thread_executed = false;
    
    auto thread_func = [&thread_executed]() -> DWORD {
        thread_executed = true;
        return 0;
    };
    
    utils::ThreadWrapper wrapper(thread_func, "TestThread");
    EXPECT_TRUE(wrapper.is_valid());
    
    // Wait for thread to complete
    EXPECT_TRUE(wrapper.wait(1000));
    EXPECT_TRUE(thread_executed);
    
    // Test move constructor
    utils::ThreadWrapper wrapper2(std::move(wrapper));
    EXPECT_TRUE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test FileMappingWrapper
TEST_F(RAIIWrappersTest, FileMappingWrapperBasic) {
    // Test with null file handle
    utils::FileMappingWrapper wrapper(INVALID_HANDLE_VALUE, "TestMapping");
    EXPECT_FALSE(wrapper.is_valid());
    
    // Test move assignment
    utils::FileMappingWrapper wrapper2(INVALID_HANDLE_VALUE, "TestMapping2");
    wrapper2 = std::move(wrapper);
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test FileMappingViewWrapper
TEST_F(RAIIWrappersTest, FileMappingViewWrapperBasic) {
    // Test with null mapping handle
    utils::FileMappingViewWrapper wrapper(INVALID_HANDLE_VALUE, "TestView");
    EXPECT_FALSE(wrapper.is_valid());
    
    // Test move constructor
    utils::FileMappingViewWrapper wrapper2(std::move(wrapper));
    EXPECT_FALSE(wrapper2.is_valid());
    EXPECT_FALSE(wrapper.is_valid());
}

// Test error handling utilities
TEST_F(RAIIWrappersTest, ErrorHandlingUtilities) {
    // Test get_last_error_message
    std::string error_msg = utils::handle_utils::get_last_error_message();
    EXPECT_FALSE(error_msg.empty());
    
    // Test get_system_error_message
    std::string sys_error = utils::handle_utils::get_system_error_message(ERROR_SUCCESS);
    EXPECT_FALSE(sys_error.empty());
    
    // Test is_valid_handle
    EXPECT_FALSE(utils::handle_utils::is_valid_handle(INVALID_HANDLE_VALUE));
    EXPECT_FALSE(utils::handle_utils::is_valid_handle(nullptr));
    
    // Test is_valid_module
    EXPECT_FALSE(utils::handle_utils::is_valid_module(nullptr));
    
    // Test is_valid_dc
    EXPECT_FALSE(utils::handle_utils::is_valid_dc(nullptr));
}

// Test thread safety
TEST_F(RAIIWrappersTest, ThreadSafety) {
    utils::CriticalSectionWrapper cs;
    std::atomic<int> counter{0};
    std::vector<std::thread> threads;
    
    // Create multiple threads that access the critical section
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&cs, &counter]() {
            for (int j = 0; j < 100; ++j) {
                cs.enter();
                int current = counter.load();
                std::this_thread::sleep_for(std::chrono::microseconds(1));
                counter.store(current + 1);
                cs.leave();
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Counter should be exactly 500 (5 threads * 100 iterations)
    EXPECT_EQ(counter.load(), 500);
}

// Test resource cleanup
TEST_F(RAIIWrappersTest, ResourceCleanup) {
    // Test that resources are properly cleaned up when wrappers go out of scope
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    ASSERT_NE(event, INVALID_HANDLE_VALUE);
    
    {
        utils::HandleWrapper wrapper(event);
        EXPECT_TRUE(wrapper.is_valid());
    } // Wrapper goes out of scope here
    
    // The event should be closed by the wrapper
    // We can't easily verify this without more complex setup, but the test
    // ensures no crashes occur during cleanup
}

// Test edge cases
TEST_F(RAIIWrappersTest, EdgeCases) {
    // Test double move
    utils::HandleWrapper wrapper1(INVALID_HANDLE_VALUE);
    utils::HandleWrapper wrapper2(INVALID_HANDLE_VALUE);
    
    wrapper2 = std::move(wrapper1);
    wrapper1 = std::move(wrapper2);
    
    EXPECT_FALSE(wrapper1.is_valid());
    EXPECT_FALSE(wrapper2.is_valid());
    
    // Test self-assignment
    utils::HandleWrapper wrapper3(INVALID_HANDLE_VALUE);
    wrapper3 = std::move(wrapper3);
    EXPECT_FALSE(wrapper3.is_valid());
}

// Test timeout scenarios
TEST_F(RAIIWrappersTest, TimeoutScenarios) {
    // Test mutex timeout
    utils::MutexWrapper mutex("TimeoutTestMutex", true); // Initial owner
    EXPECT_TRUE(mutex.is_valid());
    
    // Try to acquire from another wrapper (should timeout)
    utils::MutexWrapper mutex2("TimeoutTestMutex", false);
    EXPECT_FALSE(mutex2.wait(100)); // Should timeout
    
    // Test event timeout
    utils::EventWrapper event("TimeoutTestEvent", false, false);
    EXPECT_FALSE(event.wait(100)); // Should timeout
}

// Test performance characteristics
TEST_F(RAIIWrappersTest, PerformanceCharacteristics) {
    const int iterations = 1000;
    
    // Test critical section performance
    utils::CriticalSectionWrapper cs;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        cs.enter();
        cs.leave();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete in reasonable time (less than 1ms for 1000 iterations)
    EXPECT_LT(duration.count(), 1000);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 