#include <gtest/gtest.h>
#include "shared_memory_transport.h"
#include "frame_extractor.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>
#include <dxgiformat.h>

class SharedMemoryTransportTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize utility components for testing
        utils::ErrorHandler::Initialize();
        utils::PerformanceMonitor::Initialize();
        utils::MemoryTracker::Initialize();
    }
    
    void TearDown() override {
        // Shutdown utility components
        utils::MemoryTracker::Shutdown();
        utils::PerformanceMonitor::Shutdown();
        utils::ErrorHandler::Shutdown();
    }
};

// Test basic initialization and cleanup
TEST_F(SharedMemoryTransportTest, InitializationAndCleanup) {
    // Test that initialization works
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestTransport", 1024 * 1024);
    
    EXPECT_TRUE(transport->Initialize());
    
    // Test cleanup
    transport.reset();
    
    // Check that error handling worked correctly
    auto error_handler = utils::ErrorHandler::GetInstance();
    EXPECT_NE(error_handler, nullptr);
}

// Test error handling integration
TEST_F(SharedMemoryTransportTest, ErrorHandlingIntegration) {
    auto error_handler = utils::ErrorHandler::GetInstance();
    ASSERT_NE(error_handler, nullptr);
    
    // Test that error handler is properly initialized
    EXPECT_TRUE(error_handler->is_initialized());
    
    // Test error context functionality
    utils::ErrorContext context;
    context.set("test_key", "test_value");
    error_handler->set_error_context(context);
    
    // Verify context was set
    EXPECT_EQ(context.get("test_key"), "test_value");
    
    // Clear context
    error_handler->clear_error_context();
}

// Test performance monitoring integration
TEST_F(SharedMemoryTransportTest, PerformanceMonitoringIntegration) {
    auto perf_monitor = utils::PerformanceMonitor::GetInstance();
    ASSERT_NE(perf_monitor, nullptr);
    
    // Test that performance monitor is properly initialized
    EXPECT_TRUE(perf_monitor->is_initialized());
    
    // Test operation tracking
    auto operation_id = perf_monitor->start_operation("test_operation");
    EXPECT_NE(operation_id, 0);
    
    // Simulate some work
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // End operation
    perf_monitor->end_operation(operation_id);
    
    // Check that operation was tracked
    EXPECT_TRUE(perf_monitor->has_operation(operation_id));
}

// Test memory tracking integration
TEST_F(SharedMemoryTransportTest, MemoryTrackingIntegration) {
    auto memory_tracker = utils::MemoryTracker::GetInstance();
    ASSERT_NE(memory_tracker, nullptr);
    
    // Test that memory tracker is properly initialized
    EXPECT_TRUE(memory_tracker->is_initialized());
    
    // Test memory allocation tracking
    auto allocation_id = memory_tracker->track_allocation(
        "test_allocation", 1024, utils::MemoryCategory::SYSTEM
    );
    EXPECT_NE(allocation_id, 0);
    
    // Check that allocation is tracked
    EXPECT_TRUE(memory_tracker->has_allocation(allocation_id));
    
    // Release allocation
    memory_tracker->release_allocation(allocation_id);
    
    // Check that allocation is no longer tracked
    EXPECT_FALSE(memory_tracker->has_allocation(allocation_id));
}

// Test frame writing and reading
TEST_F(SharedMemoryTransportTest, FrameWriteAndRead) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestFrameTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Create test frame data
    UndownUnlock::DXHook::FrameData testFrame;
    testFrame.width = 1920;
    testFrame.height = 1080;
    testFrame.stride = 1920 * 4;
    testFrame.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    testFrame.timestamp = GetTickCount64();
    testFrame.sequence = 1;
    testFrame.data.resize(1920 * 1080 * 4, 0x42); // Fill with test data
    
    // Write frame
    EXPECT_TRUE(transport->WriteFrame(testFrame));
    
    // Read frame
    UndownUnlock::DXHook::FrameData readFrame;
    EXPECT_TRUE(transport->ReadFrame(readFrame));
    
    // Verify frame data
    EXPECT_EQ(readFrame.width, testFrame.width);
    EXPECT_EQ(readFrame.height, testFrame.height);
    EXPECT_EQ(readFrame.stride, testFrame.stride);
    EXPECT_EQ(readFrame.format, testFrame.format);
    EXPECT_EQ(readFrame.sequence, testFrame.sequence);
    EXPECT_EQ(readFrame.data.size(), testFrame.data.size());
    EXPECT_EQ(readFrame.data, testFrame.data);
}

// Test frame slot management
TEST_F(SharedMemoryTransportTest, FrameSlotManagement) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestSlotTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Test getting available frame slot
    uint32_t slot = transport->GetAvailableFrameSlot();
    EXPECT_NE(slot, UINT32_MAX);
    
    // Test getting next frame to read (should be none initially)
    uint32_t readSlot = transport->GetNextFrameToRead();
    EXPECT_EQ(readSlot, UINT32_MAX);
    
    // Test getting frame slot address
    void* address = transport->GetFrameSlotAddress(slot);
    EXPECT_NE(address, nullptr);
}

// Test lock management
TEST_F(SharedMemoryTransportTest, LockManagement) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestLockTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Test write lock
    EXPECT_TRUE(transport->AcquireWriteLock());
    transport->ReleaseWriteLock();
    
    // Test read lock
    EXPECT_TRUE(transport->AcquireReadLock());
    transport->ReleaseReadLock();
}

// Test event waiting
TEST_F(SharedMemoryTransportTest, EventWaiting) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestEventTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Test waiting for frame with timeout (should timeout since no frame written)
    EXPECT_FALSE(transport->WaitForFrame(100)); // 100ms timeout
}

// Test multiple transports
TEST_F(SharedMemoryTransportTest, MultipleTransports) {
    auto transport1 = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestMulti1", 1024 * 1024);
    auto transport2 = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestMulti2", 1024 * 1024);
    
    EXPECT_TRUE(transport1->Initialize());
    EXPECT_TRUE(transport2->Initialize());
    
    // Test that they can operate independently
    UndownUnlock::DXHook::FrameData testFrame;
    testFrame.width = 640;
    testFrame.height = 480;
    testFrame.stride = 640 * 4;
    testFrame.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    testFrame.timestamp = GetTickCount64();
    testFrame.sequence = 1;
    testFrame.data.resize(640 * 480 * 4, 0x42);
    
    EXPECT_TRUE(transport1->WriteFrame(testFrame));
    EXPECT_TRUE(transport2->WriteFrame(testFrame));
    
    UndownUnlock::DXHook::FrameData readFrame1, readFrame2;
    EXPECT_TRUE(transport1->ReadFrame(readFrame1));
    EXPECT_TRUE(transport2->ReadFrame(readFrame2));
}

// Test error conditions
TEST_F(SharedMemoryTransportTest, ErrorConditions) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestErrorTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Test writing frame that's too large
    UndownUnlock::DXHook::FrameData largeFrame;
    largeFrame.width = 4096;
    largeFrame.height = 4096;
    largeFrame.stride = 4096 * 4;
    largeFrame.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    largeFrame.timestamp = GetTickCount64();
    largeFrame.sequence = 1;
    largeFrame.data.resize(4096 * 4096 * 4, 0x42); // Very large frame
    
    EXPECT_FALSE(transport->WriteFrame(largeFrame));
}

// Test thread safety
TEST_F(SharedMemoryTransportTest, ThreadSafety) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestThreadTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    std::vector<std::thread> threads;
    std::atomic<int> write_count{0};
    std::atomic<int> read_count{0};
    
    // Create multiple threads that write and read frames
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&transport, i, &write_count, &read_count]() {
            // Write frame
            UndownUnlock::DXHook::FrameData testFrame;
            testFrame.width = 320;
            testFrame.height = 240;
            testFrame.stride = 320 * 4;
            testFrame.format = DXGI_FORMAT_B8G8R8A8_UNORM;
            testFrame.timestamp = GetTickCount64();
            testFrame.sequence = i;
            testFrame.data.resize(320 * 240 * 4, i);
            
            if (transport->WriteFrame(testFrame)) {
                write_count++;
            }
            
            // Read frame
            UndownUnlock::DXHook::FrameData readFrame;
            if (transport->ReadFrame(readFrame)) {
                read_count++;
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should have some successful operations
    EXPECT_GT(write_count.load(), 0);
    EXPECT_GT(read_count.load(), 0);
}

// Test performance characteristics
TEST_F(SharedMemoryTransportTest, PerformanceCharacteristics) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestPerfTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    auto perf_monitor = utils::PerformanceMonitor::GetInstance();
    
    // Test multiple write operations
    for (int i = 0; i < 10; ++i) {
        UndownUnlock::DXHook::FrameData testFrame;
        testFrame.width = 640;
        testFrame.height = 480;
        testFrame.stride = 640 * 4;
        testFrame.format = DXGI_FORMAT_B8G8R8A8_UNORM;
        testFrame.timestamp = GetTickCount64();
        testFrame.sequence = i;
        testFrame.data.resize(640 * 480 * 4, i);
        
        EXPECT_TRUE(transport->WriteFrame(testFrame));
    }
    
    // Get performance statistics
    auto stats = perf_monitor->get_performance_statistics();
    EXPECT_GE(stats.total_operations, 10);
}

// Test memory leak detection
TEST_F(SharedMemoryTransportTest, MemoryLeakDetection) {
    auto memory_tracker = utils::MemoryTracker::GetInstance();
    
    // Create some allocations
    auto alloc1 = memory_tracker->track_allocation("test1", 100, utils::MemoryCategory::SYSTEM);
    auto alloc2 = memory_tracker->track_allocation("test2", 200, utils::MemoryCategory::SYSTEM);
    
    // Release one allocation
    memory_tracker->release_allocation(alloc1);
    
    // Check for leaks
    EXPECT_TRUE(memory_tracker->has_leaks());
    
    // Release the other allocation
    memory_tracker->release_allocation(alloc2);
    
    // Should be no leaks now
    EXPECT_FALSE(memory_tracker->has_leaks());
}

// Test error recovery strategies
TEST_F(SharedMemoryTransportTest, ErrorRecoveryStrategies) {
    auto error_handler = utils::ErrorHandler::GetInstance();
    
    // Test different recovery strategies
    error_handler->error("Automatic recovery test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::AUTOMATIC);
    
    error_handler->error("Manual recovery test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::MANUAL);
    
    error_handler->error("Fatal error test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::FATAL);
}

// Test buffer resizing (not implemented)
TEST_F(SharedMemoryTransportTest, BufferResizing) {
    auto transport = std::make_unique<UndownUnlock::DXHook::SharedMemoryTransport>("TestResizeTransport", 1024 * 1024);
    ASSERT_TRUE(transport->Initialize());
    
    // Test resize buffer (should return false as not implemented)
    EXPECT_FALSE(transport->ResizeBuffer(2048 * 1024));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 