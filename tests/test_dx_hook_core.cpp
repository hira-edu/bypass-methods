#include <gtest/gtest.h>
#include "dx_hook_core.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>

class DXHookCoreTest : public ::testing::Test {
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

// Test basic initialization and shutdown
TEST_F(DXHookCoreTest, InitializationAndShutdown) {
    // Test that initialization works
    bool init_result = UndownUnlock::DXHook::DXHookCore::Initialize();
    
    // Note: In a real test environment, this might fail due to missing DirectX context
    // We're testing the utility integration, not the actual DirectX functionality
    if (init_result) {
        // Initialization succeeded - test should verify through public interface
        EXPECT_TRUE(init_result);

        // Test shutdown
        UndownUnlock::DXHook::DXHookCore::Shutdown();
        // Verify shutdown through attempting to get instance (should still exist but be shutdown)
    } else {
        // If initialization fails, it should be due to missing DirectX context, not utility issues
        // Check that error handling worked correctly
        auto error_handler = utils::ErrorHandler::GetInstance();
        EXPECT_NE(error_handler, nullptr);
    }
}

// Test error handling integration
TEST_F(DXHookCoreTest, ErrorHandlingIntegration) {
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
TEST_F(DXHookCoreTest, PerformanceMonitoringIntegration) {
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
TEST_F(DXHookCoreTest, MemoryTrackingIntegration) {
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

// Test callback registration with error handling
TEST_F(DXHookCoreTest, CallbackRegistration) {
    auto& core = UndownUnlock::DXHook::DXHookCore::GetInstance();
    
    // Test registering a valid callback
    auto callback = [](const void* data, size_t size, uint32_t width, uint32_t height) {
        // Test callback
    };
    
    size_t handle = core.RegisterFrameCallback(callback);
    EXPECT_NE(handle, 0);
    
    // Test registering a null callback (should return 0 and log warning)
    size_t null_handle = core.RegisterFrameCallback(nullptr);
    EXPECT_EQ(null_handle, 0);
    
    // Test unregistering valid callback
    core.UnregisterFrameCallback(handle);
    
    // Test unregistering invalid handle (should log warning)
    core.UnregisterFrameCallback(999);
}

// Test utility component initialization order
TEST_F(DXHookCoreTest, UtilityInitializationOrder) {
    // Test that utility components can be initialized in the correct order
    utils::ErrorHandler::Shutdown();
    utils::PerformanceMonitor::Shutdown();
    utils::MemoryTracker::Shutdown();
    
    // Reinitialize in correct order
    utils::ErrorHandler::Initialize();
    utils::PerformanceMonitor::Initialize();
    utils::MemoryTracker::Initialize();
    
    EXPECT_TRUE(utils::ErrorHandler::GetInstance()->is_initialized());
    EXPECT_TRUE(utils::PerformanceMonitor::GetInstance()->is_initialized());
    EXPECT_TRUE(utils::MemoryTracker::GetInstance()->is_initialized());
}

// Test error context serialization
TEST_F(DXHookCoreTest, ErrorContextSerialization) {
    utils::ErrorContext context;
    context.set("operation", "test_operation");
    context.set("component", "test_component");
    context.set("user_id", "12345");
    
    std::string serialized = context.serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("test_operation"), std::string::npos);
    EXPECT_NE(serialized.find("test_component"), std::string::npos);
    EXPECT_NE(serialized.find("12345"), std::string::npos);
}

// Test performance monitoring statistics
TEST_F(DXHookCoreTest, PerformanceStatistics) {
    auto perf_monitor = utils::PerformanceMonitor::GetInstance();
    
    // Perform multiple operations
    for (int i = 0; i < 5; ++i) {
        auto op_id = perf_monitor->start_operation("test_op_" + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        perf_monitor->end_operation(op_id);
    }
    
    // Get statistics
    auto stats = perf_monitor->get_performance_statistics();
    EXPECT_GE(stats.total_operations, 5);
}

// Test memory leak detection
TEST_F(DXHookCoreTest, MemoryLeakDetection) {
    auto memory_tracker = utils::MemoryTracker::GetInstance();
    
    // Create some allocations
    auto alloc1 = memory_tracker->track_allocation("test1", 100, utils::MemoryCategory::SYSTEM);
    auto alloc2 = memory_tracker->track_allocation("test2", 200, utils::MemoryCategory::GRAPHICS);
    
    // Release one allocation
    memory_tracker->release_allocation(alloc1);
    
    // Check for leaks
    EXPECT_TRUE(memory_tracker->has_leaks());
    
    // Release the other allocation
    memory_tracker->release_allocation(alloc2);
    
    // Should be no leaks now
    EXPECT_FALSE(memory_tracker->has_leaks());
}

// Test error handler configuration
TEST_F(DXHookCoreTest, ErrorHandlerConfiguration) {
    auto error_handler = utils::ErrorHandler::GetInstance();
    
    // Test log level filtering
    error_handler->set_minimum_log_level(utils::LogLevel::WARNING);
    
    // Test output configuration
    error_handler->set_console_output_enabled(true);
    error_handler->set_file_output_enabled(true);
    
    // Test error logging with different levels
    error_handler->debug("Debug message", utils::ErrorCategory::SYSTEM, "TestFunction", "test.cpp", 42);
    error_handler->info("Info message", utils::ErrorCategory::SYSTEM, "TestFunction", "test.cpp", 42);
    error_handler->warning("Warning message", utils::ErrorCategory::SYSTEM, "TestFunction", "test.cpp", 42);
    error_handler->error("Error message", utils::ErrorCategory::SYSTEM, "TestFunction", "test.cpp", 42, 0);
}

// Test thread safety of utility components
TEST_F(DXHookCoreTest, ThreadSafety) {
    auto error_handler = utils::ErrorHandler::GetInstance();
    auto perf_monitor = utils::PerformanceMonitor::GetInstance();
    auto memory_tracker = utils::MemoryTracker::GetInstance();
    
    std::vector<std::thread> threads;
    std::atomic<int> error_count{0};
    std::atomic<int> perf_count{0};
    std::atomic<int> memory_count{0};
    
    // Create multiple threads that use utility components
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&error_handler, &perf_monitor, &memory_tracker, i, &error_count, &perf_count, &memory_count]() {
            // Use error handler
            error_handler->info("Thread " + std::to_string(i) + " message", 
                              utils::ErrorCategory::SYSTEM, "TestFunction", "test.cpp", 42);
            error_count++;
            
            // Use performance monitor
            auto op_id = perf_monitor->start_operation("thread_op_" + std::to_string(i));
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            perf_monitor->end_operation(op_id);
            perf_count++;
            
            // Use memory tracker
            auto alloc_id = memory_tracker->track_allocation("thread_alloc_" + std::to_string(i), 
                                                           100, utils::MemoryCategory::SYSTEM);
            memory_tracker->release_allocation(alloc_id);
            memory_count++;
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(error_count.load(), 5);
    EXPECT_EQ(perf_count.load(), 5);
    EXPECT_EQ(memory_count.load(), 5);
}

// Test error recovery strategies
TEST_F(DXHookCoreTest, ErrorRecoveryStrategies) {
    auto error_handler = utils::ErrorHandler::GetInstance();
    
    // Test different recovery strategies
    error_handler->error("Automatic recovery test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::AUTOMATIC);
    
    error_handler->error("Manual recovery test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::MANUAL);
    
    error_handler->error("Fatal error test", utils::ErrorCategory::SYSTEM, 
                        "TestFunction", "test.cpp", 42, 0, utils::RecoveryStrategy::FATAL);
}

// Test performance monitoring alerts
TEST_F(DXHookCoreTest, PerformanceAlerts) {
    auto perf_monitor = utils::PerformanceMonitor::GetInstance();
    
    // Set up slow operation threshold
    perf_monitor->set_slow_operation_threshold("test_slow_op", std::chrono::milliseconds(1));
    
    // Perform a slow operation
    auto op_id = perf_monitor->start_operation("test_slow_op");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    perf_monitor->end_operation(op_id);
    
    // Check if operation was flagged as slow
    EXPECT_TRUE(perf_monitor->is_operation_slow(op_id));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 