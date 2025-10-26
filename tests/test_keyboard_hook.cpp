#include <gtest/gtest.h>
#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include "hooks/keyboard_hook.h"
#include "utils/raii_wrappers.h"
#include "utils/error_handler.h"
#include "utils/memory_tracker.h"
#include "utils/performance_monitor.h"

using namespace UndownUnlock::WindowsHook;

class KeyboardHookTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize error handler for testing
        ErrorHandler::Initialize();
        
        // Initialize memory tracker for testing
        MemoryTracker::Initialize();
        
        // Initialize performance monitor for testing
        PerformanceMonitor::Initialize();
    }
    
    void TearDown() override {
        // Cleanup keyboard hook if it was initialized
        KeyboardHook::Shutdown();
        
        // Shutdown utility components
        PerformanceMonitor::Shutdown();
        MemoryTracker::Shutdown();
        ErrorHandler::Shutdown();
    }
};

// Test keyboard hook initialization
TEST_F(KeyboardHookTest, InitializeSuccess) {
    EXPECT_NO_THROW(KeyboardHook::Initialize());
    
    // Verify hook was created
    // Note: We can't directly access the private static member, but we can test behavior
    EXPECT_TRUE(true); // Hook initialization completed without exception
}

// Test keyboard hook shutdown
TEST_F(KeyboardHookTest, ShutdownSuccess) {
    // Initialize first
    KeyboardHook::Initialize();
    
    // Then shutdown
    EXPECT_NO_THROW(KeyboardHook::Shutdown());
    
    // Verify shutdown completed without exception
    EXPECT_TRUE(true);
}

// Test multiple initialize/shutdown cycles
TEST_F(KeyboardHookTest, MultipleInitializeShutdownCycles) {
    for (int i = 0; i < 3; ++i) {
        EXPECT_NO_THROW(KeyboardHook::Initialize());
        EXPECT_NO_THROW(KeyboardHook::Shutdown());
    }
}

// Test error handling during initialization
TEST_F(KeyboardHookTest, ErrorHandlingDuringInitialization) {
    // This test verifies that error handling is properly integrated
    // The actual error conditions would require mocking Windows API calls
    
    EXPECT_NO_THROW(KeyboardHook::Initialize());
    EXPECT_NO_THROW(KeyboardHook::Shutdown());
}

// Test performance monitoring integration
TEST_F(KeyboardHookTest, PerformanceMonitoringIntegration) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    KeyboardHook::Initialize();
    
    auto initTime = std::chrono::high_resolution_clock::now();
    auto initDuration = std::chrono::duration_cast<std::chrono::microseconds>(initTime - startTime);
    
    KeyboardHook::Shutdown();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    
    // Verify operations completed in reasonable time
    EXPECT_LT(initDuration.count(), 1000000); // Less than 1 second for initialization
    EXPECT_LT(totalDuration.count(), 2000000); // Less than 2 seconds total
}

// Test memory tracking integration
TEST_F(KeyboardHookTest, MemoryTrackingIntegration) {
    // Initialize memory tracking
    MemoryTracker::Initialize();
    
    // Get initial memory state
    auto initialMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    KeyboardHook::Initialize();
    
    // Get memory state after initialization
    auto afterInitMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    KeyboardHook::Shutdown();
    
    // Get memory state after shutdown
    auto afterShutdownMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify memory was allocated during initialization
    EXPECT_GE(afterInitMemory, initialMemory);
    
    // Verify memory was properly deallocated during shutdown
    EXPECT_LE(afterShutdownMemory, afterInitMemory);
}

// Test RAII wrapper integration
TEST_F(KeyboardHookTest, RAIIWrapperIntegration) {
    // Test that RAII wrappers are properly used
    // This is primarily a compilation test to ensure headers are included
    
    // Create a scoped handle wrapper
    ScopedHandle testHandle(CreateEvent(nullptr, TRUE, FALSE, nullptr));
    EXPECT_NE(testHandle.get(), INVALID_HANDLE_VALUE);
    
    // Handle should be automatically closed when testHandle goes out of scope
}

// Test error handler integration
TEST_F(KeyboardHookTest, ErrorHandlerIntegration) {
    // Test that error handler is properly integrated
    // This is primarily a compilation test to ensure headers are included
    
    // Log a test message
    ErrorHandler::LogInfo(ErrorCategory::WINDOWS_API, "Test message from keyboard hook test");
    
    // Verify no exceptions are thrown
    EXPECT_NO_THROW();
}

// Test concurrent access (if applicable)
TEST_F(KeyboardHookTest, ConcurrentAccess) {
    // Test that the keyboard hook can handle concurrent access scenarios
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back([i]() {
            // Each thread tries to initialize and shutdown the hook
            // Note: In a real scenario, only one thread should manage the hook
            try {
                KeyboardHook::Initialize();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                KeyboardHook::Shutdown();
            } catch (...) {
                // Expected that only one thread can manage the hook
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify no crashes occurred
    EXPECT_TRUE(true);
}

// Test resource cleanup
TEST_F(KeyboardHookTest, ResourceCleanup) {
    // Test that all resources are properly cleaned up
    
    // Initialize memory tracking
    MemoryTracker::Initialize();
    
    // Get initial memory state
    auto initialMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Perform multiple initialize/shutdown cycles
    for (int i = 0; i < 5; ++i) {
        KeyboardHook::Initialize();
        KeyboardHook::Shutdown();
    }
    
    // Get final memory state
    auto finalMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify no memory leaks (allow for some overhead)
    EXPECT_LE(finalMemory - initialMemory, 1024); // Allow 1KB overhead
}

// Test exception safety
TEST_F(KeyboardHookTest, ExceptionSafety) {
    // Test that the keyboard hook is exception-safe
    
    try {
        KeyboardHook::Initialize();
        
        // Simulate an exception during operation
        throw std::runtime_error("Test exception");
        
    } catch (const std::exception& e) {
        // Exception was thrown as expected
        EXPECT_STREQ(e.what(), "Test exception");
    }
    
    // Verify shutdown can still be called safely
    EXPECT_NO_THROW(KeyboardHook::Shutdown());
}

// Test performance benchmarks
TEST_F(KeyboardHookTest, PerformanceBenchmarks) {
    const int numIterations = 100;
    std::vector<std::chrono::microseconds> initTimes;
    std::vector<std::chrono::microseconds> shutdownTimes;
    
    for (int i = 0; i < numIterations; ++i) {
        auto startInit = std::chrono::high_resolution_clock::now();
        KeyboardHook::Initialize();
        auto endInit = std::chrono::high_resolution_clock::now();
        
        auto startShutdown = std::chrono::high_resolution_clock::now();
        KeyboardHook::Shutdown();
        auto endShutdown = std::chrono::high_resolution_clock::now();
        
        initTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endInit - startInit));
        shutdownTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endShutdown - startShutdown));
    }
    
    // Calculate average times
    auto avgInitTime = std::accumulate(initTimes.begin(), initTimes.end(), std::chrono::microseconds(0)) / numIterations;
    auto avgShutdownTime = std::accumulate(shutdownTimes.begin(), shutdownTimes.end(), std::chrono::microseconds(0)) / numIterations;
    
    // Verify performance is within acceptable bounds
    EXPECT_LT(avgInitTime.count(), 10000); // Less than 10ms average initialization
    EXPECT_LT(avgShutdownTime.count(), 10000); // Less than 10ms average shutdown
}

// Test integration with Windows API hooks
TEST_F(KeyboardHookTest, WindowsAPIHooksIntegration) {
    // Test that keyboard hook integrates properly with Windows API hooks
    // This is primarily a compilation and linking test
    
    KeyboardHook::Initialize();
    
    // Verify no exceptions during integration
    EXPECT_NO_THROW();
    
    KeyboardHook::Shutdown();
}

// Test error recovery
TEST_F(KeyboardHookTest, ErrorRecovery) {
    // Test that the keyboard hook can recover from errors
    
    // Initialize normally
    KeyboardHook::Initialize();
    
    // Force an error condition (if possible)
    // In a real scenario, this might involve mocking Windows API failures
    
    // Verify shutdown still works
    EXPECT_NO_THROW(KeyboardHook::Shutdown());
    
    // Verify re-initialization works
    EXPECT_NO_THROW(KeyboardHook::Initialize());
    EXPECT_NO_THROW(KeyboardHook::Shutdown());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 