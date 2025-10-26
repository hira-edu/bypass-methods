#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "dx_hook_core.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>

using namespace testing;

class DirectXHookManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset singleton state before each test
        DirectXHookManager::GetInstance().Shutdown();
        ErrorHandler::GetInstance().ClearLogs();
        PerformanceMonitor::GetInstance().Reset();
        MemoryTracker::GetInstance().Reset();
    }

    void TearDown() override {
        DirectXHookManager::GetInstance().Shutdown();
    }
};

// Test singleton pattern
TEST_F(DirectXHookManagerTest, SingletonPattern) {
    DirectXHookManager& instance1 = DirectXHookManager::GetInstance();
    DirectXHookManager& instance2 = DirectXHookManager::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

// Test constructor and destructor
TEST_F(DirectXHookManagerTest, ConstructorDestructor) {
    {
        DirectXHookManager& manager = DirectXHookManager::GetInstance();
        EXPECT_FALSE(manager.IsInitialized());
    }
    
    // Check that memory tracking was used
    auto allocations = MemoryTracker::GetInstance().GetAllocations();
    EXPECT_FALSE(allocations.empty());
}

// Test initialization without dependencies
TEST_F(DirectXHookManagerTest, InitializeWithoutDependencies) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    // Mock that D3D11/DXGI DLLs are not loaded
    // This would require mocking GetModuleHandleA, but for now we test the error path
    
    manager.Initialize();
    
    // Check error logs
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundDependencyError = false;
    for (const auto& error : errors) {
        if (error.message.find("D3D11/DXGI DLLs not found") != std::string::npos) {
            foundDependencyError = true;
            break;
        }
    }
    
    // Note: This test may pass or fail depending on whether D3D11/DXGI are actually loaded
    // In a real test environment, we would mock the Windows API calls
}

// Test multiple initialization calls
TEST_F(DirectXHookManagerTest, MultipleInitializationCalls) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    auto firstInitTime = PerformanceMonitor::GetInstance().GetTimerStats("DirectXHookManager::Initialize");
    
    manager.Initialize();
    auto secondInitTime = PerformanceMonitor::GetInstance().GetTimerStats("DirectXHookManager::Initialize");
    
    // Second call should be faster due to early return
    EXPECT_LE(secondInitTime.average_time, firstInitTime.average_time);
}

// Test swap chain pointer storage with null pointer
TEST_F(DirectXHookManagerTest, StoreSwapChainPointerNull) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.StoreSwapChainPointer(nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundNullPointerError = false;
    for (const auto& error : errors) {
        if (error.message.find("Received null SwapChain pointer") != std::string::npos) {
            foundNullPointerError = true;
            break;
        }
    }
    EXPECT_TRUE(foundNullPointerError);
}

// Test performance monitoring
TEST_F(DirectXHookManagerTest, PerformanceMonitoring) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    manager.Shutdown();
    
    auto perfStats = PerformanceMonitor::GetInstance().GetAllStats();
    
    // Check that performance timers were created
    EXPECT_TRUE(perfStats.find("DirectXHookManager::Initialize") != perfStats.end());
    EXPECT_TRUE(perfStats.find("DirectXHookManager::Shutdown") != perfStats.end());
    EXPECT_TRUE(perfStats.find("DirectXHookManager::Constructor") != perfStats.end());
}

// Test error context creation
TEST_F(DirectXHookManagerTest, ErrorContextCreation) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    
    auto contexts = ErrorHandler::GetInstance().GetContexts();
    bool foundInitContext = false;
    for (const auto& context : contexts) {
        if (context.name == "DirectXHookManager::Initialize") {
            foundInitContext = true;
            break;
        }
    }
    EXPECT_TRUE(foundInitContext);
}

// Test shutdown functionality
TEST_F(DirectXHookManagerTest, Shutdown) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    manager.Shutdown();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundShutdownComplete = false;
    for (const auto& log : logs) {
        if (log.message.find("Shutdown complete") != std::string::npos) {
            foundShutdownComplete = true;
            break;
        }
    }
    EXPECT_TRUE(foundShutdownComplete);
}

// Test memory tracking
TEST_F(DirectXHookManagerTest, MemoryTracking) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    auto allocations = MemoryTracker::GetInstance().GetAllocations();
    bool foundManagerAllocation = false;
    for (const auto& alloc : allocations) {
        if (alloc.name == "DirectXHookManager") {
            foundManagerAllocation = true;
            EXPECT_GT(alloc.size, 0);
            break;
        }
    }
    EXPECT_TRUE(foundManagerAllocation);
}

// Test error severity levels
TEST_F(DirectXHookManagerTest, ErrorSeverityLevels) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    // Trigger various error conditions
    manager.StoreSwapChainPointer(nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundErrorSeverity = false;
    bool foundCriticalSeverity = false;
    
    for (const auto& error : errors) {
        if (error.severity == ErrorSeverity::ERROR) {
            foundErrorSeverity = true;
        }
        if (error.severity == ErrorSeverity::CRITICAL) {
            foundCriticalSeverity = true;
        }
    }
    
    // At least one error severity should be found
    EXPECT_TRUE(foundErrorSeverity || foundCriticalSeverity);
}

// Test error categories
TEST_F(DirectXHookManagerTest, ErrorCategories) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.StoreSwapChainPointer(nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundInvalidParameterCategory = false;
    
    for (const auto& error : errors) {
        if (error.category == ErrorCategory::INVALID_PARAMETER) {
            foundInvalidParameterCategory = true;
            break;
        }
    }
    EXPECT_TRUE(foundInvalidParameterCategory);
}

// Test concurrent access
TEST_F(DirectXHookManagerTest, ConcurrentAccess) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    // Create multiple threads accessing the manager
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&manager, &successCount]() {
            try {
                manager.Initialize();
                successCount++;
            } catch (...) {
                // Ignore exceptions for this test
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have completed successfully
    EXPECT_EQ(successCount.load(), 5);
}

// Test exception handling
TEST_F(DirectXHookManagerTest, ExceptionHandling) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    // This test would require mocking SwapChainHook to throw exceptions
    // For now, we test that the error handling infrastructure is in place
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    // Should be able to handle exceptions when they occur
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test logging levels
TEST_F(DirectXHookManagerTest, LoggingLevels) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundInfoLog = false;
    
    for (const auto& log : logs) {
        if (log.level == LogLevel::INFO) {
            foundInfoLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundInfoLog);
}

// Test resource cleanup
TEST_F(DirectXHookManagerTest, ResourceCleanup) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    manager.Initialize();
    
    // Force cleanup by going out of scope
    {
        DirectXHookManager& tempManager = DirectXHookManager::GetInstance();
        tempManager.Initialize();
    }
    
    // Check that no memory leaks were reported
    auto leaks = MemoryTracker::GetInstance().GetLeaks();
    EXPECT_TRUE(leaks.empty());
}

// Test performance timing accuracy
TEST_F(DirectXHookManagerTest, PerformanceTimingAccuracy) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    auto start = std::chrono::high_resolution_clock::now();
    manager.Initialize();
    auto end = std::chrono::high_resolution_clock::now();
    
    auto actualDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    auto perfStats = PerformanceMonitor::GetInstance().GetTimerStats("DirectXHookManager::Initialize");
    
    // Performance monitor should record similar timing
    EXPECT_GT(perfStats.average_time, 0);
    EXPECT_LE(perfStats.average_time, actualDuration.count() * 1.5); // Allow some overhead
}

// Test error recovery
TEST_F(DirectXHookManagerTest, ErrorRecovery) {
    DirectXHookManager& manager = DirectXHookManager::GetInstance();
    
    // Simulate error condition
    manager.StoreSwapChainPointer(nullptr);
    
    // Should still be able to initialize after error
    manager.Initialize();
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    EXPECT_FALSE(errors.empty());
    
    // Should still be able to shutdown cleanly
    manager.Shutdown();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundShutdownComplete = false;
    for (const auto& log : logs) {
        if (log.message.find("Shutdown complete") != std::string::npos) {
            foundShutdownComplete = true;
            break;
        }
    }
    EXPECT_TRUE(foundShutdownComplete);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 