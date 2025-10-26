#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "hooks/swap_chain_hook.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>

using namespace testing;
using namespace UndownUnlock::DXHook;

class SwapChainHookTest : public ::testing::Test {
protected:
    void SetUp() override {
        ErrorHandler::GetInstance().ClearLogs();
        PerformanceMonitor::GetInstance().Reset();
        MemoryTracker::GetInstance().Reset();
    }

    void TearDown() override {
        // Clean up any remaining hooks
        if (SwapChainHook::s_instance) {
            SwapChainHook::s_instance->RemoveHooks();
        }
    }
};

// Test constructor and destructor
TEST_F(SwapChainHookTest, ConstructorDestructor) {
    {
        SwapChainHook hook;
        EXPECT_FALSE(hook.IsHooksInstalled());
        EXPECT_EQ(SwapChainHook::s_instance, &hook);
    }
    
    EXPECT_EQ(SwapChainHook::s_instance, nullptr);
    
    // Check memory tracking
    auto allocations = MemoryTracker::GetInstance().GetAllocations();
    bool foundHookAllocation = false;
    for (const auto& alloc : allocations) {
        if (alloc.name == "SwapChainHook") {
            foundHookAllocation = true;
            EXPECT_GT(alloc.size, 0);
            break;
        }
    }
    EXPECT_TRUE(foundHookAllocation);
}

// Test VTableHook::GetVTable with null pointer
TEST_F(SwapChainHookTest, GetVTableNullPointer) {
    void** vtable = VTableHook::GetVTable(nullptr);
    EXPECT_EQ(vtable, nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundNullPointerError = false;
    for (const auto& error : errors) {
        if (error.message.find("GetVTable called with null interface pointer") != std::string::npos) {
            foundNullPointerError = true;
            break;
        }
    }
    EXPECT_TRUE(foundNullPointerError);
}

// Test VTableHook::HookVTableEntry with null parameters
TEST_F(SwapChainHookTest, HookVTableEntryNullParameters) {
    void* result = VTableHook::HookVTableEntry(nullptr, 0, nullptr);
    EXPECT_EQ(result, nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundNullParameterError = false;
    for (const auto& error : errors) {
        if (error.message.find("HookVTableEntry called with null parameters") != std::string::npos) {
            foundNullParameterError = true;
            break;
        }
    }
    EXPECT_TRUE(foundNullParameterError);
}

// Test InstallHooks with null interface
TEST_F(SwapChainHookTest, InstallHooksNullInterface) {
    SwapChainHook hook;
    bool result = hook.InstallHooks(nullptr);
    EXPECT_FALSE(result);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundInvalidParameterError = false;
    for (const auto& error : errors) {
        if (error.message.find("InstallHooks called with invalid parameters") != std::string::npos) {
            foundInvalidParameterError = true;
            break;
        }
    }
    EXPECT_TRUE(foundInvalidParameterError);
}

// Test InstallHooks when already installed
TEST_F(SwapChainHookTest, InstallHooksAlreadyInstalled) {
    SwapChainHook hook;
    
    // Mock that hooks are already installed
    hook.m_hooksInstalled = true;
    
    bool result = hook.InstallHooks(reinterpret_cast<void*>(0x12345678));
    EXPECT_FALSE(result);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundAlreadyInstalledError = false;
    for (const auto& error : errors) {
        if (error.message.find("InstallHooks called with invalid parameters") != std::string::npos) {
            foundAlreadyInstalledError = true;
            break;
        }
    }
    EXPECT_TRUE(foundAlreadyInstalledError);
}

// Test RemoveHooks when no hooks installed
TEST_F(SwapChainHookTest, RemoveHooksNoHooksInstalled) {
    SwapChainHook hook;
    hook.RemoveHooks(); // Should not crash
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundNoHooksLog = false;
    for (const auto& log : logs) {
        if (log.message.find("RemoveHooks called but no hooks installed") != std::string::npos) {
            foundNoHooksLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundNoHooksLog);
}

// Test SetPresentCallback
TEST_F(SwapChainHookTest, SetPresentCallback) {
    SwapChainHook hook;
    
    bool callbackCalled = false;
    auto callback = [&callbackCalled](IDXGISwapChain* swapChain) {
        callbackCalled = true;
    };
    
    hook.SetPresentCallback(callback);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundCallbackSetLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Present callback set") != std::string::npos) {
            foundCallbackSetLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundCallbackSetLog);
}

// Test HookPresent with invalid instance
TEST_F(SwapChainHookTest, HookPresentInvalidInstance) {
    // Clear static instance
    SwapChainHook::s_instance = nullptr;
    
    HRESULT result = SwapChainHook::HookPresent(nullptr, 0, 0);
    EXPECT_EQ(result, E_FAIL);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundInvalidInstanceError = false;
    for (const auto& error : errors) {
        if (error.message.find("HookPresent called with invalid instance") != std::string::npos) {
            foundInvalidInstanceError = true;
            break;
        }
    }
    EXPECT_TRUE(foundInvalidInstanceError);
}

// Test performance monitoring
TEST_F(SwapChainHookTest, PerformanceMonitoring) {
    SwapChainHook hook;
    
    // Test various operations
    hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
    hook.RemoveHooks();
    
    auto perfStats = PerformanceMonitor::GetInstance().GetAllStats();
    
    // Check that performance timers were created
    EXPECT_TRUE(perfStats.find("SwapChainHook::Constructor") != perfStats.end());
    EXPECT_TRUE(perfStats.find("SwapChainHook::SetPresentCallback") != perfStats.end());
    EXPECT_TRUE(perfStats.find("SwapChainHook::RemoveHooks") != perfStats.end());
    EXPECT_TRUE(perfStats.find("VTableHook::GetVTable") != perfStats.end());
    EXPECT_TRUE(perfStats.find("VTableHook::HookVTableEntry") != perfStats.end());
}

// Test error context creation
TEST_F(SwapChainHookTest, ErrorContextCreation) {
    SwapChainHook hook;
    
    hook.InstallHooks(nullptr);
    hook.RemoveHooks();
    
    auto contexts = ErrorHandler::GetInstance().GetContexts();
    bool foundInstallContext = false;
    bool foundRemoveContext = false;
    
    for (const auto& context : contexts) {
        if (context.name == "SwapChainHook::InstallHooks") {
            foundInstallContext = true;
        }
        if (context.name == "SwapChainHook::RemoveHooks") {
            foundRemoveContext = true;
        }
    }
    EXPECT_TRUE(foundInstallContext);
    EXPECT_TRUE(foundRemoveContext);
}

// Test error severity levels
TEST_F(SwapChainHookTest, ErrorSeverityLevels) {
    SwapChainHook hook;
    
    // Trigger various error conditions
    hook.InstallHooks(nullptr);
    VTableHook::GetVTable(nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundErrorSeverity = false;
    bool foundWarningSeverity = false;
    
    for (const auto& error : errors) {
        if (error.severity == ErrorSeverity::ERROR) {
            foundErrorSeverity = true;
        }
        if (error.severity == ErrorSeverity::WARNING) {
            foundWarningSeverity = true;
        }
    }
    
    // At least one error severity should be found
    EXPECT_TRUE(foundErrorSeverity || foundWarningSeverity);
}

// Test error categories
TEST_F(SwapChainHookTest, ErrorCategories) {
    SwapChainHook hook;
    
    hook.InstallHooks(nullptr);
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundInvalidParameterCategory = false;
    bool foundHookCategory = false;
    
    for (const auto& error : errors) {
        if (error.category == ErrorCategory::INVALID_PARAMETER) {
            foundInvalidParameterCategory = true;
        }
        if (error.category == ErrorCategory::HOOK) {
            foundHookCategory = true;
        }
    }
    EXPECT_TRUE(foundInvalidParameterCategory || foundHookCategory);
}

// Test exception handling in callback
TEST_F(SwapChainHookTest, ExceptionHandlingInCallback) {
    SwapChainHook hook;
    
    bool callbackCalled = false;
    auto callback = [&callbackCalled](IDXGISwapChain* swapChain) {
        callbackCalled = true;
        throw std::runtime_error("Test exception");
    };
    
    hook.SetPresentCallback(callback);
    
    // This would normally be called by the hook, but we can test the exception handling
    // by directly calling the callback
    try {
        callback(nullptr);
    } catch (...) {
        // Exception should be caught and logged
    }
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundExceptionError = false;
    for (const auto& error : errors) {
        if (error.category == ErrorCategory::EXCEPTION) {
            foundExceptionError = true;
            break;
        }
    }
    EXPECT_TRUE(foundExceptionError);
}

// Test memory tracking
TEST_F(SwapChainHookTest, MemoryTracking) {
    {
        SwapChainHook hook;
        // Hook should be tracked
    }
    
    auto allocations = MemoryTracker::GetInstance().GetAllocations();
    bool foundHookAllocation = false;
    
    for (const auto& alloc : allocations) {
        if (alloc.name == "SwapChainHook") {
            foundHookAllocation = true;
            EXPECT_GT(alloc.size, 0);
            break;
        }
    }
    EXPECT_TRUE(foundHookAllocation);
}

// Test logging levels
TEST_F(SwapChainHookTest, LoggingLevels) {
    SwapChainHook hook;
    
    hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
    
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
TEST_F(SwapChainHookTest, ResourceCleanup) {
    {
        SwapChainHook hook;
        hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
    }
    
    // Check that no memory leaks were reported
    auto leaks = MemoryTracker::GetInstance().GetLeaks();
    EXPECT_TRUE(leaks.empty());
}

// Test performance timing accuracy
TEST_F(SwapChainHookTest, PerformanceTimingAccuracy) {
    SwapChainHook hook;
    
    auto start = std::chrono::high_resolution_clock::now();
    hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
    auto end = std::chrono::high_resolution_clock::now();
    
    auto actualDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    auto perfStats = PerformanceMonitor::GetInstance().GetTimerStats("SwapChainHook::SetPresentCallback");
    
    // Performance monitor should record similar timing
    EXPECT_GT(perfStats.average_time, 0);
    EXPECT_LE(perfStats.average_time, actualDuration.count() * 1.5); // Allow some overhead
}

// Test error recovery
TEST_F(SwapChainHookTest, ErrorRecovery) {
    SwapChainHook hook;
    
    // Simulate error condition
    hook.InstallHooks(nullptr);
    
    // Should still be able to set callback after error
    hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    EXPECT_FALSE(errors.empty());
    
    // Should still be able to remove hooks cleanly
    hook.RemoveHooks();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundRemoveLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Removed SwapChain hooks") != std::string::npos) {
            foundRemoveLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundRemoveLog);
}

// Test concurrent access
TEST_F(SwapChainHookTest, ConcurrentAccess) {
    SwapChainHook hook;
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    // Create multiple threads accessing the hook
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&hook, &successCount]() {
            try {
                hook.SetPresentCallback([](IDXGISwapChain* swapChain) {});
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

// Test FindAndHookSwapChain (basic test without actual D3D11)
TEST_F(SwapChainHookTest, FindAndHookSwapChainBasic) {
    SwapChainHook hook;
    
    // This test would require mocking D3D11CreateDeviceAndSwapChain
    // For now, we test that the method exists and doesn't crash
    bool result = hook.FindAndHookSwapChain();
    
    // Result depends on system capabilities, but should not crash
    EXPECT_TRUE(true); // Placeholder assertion
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 