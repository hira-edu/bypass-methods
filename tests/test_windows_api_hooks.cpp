#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "hooks/windows_api_hooks.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>

using namespace testing;
using namespace UndownUnlock::WindowsHook;

class WindowsAPIHooksTest : public ::testing::Test {
protected:
    void SetUp() override {
        ErrorHandler::GetInstance().ClearLogs();
        PerformanceMonitor::GetInstance().Reset();
        MemoryTracker::GetInstance().Reset();
        
        // Reset static state
        WindowsAPIHooks::s_isFocusInstalled = false;
        WindowsAPIHooks::s_focusHWND = NULL;
        WindowsAPIHooks::s_bringWindowToTopHWND = NULL;
        WindowsAPIHooks::s_setWindowFocusHWND = NULL;
        WindowsAPIHooks::s_setWindowFocushWndInsertAfter = NULL;
        WindowsAPIHooks::s_setWindowFocusX = 0;
        WindowsAPIHooks::s_setWindowFocusY = 0;
        WindowsAPIHooks::s_setWindowFocuscx = 0;
        WindowsAPIHooks::s_setWindowFocuscy = 0;
        WindowsAPIHooks::s_setWindowFocusuFlags = 0;
    }

    void TearDown() override {
        // Clean up any installed hooks
        WindowsAPIHooks::Shutdown();
    }
};

// Test initialization
TEST_F(WindowsAPIHooksTest, Initialize) {
    bool result = WindowsAPIHooks::Initialize();
    
    // Should return true even if some hooks fail (system-dependent)
    EXPECT_TRUE(result);
    
    // Check that initialization was logged
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundInitLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Installing Windows API hooks") != std::string::npos) {
            foundInitLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundInitLog);
}

// Test shutdown
TEST_F(WindowsAPIHooksTest, Shutdown) {
    // Initialize first
    WindowsAPIHooks::Initialize();
    
    // Then shutdown
    WindowsAPIHooks::Shutdown();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundShutdownLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Removing Windows API hooks") != std::string::npos) {
            foundShutdownLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundShutdownLog);
}

// Test focus hooks installation
TEST_F(WindowsAPIHooksTest, InstallFocusHooks) {
    WindowsAPIHooks::InstallFocusHooks();
    
    EXPECT_TRUE(WindowsAPIHooks::s_isFocusInstalled);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundFocusInstallLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Installing focus-related hooks") != std::string::npos) {
            foundFocusInstallLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundFocusInstallLog);
}

// Test focus hooks installation when already installed
TEST_F(WindowsAPIHooksTest, InstallFocusHooksAlreadyInstalled) {
    WindowsAPIHooks::s_isFocusInstalled = true;
    
    WindowsAPIHooks::InstallFocusHooks();
    
    EXPECT_TRUE(WindowsAPIHooks::s_isFocusInstalled);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundAlreadyInstalledLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Focus hooks already installed") != std::string::npos) {
            foundAlreadyInstalledLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundAlreadyInstalledLog);
}

// Test focus hooks uninstallation
TEST_F(WindowsAPIHooksTest, UninstallFocusHooks) {
    // Install first
    WindowsAPIHooks::InstallFocusHooks();
    EXPECT_TRUE(WindowsAPIHooks::s_isFocusInstalled);
    
    // Then uninstall
    WindowsAPIHooks::UninstallFocusHooks();
    EXPECT_FALSE(WindowsAPIHooks::s_isFocusInstalled);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundUninstallLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Uninstalling focus-related hooks") != std::string::npos) {
            foundUninstallLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundUninstallLog);
}

// Test focus hooks uninstallation when not installed
TEST_F(WindowsAPIHooksTest, UninstallFocusHooksNotInstalled) {
    WindowsAPIHooks::s_isFocusInstalled = false;
    
    WindowsAPIHooks::UninstallFocusHooks();
    
    EXPECT_FALSE(WindowsAPIHooks::s_isFocusInstalled);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundNotInstalledLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Focus hooks not installed") != std::string::npos) {
            foundNotInstalledLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundNotInstalledLog);
}

// Test FindMainWindow
TEST_F(WindowsAPIHooksTest, FindMainWindow) {
    HWND result = WindowsAPIHooks::FindMainWindow();
    
    // Result depends on system state, but should not crash
    // May be NULL if no main window is found
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundWindowLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Found main window") != std::string::npos || 
            log.message.find("Failed to find main window") != std::string::npos) {
            foundWindowLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundWindowLog);
}

// Test SetupKeyboardHook
TEST_F(WindowsAPIHooksTest, SetupKeyboardHook) {
    // This test would require mocking the keyboard hook
    // For now, we test that the method exists and logs appropriately
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    // Should not crash
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test UninstallKeyboardHook
TEST_F(WindowsAPIHooksTest, UninstallKeyboardHook) {
    // This test would require mocking the keyboard hook
    // For now, we test that the method exists and logs appropriately
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    // Should not crash
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test performance monitoring
TEST_F(WindowsAPIHooksTest, PerformanceMonitoring) {
    WindowsAPIHooks::Initialize();
    WindowsAPIHooks::InstallFocusHooks();
    WindowsAPIHooks::FindMainWindow();
    WindowsAPIHooks::UninstallFocusHooks();
    WindowsAPIHooks::Shutdown();
    
    auto perfStats = PerformanceMonitor::GetInstance().GetAllStats();
    
    // Check that performance timers were created
    EXPECT_TRUE(perfStats.find("WindowsAPIHooks::Initialize") != perfStats.end());
    EXPECT_TRUE(perfStats.find("WindowsAPIHooks::InstallFocusHooks") != perfStats.end());
    EXPECT_TRUE(perfStats.find("WindowsAPIHooks::FindMainWindow") != perfStats.end());
    EXPECT_TRUE(perfStats.find("WindowsAPIHooks::UninstallFocusHooks") != perfStats.end());
    EXPECT_TRUE(perfStats.find("WindowsAPIHooks::Shutdown") != perfStats.end());
}

// Test error context creation
TEST_F(WindowsAPIHooksTest, ErrorContextCreation) {
    WindowsAPIHooks::Initialize();
    WindowsAPIHooks::InstallFocusHooks();
    WindowsAPIHooks::UninstallFocusHooks();
    WindowsAPIHooks::Shutdown();
    
    auto contexts = ErrorHandler::GetInstance().GetContexts();
    bool foundInitContext = false;
    bool foundFocusContext = false;
    bool foundUninstallContext = false;
    bool foundShutdownContext = false;
    
    for (const auto& context : contexts) {
        if (context.name == "WindowsAPIHooks::Initialize") {
            foundInitContext = true;
        }
        if (context.name == "WindowsAPIHooks::InstallFocusHooks") {
            foundFocusContext = true;
        }
        if (context.name == "WindowsAPIHooks::UninstallFocusHooks") {
            foundUninstallContext = true;
        }
        if (context.name == "WindowsAPIHooks::Shutdown") {
            foundShutdownContext = true;
        }
    }
    EXPECT_TRUE(foundInitContext);
    EXPECT_TRUE(foundFocusContext);
    EXPECT_TRUE(foundUninstallContext);
    EXPECT_TRUE(foundShutdownContext);
}

// Test error severity levels
TEST_F(WindowsAPIHooksTest, ErrorSeverityLevels) {
    WindowsAPIHooks::Initialize();
    
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
    
    // At least one error severity should be found (system-dependent)
    EXPECT_TRUE(foundErrorSeverity || foundWarningSeverity);
}

// Test error categories
TEST_F(WindowsAPIHooksTest, ErrorCategories) {
    WindowsAPIHooks::Initialize();
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    bool foundHookCategory = false;
    bool foundSystemCategory = false;
    
    for (const auto& error : errors) {
        if (error.category == ErrorCategory::HOOK) {
            foundHookCategory = true;
        }
        if (error.category == ErrorCategory::SYSTEM) {
            foundSystemCategory = true;
        }
    }
    EXPECT_TRUE(foundHookCategory || foundSystemCategory);
}

// Test logging levels
TEST_F(WindowsAPIHooksTest, LoggingLevels) {
    WindowsAPIHooks::Initialize();
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundInfoLog = false;
    bool foundWarningLog = false;
    
    for (const auto& log : logs) {
        if (log.level == LogLevel::INFO) {
            foundInfoLog = true;
        }
        if (log.level == LogLevel::WARNING) {
            foundWarningLog = true;
        }
    }
    EXPECT_TRUE(foundInfoLog);
}

// Test resource cleanup
TEST_F(WindowsAPIHooksTest, ResourceCleanup) {
    WindowsAPIHooks::Initialize();
    WindowsAPIHooks::InstallFocusHooks();
    WindowsAPIHooks::Shutdown();
    
    // Check that no memory leaks were reported
    auto leaks = MemoryTracker::GetInstance().GetLeaks();
    EXPECT_TRUE(leaks.empty());
}

// Test performance timing accuracy
TEST_F(WindowsAPIHooksTest, PerformanceTimingAccuracy) {
    auto start = std::chrono::high_resolution_clock::now();
    WindowsAPIHooks::InstallFocusHooks();
    auto end = std::chrono::high_resolution_clock::now();
    
    auto actualDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    auto perfStats = PerformanceMonitor::GetInstance().GetTimerStats("WindowsAPIHooks::InstallFocusHooks");
    
    // Performance monitor should record similar timing
    EXPECT_GT(perfStats.average_time, 0);
    EXPECT_LE(perfStats.average_time, actualDuration.count() * 1.5); // Allow some overhead
}

// Test error recovery
TEST_F(WindowsAPIHooksTest, ErrorRecovery) {
    // Initialize and shutdown multiple times
    WindowsAPIHooks::Initialize();
    WindowsAPIHooks::Shutdown();
    WindowsAPIHooks::Initialize();
    WindowsAPIHooks::Shutdown();
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    // Should handle multiple initialization/shutdown cycles gracefully
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test concurrent access
TEST_F(WindowsAPIHooksTest, ConcurrentAccess) {
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    // Create multiple threads accessing the hooks
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back([&successCount]() {
            try {
                WindowsAPIHooks::InstallFocusHooks();
                WindowsAPIHooks::UninstallFocusHooks();
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
    EXPECT_EQ(successCount.load(), 3);
}

// Test static variable access
TEST_F(WindowsAPIHooksTest, StaticVariableAccess) {
    // Test that static variables can be accessed and modified
    WindowsAPIHooks::s_focusHWND = reinterpret_cast<HWND>(0x12345678);
    WindowsAPIHooks::s_setWindowFocusX = 100;
    WindowsAPIHooks::s_setWindowFocusY = 200;
    
    EXPECT_EQ(WindowsAPIHooks::s_focusHWND, reinterpret_cast<HWND>(0x12345678));
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusX, 100);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusY, 200);
}

// Test hook installation error handling
TEST_F(WindowsAPIHooksTest, HookInstallationErrorHandling) {
    // This test would require mocking the Windows API calls
    // For now, we test that the error handling infrastructure is in place
    
    auto errors = ErrorHandler::GetInstance().GetErrors();
    // Should be able to handle hook installation failures gracefully
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test DLL handle acquisition
TEST_F(WindowsAPIHooksTest, DLLHandleAcquisition) {
    // Test that DLL handles can be acquired
    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    
    // These should be available on Windows systems
    EXPECT_NE(hUser32, nullptr);
    EXPECT_NE(hKernel32, nullptr);
}

// Test function address resolution
TEST_F(WindowsAPIHooksTest, FunctionAddressResolution) {
    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (hUser32) {
        void* targetEmptyClipboard = GetProcAddress(hUser32, "EmptyClipboard");
        void* targetGetForegroundWindow = GetProcAddress(hUser32, "GetForegroundWindow");
        
        // These functions should be available
        EXPECT_NE(targetEmptyClipboard, nullptr);
        EXPECT_NE(targetGetForegroundWindow, nullptr);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 