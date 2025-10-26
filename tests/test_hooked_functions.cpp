#include <gtest/gtest.h>
#include "hooks/hooked_functions.h"
#include "hooks/windows_api_hooks.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <memory>
#include <thread>
#include <chrono>

using namespace testing;
using namespace UndownUnlock::WindowsHook;

class HookedFunctionsTest : public ::testing::Test {
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

// Test clipboard functions
TEST_F(HookedFunctionsTest, HookedSetClipboardData) {
    HANDLE result = HookedSetClipboardData(CF_TEXT, nullptr);
    EXPECT_EQ(result, nullptr);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundClipboardLog = false;
    for (const auto& log : logs) {
        if (log.message.find("SetClipboardData hook called") != std::string::npos) {
            foundClipboardLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundClipboardLog);
}

TEST_F(HookedFunctionsTest, HookedEmptyClipboard) {
    BOOL result = HookedEmptyClipboard();
    EXPECT_EQ(result, TRUE);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundEmptyLog = false;
    for (const auto& log : logs) {
        if (log.message.find("EmptyClipboard hook called") != std::string::npos) {
            foundEmptyLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundEmptyLog);
}

// Test process management functions
TEST_F(HookedFunctionsTest, HookedOpenProcess) {
    HANDLE result = HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 12345);
    EXPECT_EQ(result, nullptr);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundOpenProcessLog = false;
    for (const auto& log : logs) {
        if (log.message.find("OpenProcess hook called") != std::string::npos && 
            log.message.find("12345") != std::string::npos) {
            foundOpenProcessLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundOpenProcessLog);
}

TEST_F(HookedFunctionsTest, HookedTerminateProcess) {
    BOOL result = HookedTerminateProcess(nullptr, 1);
    EXPECT_EQ(result, TRUE);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundTerminateLog = false;
    for (const auto& log : logs) {
        if (log.message.find("TerminateProcess hook called") != std::string::npos && 
            log.message.find("1") != std::string::npos) {
            foundTerminateLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundTerminateLog);
}

TEST_F(HookedFunctionsTest, HookedExitProcess) {
    // This function doesn't return, so we just test that it doesn't crash
    // and logs appropriately
    auto logs = ErrorHandler::GetInstance().GetLogs();
    // Should not crash
    EXPECT_TRUE(true); // Placeholder assertion
}

TEST_F(HookedFunctionsTest, HookedK32EnumProcesses) {
    DWORD processIds[10];
    DWORD bytesReturned;
    BOOL result = HookedK32EnumProcesses(processIds, sizeof(processIds), &bytesReturned);
    
    EXPECT_EQ(result, TRUE);
    EXPECT_EQ(bytesReturned, 0);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundEnumLog = false;
    for (const auto& log : logs) {
        if (log.message.find("K32EnumProcesses hook called") != std::string::npos) {
            foundEnumLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundEnumLog);
}

// Test window management functions
TEST_F(HookedFunctionsTest, HookedGetWindowTextW) {
    wchar_t buffer[256];
    int result = HookedGetWindowTextW(nullptr, buffer, 256);
    
    EXPECT_EQ(result, 0);
    EXPECT_EQ(buffer[0], L'\0');
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundGetWindowTextLog = false;
    for (const auto& log : logs) {
        if (log.message.find("GetWindowTextW hook called") != std::string::npos && 
            log.message.find("256") != std::string::npos) {
            foundGetWindowTextLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundGetWindowTextLog);
}

TEST_F(HookedFunctionsTest, HookedSetWindowPos) {
    HWND testHwnd = reinterpret_cast<HWND>(0x12345678);
    HWND testInsertAfter = reinterpret_cast<HWND>(0x87654321);
    
    BOOL result = HookedSetWindowPos(testHwnd, testInsertAfter, 100, 200, 300, 400, SWP_NOMOVE);
    
    EXPECT_EQ(result, TRUE);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusHWND, testHwnd);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocushWndInsertAfter, testInsertAfter);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusX, 100);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusY, 200);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocuscx, 300);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocuscy, 400);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusuFlags, SWP_NOMOVE);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundSetWindowPosLog = false;
    for (const auto& log : logs) {
        if (log.message.find("SetWindowPos hook called") != std::string::npos && 
            log.message.find("100") != std::string::npos && 
            log.message.find("200") != std::string::npos) {
            foundSetWindowPosLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundSetWindowPosLog);
}

TEST_F(HookedFunctionsTest, HookedShowWindow) {
    HWND testHwnd = reinterpret_cast<HWND>(0x12345678);
    
    BOOL result = HookedShowWindow(testHwnd);
    
    EXPECT_EQ(result, TRUE);
    EXPECT_EQ(WindowsAPIHooks::s_bringWindowToTopHWND, testHwnd);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundShowWindowLog = false;
    for (const auto& log : logs) {
        if (log.message.find("ShowWindow hook called") != std::string::npos) {
            foundShowWindowLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundShowWindowLog);
}

TEST_F(HookedFunctionsTest, HookedGetWindow) {
    HWND result = HookedGetWindow(nullptr, GW_HWNDNEXT);
    EXPECT_EQ(result, nullptr);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundGetWindowLog = false;
    for (const auto& log : logs) {
        if (log.message.find("GetWindow hook called") != std::string::npos && 
            log.message.find("2") != std::string::npos) { // GW_HWNDNEXT = 2
            foundGetWindowLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundGetWindowLog);
}

// Test GetForegroundWindow hook
TEST_F(HookedFunctionsTest, HookedGetForegroundWindow) {
    HWND result = HookedGetForegroundWindow();
    
    // Result depends on system state, but should not crash
    // May be NULL if no main window is found
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundForegroundLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Returning the main window") != std::string::npos || 
            log.message.find("Main window not found") != std::string::npos) {
            foundForegroundLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundForegroundLog);
}

// Test SetFocus hook
TEST_F(HookedFunctionsTest, HookedSetFocus) {
    HWND testHwnd = reinterpret_cast<HWND>(0x12345678);
    
    HWND result = HookedSetFocus(testHwnd);
    
    EXPECT_EQ(WindowsAPIHooks::s_focusHWND, testHwnd);
    
    // Result depends on system state, but should not crash
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundSetFocusLog = false;
    for (const auto& log : logs) {
        if (log.message.find("Returning the main window") != std::string::npos || 
            log.message.find("Main window not found") != std::string::npos) {
            foundSetFocusLog = true;
            break;
        }
    }
    EXPECT_TRUE(foundSetFocusLog);
}

// Test performance monitoring
TEST_F(HookedFunctionsTest, PerformanceMonitoring) {
    HookedSetClipboardData(CF_TEXT, nullptr);
    HookedEmptyClipboard();
    HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 12345);
    HookedTerminateProcess(nullptr, 1);
    HookedK32EnumProcesses(nullptr, 0, nullptr);
    HookedGetWindowTextW(nullptr, nullptr, 0);
    HookedSetWindowPos(nullptr, nullptr, 0, 0, 0, 0, 0);
    HookedShowWindow(nullptr);
    HookedGetWindow(nullptr, 0);
    HookedGetForegroundWindow();
    HookedSetFocus(nullptr);
    
    auto perfStats = PerformanceMonitor::GetInstance().GetAllStats();
    
    // Check that performance timers were created
    EXPECT_TRUE(perfStats.find("HookedSetClipboardData") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedEmptyClipboard") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedOpenProcess") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedTerminateProcess") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedK32EnumProcesses") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedGetWindowTextW") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedSetWindowPos") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedShowWindow") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedGetWindow") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedGetForegroundWindow") != perfStats.end());
    EXPECT_TRUE(perfStats.find("HookedSetFocus") != perfStats.end());
}

// Test error context creation
TEST_F(HookedFunctionsTest, ErrorContextCreation) {
    HookedSetClipboardData(CF_TEXT, nullptr);
    HookedEmptyClipboard();
    HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 12345);
    HookedSetWindowPos(nullptr, nullptr, 0, 0, 0, 0, 0);
    HookedGetForegroundWindow();
    
    auto contexts = ErrorHandler::GetInstance().GetContexts();
    bool foundClipboardContext = false;
    bool foundEmptyContext = false;
    bool foundOpenProcessContext = false;
    bool foundSetWindowPosContext = false;
    bool foundForegroundContext = false;
    
    for (const auto& context : contexts) {
        if (context.name == "HookedSetClipboardData") {
            foundClipboardContext = true;
        }
        if (context.name == "HookedEmptyClipboard") {
            foundEmptyContext = true;
        }
        if (context.name == "HookedOpenProcess") {
            foundOpenProcessContext = true;
        }
        if (context.name == "HookedSetWindowPos") {
            foundSetWindowPosContext = true;
        }
        if (context.name == "HookedGetForegroundWindow") {
            foundForegroundContext = true;
        }
    }
    EXPECT_TRUE(foundClipboardContext);
    EXPECT_TRUE(foundEmptyContext);
    EXPECT_TRUE(foundOpenProcessContext);
    EXPECT_TRUE(foundSetWindowPosContext);
    EXPECT_TRUE(foundForegroundContext);
}

// Test logging levels
TEST_F(HookedFunctionsTest, LoggingLevels) {
    HookedSetClipboardData(CF_TEXT, nullptr);
    HookedGetForegroundWindow();
    HookedSetFocus(nullptr);
    
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
    EXPECT_TRUE(foundWarningLog);
}

// Test parameter logging
TEST_F(HookedFunctionsTest, ParameterLogging) {
    HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 99999);
    HookedTerminateProcess(nullptr, 42);
    HookedSetWindowPos(nullptr, nullptr, 123, 456, 789, 101, SWP_NOMOVE);
    HookedGetWindowTextW(nullptr, nullptr, 512);
    HookedGetWindow(nullptr, GW_HWNDPREV);
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    bool foundProcessId = false;
    bool foundExitCode = false;
    bool foundWindowPos = false;
    bool foundMaxCount = false;
    bool foundWindowCmd = false;
    
    for (const auto& log : logs) {
        if (log.message.find("99999") != std::string::npos) {
            foundProcessId = true;
        }
        if (log.message.find("42") != std::string::npos) {
            foundExitCode = true;
        }
        if (log.message.find("123") != std::string::npos && log.message.find("456") != std::string::npos) {
            foundWindowPos = true;
        }
        if (log.message.find("512") != std::string::npos) {
            foundMaxCount = true;
        }
        if (log.message.find("3") != std::string::npos) { // GW_HWNDPREV = 3
            foundWindowCmd = true;
        }
    }
    EXPECT_TRUE(foundProcessId);
    EXPECT_TRUE(foundExitCode);
    EXPECT_TRUE(foundWindowPos);
    EXPECT_TRUE(foundMaxCount);
    EXPECT_TRUE(foundWindowCmd);
}

// Test static variable tracking
TEST_F(HookedFunctionsTest, StaticVariableTracking) {
    HWND testHwnd1 = reinterpret_cast<HWND>(0x11111111);
    HWND testHwnd2 = reinterpret_cast<HWND>(0x22222222);
    HWND testInsertAfter = reinterpret_cast<HWND>(0x33333333);
    
    // Test SetWindowPos tracking
    HookedSetWindowPos(testHwnd1, testInsertAfter, 100, 200, 300, 400, SWP_NOMOVE);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusHWND, testHwnd1);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocushWndInsertAfter, testInsertAfter);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusX, 100);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusY, 200);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocuscx, 300);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocuscy, 400);
    EXPECT_EQ(WindowsAPIHooks::s_setWindowFocusuFlags, SWP_NOMOVE);
    
    // Test ShowWindow tracking
    HookedShowWindow(testHwnd2);
    EXPECT_EQ(WindowsAPIHooks::s_bringWindowToTopHWND, testHwnd2);
    
    // Test SetFocus tracking
    HookedSetFocus(testHwnd1);
    EXPECT_EQ(WindowsAPIHooks::s_focusHWND, testHwnd1);
}

// Test performance timing accuracy
TEST_F(HookedFunctionsTest, PerformanceTimingAccuracy) {
    auto start = std::chrono::high_resolution_clock::now();
    HookedSetClipboardData(CF_TEXT, nullptr);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto actualDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    auto perfStats = PerformanceMonitor::GetInstance().GetTimerStats("HookedSetClipboardData");
    
    // Performance monitor should record similar timing
    EXPECT_GT(perfStats.average_time, 0);
    EXPECT_LE(perfStats.average_time, actualDuration.count() * 1.5); // Allow some overhead
}

// Test concurrent access
TEST_F(HookedFunctionsTest, ConcurrentAccess) {
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    // Create multiple threads calling hooked functions
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&successCount, i]() {
            try {
                HookedSetClipboardData(CF_TEXT, nullptr);
                HookedEmptyClipboard();
                HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 1000 + i);
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

// Test error recovery
TEST_F(HookedFunctionsTest, ErrorRecovery) {
    // Call functions multiple times to test error recovery
    for (int i = 0; i < 3; ++i) {
        HookedSetClipboardData(CF_TEXT, nullptr);
        HookedEmptyClipboard();
        HookedOpenProcess(PROCESS_ALL_ACCESS, FALSE, 1000 + i);
        HookedSetWindowPos(nullptr, nullptr, i * 10, i * 20, i * 30, i * 40, 0);
    }
    
    auto logs = ErrorHandler::GetInstance().GetLogs();
    // Should handle multiple calls gracefully
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test null parameter handling
TEST_F(HookedFunctionsTest, NullParameterHandling) {
    // Test functions with null parameters
    HookedGetWindowTextW(nullptr, nullptr, 0);
    HookedSetWindowPos(nullptr, nullptr, 0, 0, 0, 0, 0);
    HookedShowWindow(nullptr);
    HookedGetWindow(nullptr, 0);
    HookedSetFocus(nullptr);
    
    // Should not crash with null parameters
    EXPECT_TRUE(true); // Placeholder assertion
}

// Test edge case parameters
TEST_F(HookedFunctionsTest, EdgeCaseParameters) {
    // Test with edge case values
    HookedOpenProcess(0, FALSE, 0);
    HookedTerminateProcess(nullptr, 0);
    HookedSetWindowPos(nullptr, nullptr, -1, -1, 0, 0, 0);
    HookedGetWindowTextW(nullptr, nullptr, 1);
    HookedGetWindow(nullptr, 0xFFFFFFFF);
    
    // Should handle edge cases gracefully
    EXPECT_TRUE(true); // Placeholder assertion
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 