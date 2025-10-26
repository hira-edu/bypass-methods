#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <unordered_map>
#include "signatures/dx_signatures.h"
#include "utils/raii_wrappers.h"
#include "utils/error_handler.h"
#include "utils/memory_tracker.h"
#include "utils/performance_monitor.h"

using namespace UndownUnlock::DXHook::Signatures;

class DXSignaturesTest : public ::testing::Test {
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
        // Shutdown utility components
        PerformanceMonitor::Shutdown();
        MemoryTracker::Shutdown();
        ErrorHandler::Shutdown();
    }
};

// Test pattern parsing functionality
TEST_F(DXSignaturesTest, ParsePatternValid) {
    std::string pattern = "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 40";
    
    auto result = ParsePattern(pattern);
    
    EXPECT_FALSE(result.first.empty());
    EXPECT_FALSE(result.second.empty());
    EXPECT_EQ(result.first.size(), result.second.size());
    
    // Verify specific bytes
    EXPECT_EQ(result.first[0], 0x48);
    EXPECT_EQ(result.first[1], 0x89);
    EXPECT_EQ(result.first[2], 0x5C);
    EXPECT_EQ(result.first[3], 0x24);
    EXPECT_EQ(result.first[4], 0x00); // Wildcard byte
    
    // Verify mask
    EXPECT_EQ(result.second[0], 'x');
    EXPECT_EQ(result.second[1], 'x');
    EXPECT_EQ(result.second[2], 'x');
    EXPECT_EQ(result.second[3], 'x');
    EXPECT_EQ(result.second[4], '?'); // Wildcard mask
}

// Test pattern parsing with invalid hex
TEST_F(DXSignaturesTest, ParsePatternInvalidHex) {
    std::string pattern = "48 89 5C 24 ? 48 89 INVALID 57 48 83 EC 40";
    
    auto result = ParsePattern(pattern);
    
    EXPECT_FALSE(result.first.empty());
    EXPECT_FALSE(result.second.empty());
    EXPECT_EQ(result.first.size(), result.second.size());
    
    // Invalid token should be converted to wildcard
    EXPECT_EQ(result.second[5], '?');
    EXPECT_EQ(result.first[5], 0x00);
}

// Test pattern parsing with empty pattern
TEST_F(DXSignaturesTest, ParsePatternEmpty) {
    std::string pattern = "";
    
    auto result = ParsePattern(pattern);
    
    EXPECT_TRUE(result.first.empty());
    EXPECT_TRUE(result.second.empty());
}

// Test pattern parsing with only wildcards
TEST_F(DXSignaturesTest, ParsePatternOnlyWildcards) {
    std::string pattern = "? ? ? ? ?";
    
    auto result = ParsePattern(pattern);
    
    EXPECT_EQ(result.first.size(), 5);
    EXPECT_EQ(result.second.size(), 5);
    
    for (size_t i = 0; i < result.first.size(); ++i) {
        EXPECT_EQ(result.first[i], 0x00);
        EXPECT_EQ(result.second[i], '?');
    }
}

// Test GetDXSignatures function
TEST_F(DXSignaturesTest, GetDXSignatures) {
    auto signatures = GetDXSignatures();
    
    EXPECT_FALSE(signatures.empty());
    
    // Verify signature structure
    for (const auto& sig : signatures) {
        EXPECT_FALSE(sig.name.empty());
        EXPECT_FALSE(sig.pattern.empty());
        EXPECT_FALSE(sig.mask.empty());
        EXPECT_FALSE(sig.module.empty());
        EXPECT_FALSE(sig.description.empty());
        EXPECT_EQ(sig.pattern.size(), sig.mask.size());
    }
    
    // Verify specific signatures are present
    bool foundD3D11Create = false;
    bool foundCreateDXGI = false;
    
    for (const auto& sig : signatures) {
        if (sig.name.find("D3D11Create") != std::string::npos) {
            foundD3D11Create = true;
        }
        if (sig.name.find("CreateDXGI") != std::string::npos) {
            foundCreateDXGI = true;
        }
    }
    
    EXPECT_TRUE(foundD3D11Create);
    EXPECT_TRUE(foundCreateDXGI);
}

// Test GetLockDownSignatures function
TEST_F(DXSignaturesTest, GetLockDownSignatures) {
    auto signatures = GetLockDownSignatures();
    
    EXPECT_FALSE(signatures.empty());
    
    // Verify signature structure
    for (const auto& sig : signatures) {
        EXPECT_FALSE(sig.name.empty());
        EXPECT_FALSE(sig.pattern.empty());
        EXPECT_FALSE(sig.mask.empty());
        EXPECT_FALSE(sig.module.empty());
        EXPECT_FALSE(sig.description.empty());
        EXPECT_EQ(sig.pattern.size(), sig.mask.size());
    }
    
    // Verify LockDown-specific signatures are present
    bool foundScreenCapture = false;
    bool foundFocusCheck = false;
    
    for (const auto& sig : signatures) {
        if (sig.name.find("ScreenCapture") != std::string::npos) {
            foundScreenCapture = true;
        }
        if (sig.name.find("Focus") != std::string::npos) {
            foundFocusCheck = true;
        }
    }
    
    EXPECT_TRUE(foundScreenCapture);
    EXPECT_TRUE(foundFocusCheck);
}

TEST_F(DXSignaturesTest, GetExamClientVendorSignatures) {
    auto proProctor = GetProProctorSignatures();
    auto ets = GetETSSecureBrowserSignatures();
    auto prometric = GetPrometricSignatures();
    auto aggregate = GetAllExamClientSignatures();

    auto validate = [](const std::vector<SignaturePattern>& signatures) {
        EXPECT_FALSE(signatures.empty());
        for (const auto& sig : signatures) {
            EXPECT_FALSE(sig.name.empty());
            EXPECT_FALSE(sig.pattern.empty());
            EXPECT_FALSE(sig.mask.empty());
            EXPECT_FALSE(sig.module.empty());
        }
    };

    validate(proProctor);
    validate(ets);
    validate(pometric);
    validate(aggregate);

    EXPECT_GE(aggregate.size(), proProctor.size());
    EXPECT_GE(aggregate.size(), ets.size());
    EXPECT_GE(aggregate.size(), prometric.size());
}

// Test GetDXInterfaces function
TEST_F(DXSignaturesTest, GetDXInterfaces) {
    auto interfaces = GetDXInterfaces();
    
    EXPECT_FALSE(interfaces.empty());
    
    // Verify interface structure
    for (const auto& [name, interface] : interfaces) {
        EXPECT_FALSE(name.empty());
        EXPECT_FALSE(interface.name.empty());
        EXPECT_FALSE(interface.iid.empty());
        EXPECT_FALSE(interface.methods.empty());
        EXPECT_GT(interface.version, 0);
    }
    
    // Verify specific interfaces are present
    EXPECT_TRUE(interfaces.find("IDXGISwapChain") != interfaces.end());
    EXPECT_TRUE(interfaces.find("IDXGISwapChain1") != interfaces.end());
    
    // Verify IDXGISwapChain interface details
    const auto& swapChain = interfaces["IDXGISwapChain"];
    EXPECT_EQ(swapChain.name, "IDXGISwapChain");
    EXPECT_EQ(swapChain.iid, "2411E7E1-12AC-4CCF-BD14-9798E8534DC0");
    EXPECT_EQ(swapChain.version, 1);
    
    // Verify required methods are present
    bool foundPresent = false;
    bool foundQueryInterface = false;
    
    for (const auto& method : swapChain.methods) {
        if (method == "Present") {
            foundPresent = true;
        }
        if (method == "QueryInterface") {
            foundQueryInterface = true;
        }
    }
    
    EXPECT_TRUE(foundPresent);
    EXPECT_TRUE(foundQueryInterface);
}

// Test GetPresentOffset function with null pointer
TEST_F(DXSignaturesTest, GetPresentOffsetNullPointer) {
    int offset = GetPresentOffset(nullptr);
    EXPECT_EQ(offset, -1);
}

// Test GetPresentOffset function with valid pointer (mocked)
TEST_F(DXSignaturesTest, GetPresentOffsetValidPointer) {
    // Create a mock swap chain pointer
    // In a real test, this would be a properly initialized COM interface
    void* mockSwapChain = reinterpret_cast<void*>(0x12345678);
    
    // This test primarily verifies the function doesn't crash
    // The actual offset value depends on the COM interface implementation
    int offset = GetPresentOffset(mockSwapChain);
    
    // Should return a valid offset or -1 if interface query fails
    EXPECT_TRUE(offset == -1 || offset >= 0);
}

// Test performance monitoring integration
TEST_F(DXSignaturesTest, PerformanceMonitoringIntegration) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    auto signatures = GetDXSignatures();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    
    // Verify operation completed in reasonable time
    EXPECT_LT(duration.count(), 1000000); // Less than 1 second
    EXPECT_FALSE(signatures.empty());
}

// Test memory tracking integration
TEST_F(DXSignaturesTest, MemoryTrackingIntegration) {
    // Get initial memory state
    auto initialMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Perform signature operations
    auto signatures = GetDXSignatures();
    auto lockDownSignatures = GetLockDownSignatures();
    auto interfaces = GetDXInterfaces();
    
    // Get memory state after operations
    auto afterOperationsMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify memory was allocated
    EXPECT_GE(afterOperationsMemory, initialMemory);
    
    // Clear collections to trigger deallocation
    signatures.clear();
    lockDownSignatures.clear();
    interfaces.clear();
    
    // Get final memory state
    auto finalMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify memory was properly deallocated (allow for some overhead)
    EXPECT_LE(finalMemory - initialMemory, 1024); // Allow 1KB overhead
}

// Test error handling integration
TEST_F(DXSignaturesTest, ErrorHandlingIntegration) {
    // Test pattern parsing with malformed input
    std::string malformedPattern = "48 89 5C 24 ? 48 89 INVALID_HEX 57";
    
    // Should not throw exception, should handle gracefully
    EXPECT_NO_THROW({
        auto result = ParsePattern(malformedPattern);
        EXPECT_FALSE(result.first.empty());
    });
}

// Test RAII wrapper integration
TEST_F(DXSignaturesTest, RAIIWrapperIntegration) {
    // Test that RAII wrappers are properly integrated
    // This is primarily a compilation test
    
    // Create a scoped handle wrapper
    ScopedHandle testHandle(CreateEvent(nullptr, TRUE, FALSE, nullptr));
    EXPECT_NE(testHandle.get(), INVALID_HANDLE_VALUE);
    
    // Handle should be automatically closed when testHandle goes out of scope
}

// Test concurrent access
TEST_F(DXSignaturesTest, ConcurrentAccess) {
    std::vector<std::thread> threads;
    std::vector<std::vector<SignaturePattern>> results(4);
    
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([i, &results]() {
            results[i] = GetDXSignatures();
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify all threads got results
    for (const auto& result : results) {
        EXPECT_FALSE(result.empty());
    }
    
    // Verify results are consistent
    for (size_t i = 1; i < results.size(); ++i) {
        EXPECT_EQ(results[i].size(), results[0].size());
    }
}

// Test exception safety
TEST_F(DXSignaturesTest, ExceptionSafety) {
    // Test that signature operations are exception-safe
    
    std::vector<SignaturePattern> signatures;
    
    try {
        signatures = GetDXSignatures();
        
        // Simulate an exception during operation
        throw std::runtime_error("Test exception");
        
    } catch (const std::exception& e) {
        // Exception was thrown as expected
        EXPECT_STREQ(e.what(), "Test exception");
    }
    
    // Verify signatures were still populated before exception
    EXPECT_FALSE(signatures.empty());
}

// Test performance benchmarks
TEST_F(DXSignaturesTest, PerformanceBenchmarks) {
    const int numIterations = 100;
    std::vector<std::chrono::microseconds> parseTimes;
    std::vector<std::chrono::microseconds> signatureTimes;
    
    std::string testPattern = "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 40";
    
    for (int i = 0; i < numIterations; ++i) {
        auto startParse = std::chrono::high_resolution_clock::now();
        auto parseResult = ParsePattern(testPattern);
        auto endParse = std::chrono::high_resolution_clock::now();
        
        auto startSignatures = std::chrono::high_resolution_clock::now();
        auto signatures = GetDXSignatures();
        auto endSignatures = std::chrono::high_resolution_clock::now();
        
        parseTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endParse - startParse));
        signatureTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endSignatures - startSignatures));
    }
    
    // Calculate average times
    auto avgParseTime = std::accumulate(parseTimes.begin(), parseTimes.end(), std::chrono::microseconds(0)) / numIterations;
    auto avgSignatureTime = std::accumulate(signatureTimes.begin(), signatureTimes.end(), std::chrono::microseconds(0)) / numIterations;
    
    // Verify performance is within acceptable bounds
    EXPECT_LT(avgParseTime.count(), 1000); // Less than 1ms average parsing
    EXPECT_LT(avgSignatureTime.count(), 10000); // Less than 10ms average signature loading
}

// Test signature validation
TEST_F(DXSignaturesTest, SignatureValidation) {
    auto signatures = GetDXSignatures();
    
    for (const auto& sig : signatures) {
        // Verify pattern and mask have same length
        EXPECT_EQ(sig.pattern.size(), sig.mask.size());
        
        // Verify pattern is not empty
        EXPECT_FALSE(sig.pattern.empty());
        
        // Verify mask contains only valid characters
        for (char c : sig.mask) {
            EXPECT_TRUE(c == 'x' || c == '?');
        }
        
        // Verify name is not empty
        EXPECT_FALSE(sig.name.empty());
        
        // Verify module is not empty
        EXPECT_FALSE(sig.module.empty());
    }
}

// Test interface validation
TEST_F(DXSignaturesTest, InterfaceValidation) {
    auto interfaces = GetDXInterfaces();
    
    for (const auto& [name, interface] : interfaces) {
        // Verify interface name matches key
        EXPECT_EQ(interface.name, name);
        
        // Verify IID is valid UUID format
        EXPECT_EQ(interface.iid.length(), 36); // UUID length
        EXPECT_EQ(interface.iid[8], '-');
        EXPECT_EQ(interface.iid[13], '-');
        EXPECT_EQ(interface.iid[18], '-');
        EXPECT_EQ(interface.iid[23], '-');
        
        // Verify methods list is not empty
        EXPECT_FALSE(interface.methods.empty());
        
        // Verify version is positive
        EXPECT_GT(interface.version, 0);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
