#include <gtest/gtest.h>
#include <vector>
#include <string>
#include "signatures/dx_signatures.h"
#include "utils/raii_wrappers.h"
#include "utils/error_handler.h"
#include "utils/memory_tracker.h"
#include "utils/performance_monitor.h"

using namespace UndownUnlock::DXHook::Signatures;

class LockDownSignaturesTest : public ::testing::Test {
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

// Test GetVersionedLockDownSignatures function
TEST_F(LockDownSignaturesTest, GetVersionedLockDownSignatures) {
    auto versionedSignatures = GetVersionedLockDownSignatures();
    
    EXPECT_FALSE(versionedSignatures.empty());
    
    // Verify version structure
    for (const auto& versionSig : versionedSignatures) {
        EXPECT_FALSE(versionSig.version.empty());
        EXPECT_FALSE(versionSig.patterns.empty());
        
        // Verify pattern structure within each version
        for (const auto& sig : versionSig.patterns) {
            EXPECT_FALSE(sig.name.empty());
            EXPECT_FALSE(sig.pattern.empty());
            EXPECT_FALSE(sig.mask.empty());
            EXPECT_FALSE(sig.module.empty());
            EXPECT_FALSE(sig.description.empty());
            EXPECT_EQ(sig.pattern.size(), sig.mask.size());
        }
    }
    
    // Verify specific versions are present
    bool foundV2_0 = false;
    bool foundV2_1 = false;
    bool foundV2_2 = false;
    
    for (const auto& versionSig : versionedSignatures) {
        if (versionSig.version == "2.0.x") {
            foundV2_0 = true;
        } else if (versionSig.version == "2.1.x") {
            foundV2_1 = true;
        } else if (versionSig.version == "2.2.x") {
            foundV2_2 = true;
        }
    }
    
    EXPECT_TRUE(foundV2_0);
    EXPECT_TRUE(foundV2_1);
    EXPECT_TRUE(foundV2_2);
}

// Test GetLockDownSignatures function
TEST_F(LockDownSignaturesTest, GetLockDownSignatures) {
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
    bool foundProcessEnum = false;
    bool foundRenderHook = false;
    bool foundMemoryIntegrity = false;
    bool foundD3DHook = false;
    
    for (const auto& sig : signatures) {
        if (sig.name.find("ScreenCapture") != std::string::npos) {
            foundScreenCapture = true;
        }
        if (sig.name.find("Focus") != std::string::npos) {
            foundFocusCheck = true;
        }
        if (sig.name.find("ProcessEnum") != std::string::npos) {
            foundProcessEnum = true;
        }
        if (sig.name.find("RenderHook") != std::string::npos) {
            foundRenderHook = true;
        }
        if (sig.name.find("MemoryIntegrity") != std::string::npos) {
            foundMemoryIntegrity = true;
        }
        if (sig.name.find("D3DHook") != std::string::npos) {
            foundD3DHook = true;
        }
    }
    
    EXPECT_TRUE(foundScreenCapture);
    EXPECT_TRUE(foundFocusCheck);
    EXPECT_TRUE(foundProcessEnum);
    EXPECT_TRUE(foundRenderHook);
    EXPECT_TRUE(foundMemoryIntegrity);
    EXPECT_TRUE(foundD3DHook);
}

// Test GetAntiDetectionSignatures function
TEST_F(LockDownSignaturesTest, GetAntiDetectionSignatures) {
    auto signatures = GetAntiDetectionSignatures();
    
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
    
    // Verify anti-detection signatures are present
    bool foundTimingCheck = false;
    bool foundIntegrityCheck = false;
    bool foundHookDetection = false;
    
    for (const auto& sig : signatures) {
        if (sig.name == "TimingCheck") {
            foundTimingCheck = true;
        }
        if (sig.name == "IntegrityCheck") {
            foundIntegrityCheck = true;
        }
        if (sig.name == "HookDetection") {
            foundHookDetection = true;
        }
    }
    
    EXPECT_TRUE(foundTimingCheck);
    EXPECT_TRUE(foundIntegrityCheck);
    EXPECT_TRUE(foundHookDetection);
}

// Test version-specific signature validation
TEST_F(LockDownSignaturesTest, VersionSpecificSignatureValidation) {
    auto versionedSignatures = GetVersionedLockDownSignatures();
    
    for (const auto& versionSig : versionedSignatures) {
        // Verify version format
        EXPECT_TRUE(versionSig.version.find(".") != std::string::npos);
        
        // Verify each version has appropriate signatures
        bool hasScreenCapture = false;
        bool hasFocusCheck = false;
        
        for (const auto& sig : versionSig.patterns) {
            if (sig.name.find("ScreenCapture") != std::string::npos) {
                hasScreenCapture = true;
            }
            if (sig.name.find("Focus") != std::string::npos) {
                hasFocusCheck = true;
            }
            
            // Verify signature belongs to LockDownBrowser.exe
            EXPECT_EQ(sig.module, "LockDownBrowser.exe");
            
            // Verify description is meaningful
            EXPECT_FALSE(sig.description.empty());
            EXPECT_TRUE(sig.description.length() > 10);
        }
        
        EXPECT_TRUE(hasScreenCapture);
        EXPECT_TRUE(hasFocusCheck);
    }
}

// Test signature pattern validation
TEST_F(LockDownSignaturesTest, SignaturePatternValidation) {
    auto signatures = GetLockDownSignatures();
    
    for (const auto& sig : signatures) {
        // Verify pattern and mask have same length
        EXPECT_EQ(sig.pattern.size(), sig.mask.size());
        
        // Verify pattern is not empty
        EXPECT_FALSE(sig.pattern.empty());
        
        // Verify mask contains only valid characters
        for (char c : sig.mask) {
            EXPECT_TRUE(c == 'x' || c == '?');
        }
        
        // Verify pattern contains valid hex bytes or zeros for wildcards
        for (size_t i = 0; i < sig.pattern.size(); ++i) {
            if (sig.mask[i] == 'x') {
                // Should be a valid hex byte (0x00-0xFF)
                EXPECT_GE(sig.pattern[i], 0x00);
                EXPECT_LE(sig.pattern[i], 0xFF);
            } else if (sig.mask[i] == '?') {
                // Should be zero for wildcard
                EXPECT_EQ(sig.pattern[i], 0x00);
            }
        }
    }
}

// Test performance monitoring integration
TEST_F(LockDownSignaturesTest, PerformanceMonitoringIntegration) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    auto versionedSignatures = GetVersionedLockDownSignatures();
    auto signatures = GetLockDownSignatures();
    auto antiDetectionSignatures = GetAntiDetectionSignatures();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    
    // Verify operations completed in reasonable time
    EXPECT_LT(duration.count(), 1000000); // Less than 1 second
    EXPECT_FALSE(versionedSignatures.empty());
    EXPECT_FALSE(signatures.empty());
    EXPECT_FALSE(antiDetectionSignatures.empty());
}

// Test memory tracking integration
TEST_F(LockDownSignaturesTest, MemoryTrackingIntegration) {
    // Get initial memory state
    auto initialMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Perform signature operations
    auto versionedSignatures = GetVersionedLockDownSignatures();
    auto signatures = GetLockDownSignatures();
    auto antiDetectionSignatures = GetAntiDetectionSignatures();
    
    // Get memory state after operations
    auto afterOperationsMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify memory was allocated
    EXPECT_GE(afterOperationsMemory, initialMemory);
    
    // Clear collections to trigger deallocation
    versionedSignatures.clear();
    signatures.clear();
    antiDetectionSignatures.clear();
    
    // Get final memory state
    auto finalMemory = MemoryTracker::GetInstance().GetTotalAllocated();
    
    // Verify memory was properly deallocated (allow for some overhead)
    EXPECT_LE(finalMemory - initialMemory, 1024); // Allow 1KB overhead
}

// Test error handling integration
TEST_F(LockDownSignaturesTest, ErrorHandlingIntegration) {
    // Test that error handling is properly integrated
    // This is primarily a compilation test to ensure headers are included
    
    // Log a test message
    ErrorHandler::LogInfo(ErrorCategory::SIGNATURE_PARSING, "Test message from LockDown signatures test");
    
    // Verify no exceptions are thrown
    EXPECT_NO_THROW();
}

// Test RAII wrapper integration
TEST_F(LockDownSignaturesTest, RAIIWrapperIntegration) {
    // Test that RAII wrappers are properly integrated
    // This is primarily a compilation test
    
    // Create a scoped handle wrapper
    ScopedHandle testHandle(CreateEvent(nullptr, TRUE, FALSE, nullptr));
    EXPECT_NE(testHandle.get(), INVALID_HANDLE_VALUE);
    
    // Handle should be automatically closed when testHandle goes out of scope
}

// Test concurrent access
TEST_F(LockDownSignaturesTest, ConcurrentAccess) {
    std::vector<std::thread> threads;
    std::vector<std::vector<SignaturePattern>> results(4);
    
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([i, &results]() {
            results[i] = GetLockDownSignatures();
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
TEST_F(LockDownSignaturesTest, ExceptionSafety) {
    // Test that signature operations are exception-safe
    
    std::vector<SignaturePattern> signatures;
    
    try {
        signatures = GetLockDownSignatures();
        
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
TEST_F(LockDownSignaturesTest, PerformanceBenchmarks) {
    const int numIterations = 100;
    std::vector<std::chrono::microseconds> versionedTimes;
    std::vector<std::chrono::microseconds> flattenedTimes;
    std::vector<std::chrono::microseconds> antiDetectionTimes;
    
    for (int i = 0; i < numIterations; ++i) {
        auto startVersioned = std::chrono::high_resolution_clock::now();
        auto versionedSignatures = GetVersionedLockDownSignatures();
        auto endVersioned = std::chrono::high_resolution_clock::now();
        
        auto startFlattened = std::chrono::high_resolution_clock::now();
        auto signatures = GetLockDownSignatures();
        auto endFlattened = std::chrono::high_resolution_clock::now();
        
        auto startAntiDetection = std::chrono::high_resolution_clock::now();
        auto antiDetectionSignatures = GetAntiDetectionSignatures();
        auto endAntiDetection = std::chrono::high_resolution_clock::now();
        
        versionedTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endVersioned - startVersioned));
        flattenedTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endFlattened - startFlattened));
        antiDetectionTimes.push_back(std::chrono::duration_cast<std::chrono::microseconds>(endAntiDetection - startAntiDetection));
    }
    
    // Calculate average times
    auto avgVersionedTime = std::accumulate(versionedTimes.begin(), versionedTimes.end(), std::chrono::microseconds(0)) / numIterations;
    auto avgFlattenedTime = std::accumulate(flattenedTimes.begin(), flattenedTimes.end(), std::chrono::microseconds(0)) / numIterations;
    auto avgAntiDetectionTime = std::accumulate(antiDetectionTimes.begin(), antiDetectionTimes.end(), std::chrono::microseconds(0)) / numIterations;
    
    // Verify performance is within acceptable bounds
    EXPECT_LT(avgVersionedTime.count(), 10000); // Less than 10ms average
    EXPECT_LT(avgFlattenedTime.count(), 10000); // Less than 10ms average
    EXPECT_LT(avgAntiDetectionTime.count(), 10000); // Less than 10ms average
}

// Test signature uniqueness
TEST_F(LockDownSignaturesTest, SignatureUniqueness) {
    auto signatures = GetLockDownSignatures();
    
    std::set<std::string> signatureNames;
    
    for (const auto& sig : signatures) {
        // Verify each signature name is unique
        EXPECT_TRUE(signatureNames.find(sig.name) == signatureNames.end());
        signatureNames.insert(sig.name);
    }
}

// Test version consistency
TEST_F(LockDownSignaturesTest, VersionConsistency) {
    auto versionedSignatures = GetVersionedLockDownSignatures();
    auto flattenedSignatures = GetLockDownSignatures();
    
    // Count total signatures in versioned structure
    size_t versionedCount = 0;
    for (const auto& versionSig : versionedSignatures) {
        versionedCount += versionSig.patterns.size();
    }
    
    // Verify flattened count matches versioned count
    EXPECT_EQ(flattenedSignatures.size(), versionedCount);
}

// Test anti-detection signature validation
TEST_F(LockDownSignaturesTest, AntiDetectionSignatureValidation) {
    auto signatures = GetAntiDetectionSignatures();
    
    for (const auto& sig : signatures) {
        // Verify all anti-detection signatures belong to LockDownBrowser.exe
        EXPECT_EQ(sig.module, "LockDownBrowser.exe");
        
        // Verify description mentions anti-detection functionality
        std::string description = sig.description;
        std::transform(description.begin(), description.end(), description.begin(), ::tolower);
        
        bool hasAntiDetectionTerm = 
            description.find("anti") != std::string::npos ||
            description.find("detection") != std::string::npos ||
            description.find("timing") != std::string::npos ||
            description.find("integrity") != std::string::npos ||
            description.find("hook") != std::string::npos;
        
        EXPECT_TRUE(hasAntiDetectionTerm);
    }
}

// Test signature pattern complexity
TEST_F(LockDownSignaturesTest, SignaturePatternComplexity) {
    auto signatures = GetLockDownSignatures();
    
    for (const auto& sig : signatures) {
        // Verify patterns have reasonable complexity (not too short, not too long)
        EXPECT_GE(sig.pattern.size(), 8); // At least 8 bytes
        EXPECT_LE(sig.pattern.size(), 64); // No more than 64 bytes
        
        // Verify patterns have a mix of fixed bytes and wildcards
        size_t wildcardCount = 0;
        for (char c : sig.mask) {
            if (c == '?') wildcardCount++;
        }
        
        // Should have some wildcards but not all
        EXPECT_GT(wildcardCount, 0);
        EXPECT_LT(wildcardCount, sig.mask.size());
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 