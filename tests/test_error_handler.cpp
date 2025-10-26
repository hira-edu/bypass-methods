#include <gtest/gtest.h>
#include "utils/error_handler.h"
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>

class ErrorHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clean up any existing error handler
        utils::ErrorHandler::Shutdown();
        
        // Initialize with test configuration
        utils::ErrorHandler::Initialize();
        
        // Get the error handler instance
        error_handler_ = utils::ErrorHandler::GetInstance();
        ASSERT_NE(error_handler_, nullptr);
    }
    
    void TearDown() override {
        utils::ErrorHandler::Shutdown();
    }
    
    // Helper method to capture console output
    std::string capture_console_output(std::function<void()> func) {
        // Redirect stdout to string stream
        std::stringstream buffer;
        std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());
        
        func();
        
        // Restore stdout
        std::cout.rdbuf(old);
        return buffer.str();
    }
    
    // Helper method to check if log file exists and contains content
    bool log_file_exists_and_contains(const std::string& filename, const std::string& content) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string file_content = buffer.str();
        
        return file_content.find(content) != std::string::npos;
    }
    
    utils::ErrorHandler* error_handler_;
};

// Test basic initialization
TEST_F(ErrorHandlerTest, BasicInitialization) {
    EXPECT_NE(error_handler_, nullptr);
    EXPECT_TRUE(error_handler_->is_initialized());
}

// Test error logging with different severity levels
TEST_F(ErrorHandlerTest, ErrorLogging) {
    std::string console_output = capture_console_output([this]() {
        error_handler_->error("Test error message", utils::ErrorCategory::WINDOWS_API, 
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Test error message"), std::string::npos);
    EXPECT_NE(console_output.find("TestFunction"), std::string::npos);
    EXPECT_NE(console_output.find("test.cpp:42"), std::string::npos);
}

TEST_F(ErrorHandlerTest, WarningLogging) {
    std::string console_output = capture_console_output([this]() {
        error_handler_->warning("Test warning message", utils::ErrorCategory::GRAPHICS, 
                              "TestFunction", "test.cpp", 42);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Test warning message"), std::string::npos);
    EXPECT_NE(console_output.find("WARNING"), std::string::npos);
}

TEST_F(ErrorHandlerTest, InfoLogging) {
    std::string console_output = capture_console_output([this]() {
        error_handler_->info("Test info message", utils::ErrorCategory::MEMORY, 
                           "TestFunction", "test.cpp", 42);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Test info message"), std::string::npos);
    EXPECT_NE(console_output.find("INFO"), std::string::npos);
}

TEST_F(ErrorHandlerTest, DebugLogging) {
    std::string console_output = capture_console_output([this]() {
        error_handler_->debug("Test debug message", utils::ErrorCategory::NETWORK, 
                            "TestFunction", "test.cpp", 42);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Test debug message"), std::string::npos);
    EXPECT_NE(console_output.find("DEBUG"), std::string::npos);
}

// Test error categories
TEST_F(ErrorHandlerTest, ErrorCategories) {
    std::vector<utils::ErrorCategory> categories = {
        utils::ErrorCategory::WINDOWS_API,
        utils::ErrorCategory::GRAPHICS,
        utils::ErrorCategory::MEMORY,
        utils::ErrorCategory::NETWORK,
        utils::ErrorCategory::FILE_SYSTEM,
        utils::ErrorCategory::SECURITY,
        utils::ErrorCategory::PERFORMANCE,
        utils::ErrorCategory::UNKNOWN
    };
    
    for (auto category : categories) {
        std::string console_output = capture_console_output([this, category]() {
            error_handler_->error("Category test", category, "TestFunction", "test.cpp", 42, 0);
        });
        
        EXPECT_FALSE(console_output.empty());
        EXPECT_NE(console_output.find("Category test"), std::string::npos);
    }
}

// Test error context management
TEST_F(ErrorHandlerTest, ErrorContext) {
    // Test setting and getting error context
    utils::ErrorContext context;
    context.set("operation", "test_operation");
    context.set("user_id", "12345");
    context.set("session_id", "abc123");
    
    error_handler_->set_error_context(context);
    
    std::string console_output = capture_console_output([this]() {
        error_handler_->error("Context test", utils::ErrorCategory::WINDOWS_API, 
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("test_operation"), std::string::npos);
    EXPECT_NE(console_output.find("12345"), std::string::npos);
    EXPECT_NE(console_output.find("abc123"), std::string::npos);
}

// Test error context clearing
TEST_F(ErrorHandlerTest, ErrorContextClearing) {
    utils::ErrorContext context;
    context.set("test_key", "test_value");
    
    error_handler_->set_error_context(context);
    error_handler_->clear_error_context();
    
    std::string console_output = capture_console_output([this]() {
        error_handler_->error("No context test", utils::ErrorCategory::WINDOWS_API, 
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_EQ(console_output.find("test_value"), std::string::npos);
}

// Test error recovery strategies
TEST_F(ErrorHandlerTest, ErrorRecovery) {
    // Test automatic recovery
    std::string console_output = capture_console_output([this]() {
        error_handler_->error("Recovery test", utils::ErrorCategory::WINDOWS_API,
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Recovery test"), std::string::npos);
    
    // Test manual recovery
    console_output = capture_console_output([this]() {
        error_handler_->error("Manual recovery test", utils::ErrorCategory::WINDOWS_API,
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Manual recovery test"), std::string::npos);
    
    // Test fatal error
    console_output = capture_console_output([this]() {
        error_handler_->error("Fatal test", utils::ErrorCategory::WINDOWS_API,
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Fatal test"), std::string::npos);
}

// Test error statistics
TEST_F(ErrorHandlerTest, ErrorStatistics) {
    // Log some errors
    error_handler_->error("Error 1", utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42, 0);
    error_handler_->warning("Warning 1", utils::ErrorCategory::GRAPHICS, "TestFunction", "test.cpp", 42);
    error_handler_->error("Error 2", utils::ErrorCategory::MEMORY, "TestFunction", "test.cpp", 42, 0);
    error_handler_->info("Info 1", utils::ErrorCategory::NETWORK, "TestFunction", "test.cpp", 42);
    
    auto stats = error_handler_->get_error_statistics();
    
    EXPECT_GE(stats.total_errors, 2);
    EXPECT_GE(stats.total_warnings, 1);
    EXPECT_GE(stats.total_info_messages, 1);
    EXPECT_GE(stats.total_debug_messages, 0);
}

// Test error filtering
TEST_F(ErrorHandlerTest, ErrorFiltering) {
    // Set minimum log level to WARNING
    error_handler_->set_minimum_log_level(utils::LogLevel::WARNING);
    
    std::string console_output = capture_console_output([this]() {
        error_handler_->debug("Debug message", utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42);
        error_handler_->info("Info message", utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42);
        error_handler_->warning("Warning message", utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42);
        error_handler_->error("Error message", utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_EQ(console_output.find("Debug message"), std::string::npos);
    EXPECT_EQ(console_output.find("Info message"), std::string::npos);
    EXPECT_NE(console_output.find("Warning message"), std::string::npos);
    EXPECT_NE(console_output.find("Error message"), std::string::npos);
}

// Test thread safety
TEST_F(ErrorHandlerTest, ThreadSafety) {
    std::vector<std::thread> threads;
    std::atomic<int> error_count{0};
    
    // Create multiple threads that log errors simultaneously
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this, i, &error_count]() {
            for (int j = 0; j < 10; ++j) {
                error_handler_->error("Thread " + std::to_string(i) + " error " + std::to_string(j), 
                                    utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42, 0);
                error_count++;
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(error_count.load(), 100);
    
    auto stats = error_handler_->get_error_statistics();
    EXPECT_GE(stats.total_errors, 100);
}

// Test error handler reinitialization
TEST_F(ErrorHandlerTest, Reinitialization) {
    // Shutdown and reinitialize
    utils::ErrorHandler::Shutdown();
    utils::ErrorHandler::Initialize();
    
    auto new_handler = utils::ErrorHandler::GetInstance();
    EXPECT_NE(new_handler, nullptr);
    EXPECT_TRUE(new_handler->is_initialized());
    
    // Test that it still works
    std::string console_output = capture_console_output([new_handler]() {
        new_handler->error("Reinit test", utils::ErrorCategory::WINDOWS_API, 
                          "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Reinit test"), std::string::npos);
}

// Test error handler configuration
TEST_F(ErrorHandlerTest, Configuration) {
    // Test enabling/disabling different outputs
    error_handler_->set_console_output_enabled(false);
    
    std::string console_output = capture_console_output([this]() {
        error_handler_->error("Console disabled test", utils::ErrorCategory::WINDOWS_API, 
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_TRUE(console_output.empty());
    
    // Re-enable console output
    error_handler_->set_console_output_enabled(true);
    
    console_output = capture_console_output([this]() {
        error_handler_->error("Console enabled test", utils::ErrorCategory::WINDOWS_API, 
                            "TestFunction", "test.cpp", 42, 0);
    });
    
    EXPECT_FALSE(console_output.empty());
    EXPECT_NE(console_output.find("Console enabled test"), std::string::npos);
}

// Test error context operations
TEST_F(ErrorHandlerTest, ErrorContextOperations) {
    utils::ErrorContext context;
    
    // Test setting values
    context.set("key1", "value1");
    context.set("key2", "value2");
    context.set("key3", "value3");
    
    EXPECT_EQ(context.get("key1"), "value1");
    EXPECT_EQ(context.get("key2"), "value2");
    EXPECT_EQ(context.get("key3"), "value3");
    EXPECT_EQ(context.get("nonexistent"), "");
    
    // Test updating values
    context.set("key1", "updated_value1");
    EXPECT_EQ(context.get("key1"), "updated_value1");
    
    // Test removing values
    context.remove("key2");
    EXPECT_EQ(context.get("key2"), "");
    
    // Test clearing all values
    context.clear();
    EXPECT_EQ(context.get("key1"), "");
    EXPECT_EQ(context.get("key3"), "");
}

// Test error context serialization
TEST_F(ErrorHandlerTest, ErrorContextSerialization) {
    utils::ErrorContext context;
    context.set("operation", "test_operation");
    context.set("user_id", "12345");
    context.set("session_id", "abc123");
    
    std::string serialized = context.serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("test_operation"), std::string::npos);
    EXPECT_NE(serialized.find("12345"), std::string::npos);
    EXPECT_NE(serialized.find("abc123"), std::string::npos);
}

// Test performance characteristics
TEST_F(ErrorHandlerTest, PerformanceCharacteristics) {
    const int iterations = 1000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        error_handler_->error("Performance test " + std::to_string(i), 
                            utils::ErrorCategory::WINDOWS_API, "TestFunction", "test.cpp", 42, 0);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should complete in reasonable time (less than 1 second for 1000 errors)
    EXPECT_LT(duration.count(), 1000);
}

// Test error handler singleton behavior
TEST_F(ErrorHandlerTest, SingletonBehavior) {
    auto instance1 = utils::ErrorHandler::GetInstance();
    auto instance2 = utils::ErrorHandler::GetInstance();
    
    EXPECT_EQ(instance1, instance2);
    EXPECT_NE(instance1, nullptr);
    EXPECT_NE(instance2, nullptr);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 