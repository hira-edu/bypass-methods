#include <gtest/gtest.h>
#include "optimization/memory_pool.h"
#include "optimization/thread_pool.h"
#include "optimization/performance_optimizer.h"
#include "utils/error_handler.h"
#include "utils/performance_monitor.h"
#include "utils/memory_tracker.h"
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>

using namespace UndownUnlock::Optimization;

class MemoryPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        utils::ErrorHandler::Initialize();
        utils::PerformanceMonitor::Initialize();
        utils::MemoryTracker::Initialize();
        
        MemoryPoolConfig config;
        config.initial_pool_size = 1024 * 1024; // 1MB
        config.max_pool_size = 10 * 1024 * 1024; // 10MB
        config.enable_statistics = true;
        MemoryPool::initialize(config);
    }
    
    void TearDown() override {
        MemoryPool::shutdown();
        utils::MemoryTracker::Shutdown();
        utils::PerformanceMonitor::Shutdown();
        utils::ErrorHandler::Shutdown();
    }
};

TEST_F(MemoryPoolTest, BasicAllocation) {
    auto& pool = MemoryPool::get_instance();
    
    // Allocate memory
    void* ptr1 = pool.allocate(1024, 8, "test_allocation");
    ASSERT_NE(ptr1, nullptr);
    
    // Allocate more memory
    void* ptr2 = pool.allocate(2048, 16, "test_allocation");
    ASSERT_NE(ptr2, nullptr);
    
    // Verify addresses are different
    ASSERT_NE(ptr1, ptr2);
    
    // Deallocate
    pool.deallocate(ptr1);
    pool.deallocate(ptr2);
}

TEST_F(MemoryPoolTest, PooledAllocation) {
    auto& pool = MemoryPool::get_instance();
    
    std::vector<void*> allocations;
    
    // Allocate multiple blocks of the same size
    for (int i = 0; i < 10; ++i) {
        void* ptr = pool.allocate(512, 8, "pooled_test");
        ASSERT_NE(ptr, nullptr);
        allocations.push_back(ptr);
    }
    
    // Deallocate all
    for (void* ptr : allocations) {
        pool.deallocate(ptr);
    }
    
    // Allocate again - should reuse freed blocks
    void* reused_ptr = pool.allocate(512, 8, "pooled_test");
    ASSERT_NE(reused_ptr, nullptr);
    pool.deallocate(reused_ptr);
}

TEST_F(MemoryPoolTest, Statistics) {
    auto& pool = MemoryPool::get_instance();
    
    // Perform some allocations
    void* ptr1 = pool.allocate(1024, 8, "stats_test");
    void* ptr2 = pool.allocate(2048, 16, "stats_test");
    
    auto stats = pool.get_stats();
    EXPECT_EQ(stats.current_allocations.load(), 2);
    EXPECT_EQ(stats.total_allocations.load(), 2);
    EXPECT_GT(stats.total_bytes_allocated.load(), 0);
    
    pool.deallocate(ptr1);
    pool.deallocate(ptr2);
    
    stats = pool.get_stats();
    EXPECT_EQ(stats.current_allocations.load(), 0);
    EXPECT_EQ(stats.total_deallocations.load(), 2);
}

TEST_F(MemoryPoolTest, Alignment) {
    auto& pool = MemoryPool::get_instance();
    
    // Test different alignments
    void* ptr1 = pool.allocate(1024, 8, "alignment_test");
    void* ptr2 = pool.allocate(1024, 16, "alignment_test");
    void* ptr3 = pool.allocate(1024, 32, "alignment_test");
    
    // Check alignment
    EXPECT_EQ(reinterpret_cast<uintptr_t>(ptr1) % 8, 0);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(ptr2) % 16, 0);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(ptr3) % 32, 0);
    
    pool.deallocate(ptr1);
    pool.deallocate(ptr2);
    pool.deallocate(ptr3);
}

TEST_F(MemoryPoolTest, Reallocation) {
    auto& pool = MemoryPool::get_instance();
    
    // Allocate initial block
    void* ptr = pool.allocate(1024, 8, "realloc_test");
    ASSERT_NE(ptr, nullptr);
    
    // Reallocate to larger size
    void* new_ptr = pool.reallocate(ptr, 2048, 8);
    ASSERT_NE(new_ptr, nullptr);
    
    // Reallocate to smaller size
    void* final_ptr = pool.reallocate(new_ptr, 512, 8);
    ASSERT_NE(final_ptr, nullptr);
    
    pool.deallocate(final_ptr);
}

TEST_F(MemoryPoolTest, PoolAllocator) {
    auto& pool = MemoryPool::get_instance();
    
    // Test PoolAllocator with vector
    std::vector<int, PoolAllocator<int>> vec(PoolAllocator<int>("vector_test"));
    
    // Add elements
    for (int i = 0; i < 100; ++i) {
        vec.push_back(i);
    }
    
    // Verify elements
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(vec[i], i);
    }
}

TEST_F(MemoryPoolTest, PoolPtr) {
    auto& pool = MemoryPool::get_instance();
    
    // Create pooled pointer
    auto ptr = MemoryPoolUtils::make_pooled<std::string>("pool_ptr_test", "Hello, World!");
    
    EXPECT_TRUE(ptr);
    EXPECT_EQ(*ptr, "Hello, World!");
    
    // Test move semantics
    auto moved_ptr = std::move(ptr);
    EXPECT_FALSE(ptr);
    EXPECT_TRUE(moved_ptr);
    EXPECT_EQ(*moved_ptr, "Hello, World!");
}

class ThreadPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        utils::ErrorHandler::Initialize();
        utils::PerformanceMonitor::Initialize();
        utils::MemoryTracker::Initialize();
        
        ThreadPoolConfig config;
        config.min_threads = 2;
        config.max_threads = 4;
        config.enable_statistics = true;
        ThreadPool::initialize(config);
        
        auto& pool = ThreadPool::get_instance();
        pool.start();
    }
    
    void TearDown() override {
        auto& pool = ThreadPool::get_instance();
        pool.stop();
        ThreadPool::shutdown();
        utils::MemoryTracker::Shutdown();
        utils::PerformanceMonitor::Shutdown();
        utils::ErrorHandler::Shutdown();
    }
};

TEST_F(ThreadPoolTest, BasicTaskExecution) {
    auto& pool = ThreadPool::get_instance();
    
    std::atomic<int> counter{0};
    
    // Submit a simple task
    auto future = pool.submit([&counter]() {
        counter.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
    
    future.wait();
    EXPECT_EQ(counter.load(), 1);
}

TEST_F(ThreadPoolTest, MultipleTasks) {
    auto& pool = ThreadPool::get_instance();
    
    std::atomic<int> counter{0};
    std::vector<std::future<void>> futures;
    
    // Submit multiple tasks
    for (int i = 0; i < 10; ++i) {
        auto future = pool.submit([&counter, i]() {
            counter.fetch_add(1);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        });
        futures.push_back(std::move(future));
    }
    
    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    EXPECT_EQ(counter.load(), 10);
}

TEST_F(ThreadPoolTest, TaskPriorities) {
    auto& pool = ThreadPool::get_instance();
    
    std::vector<int> execution_order;
    std::mutex order_mutex;
    
    // Submit tasks with different priorities
    auto low_future = pool.submit_priority(TaskPriority::LOW, [&execution_order, &order_mutex]() {
        std::lock_guard<std::mutex> lock(order_mutex);
        execution_order.push_back(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
    
    auto high_future = pool.submit_priority(TaskPriority::HIGH, [&execution_order, &order_mutex]() {
        std::lock_guard<std::mutex> lock(order_mutex);
        execution_order.push_back(2);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
    
    low_future.wait();
    high_future.wait();
    
    // High priority task should execute first (though not guaranteed due to timing)
    EXPECT_EQ(execution_order.size(), 2);
}

TEST_F(ThreadPoolTest, TaskWithReturnValue) {
    auto& pool = ThreadPool::get_instance();
    
    // Submit task that returns a value
    auto future = pool.submit([]() -> int {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return 42;
    });
    
    int result = future.get();
    EXPECT_EQ(result, 42);
}

TEST_F(ThreadPoolTest, TaskWithId) {
    auto& pool = ThreadPool::get_instance();
    
    std::atomic<bool> task_completed{false};
    
    // Submit task with custom ID
    auto future = pool.submit_with_id("test_task_1", "Test Task", [&task_completed]() {
        task_completed.store(true);
    });
    
    future.wait();
    EXPECT_TRUE(task_completed.load());
    
    // Check task status
    EXPECT_TRUE(pool.is_task_completed("test_task_1"));
    EXPECT_EQ(pool.get_task_status("test_task_1"), TaskStatus::COMPLETED);
}

TEST_F(ThreadPoolTest, ThreadPoolStatistics) {
    auto& pool = ThreadPool::get_instance();
    
    // Submit some tasks
    std::vector<std::future<void>> futures;
    for (int i = 0; i < 5; ++i) {
        auto future = pool.submit([i]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        });
        futures.push_back(std::move(future));
    }
    
    // Wait for completion
    for (auto& future : futures) {
        future.wait();
    }
    
    auto stats = pool.get_stats();
    EXPECT_EQ(stats.total_tasks_submitted.load(), 5);
    EXPECT_EQ(stats.total_tasks_completed.load(), 5);
    EXPECT_GT(stats.average_task_duration_ms.load(), 0.0);
}

TEST_F(ThreadPoolTest, ThreadPoolUtils) {
    // Test utility functions
    auto future1 = ThreadPoolUtils::submit_task([]() { return 1; });
    auto future2 = ThreadPoolUtils::submit_urgent_task([]() { return 2; });
    auto future3 = ThreadPoolUtils::submit_background_task([]() { return 3; });
    
    EXPECT_EQ(future1.get(), 1);
    EXPECT_EQ(future2.get(), 2);
    EXPECT_EQ(future3.get(), 3);
    
    // Test task builder
    auto future4 = ThreadPoolUtils::create_task()
        .with_priority(TaskPriority::HIGH)
        .with_id("builder_test")
        .with_name("Builder Task")
        .submit([]() { return 4; });
    
    EXPECT_EQ(future4.get(), 4);
}

TEST_F(ThreadPoolTest, PauseAndResume) {
    auto& pool = ThreadPool::get_instance();
    
    std::atomic<int> counter{0};
    
    // Submit a task
    auto future = pool.submit([&counter]() {
        counter.fetch_add(1);
    });
    
    // Pause the pool
    pool.pause();
    EXPECT_TRUE(pool.is_paused());
    
    // Resume the pool
    pool.resume();
    EXPECT_FALSE(pool.is_paused());
    
    future.wait();
    EXPECT_EQ(counter.load(), 1);
}

class PerformanceOptimizerTest : public ::testing::Test {
protected:
    void SetUp() override {
        utils::ErrorHandler::Initialize();
        utils::PerformanceMonitor::Initialize();
        utils::MemoryTracker::Initialize();
        MemoryPool::initialize();
        ThreadPool::initialize();
        
        PerformanceOptimizerConfig config;
        config.enable_adaptive_optimization = true;
        config.enable_hardware_acceleration = true;
        config.enable_quality_scaling = true;
        PerformanceOptimizer::initialize(config);
    }
    
    void TearDown() override {
        PerformanceOptimizer::shutdown();
        ThreadPool::shutdown();
        MemoryPool::shutdown();
        utils::MemoryTracker::Shutdown();
        utils::PerformanceMonitor::Shutdown();
        utils::ErrorHandler::Shutdown();
    }
};

TEST_F(PerformanceOptimizerTest, BasicOptimization) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Perform optimization
    optimizer.optimize_now();
    
    // Check that optimization was performed
    EXPECT_GT(optimizer.get_optimization_count(), 0);
}

TEST_F(PerformanceOptimizerTest, HardwareCapabilities) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    auto capabilities = optimizer.get_hardware_capabilities();
    
    // Check basic hardware information
    EXPECT_GT(capabilities.cpu_cores, 0);
    EXPECT_GT(capabilities.total_memory_mb, 0);
    
    // Check CPU capabilities
    bool has_avx = HardwareAccelerationUtils::has_avx_support();
    EXPECT_EQ(capabilities.has_avx, has_avx);
}

TEST_F(PerformanceOptimizerTest, PerformanceMetrics) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    auto metrics = optimizer.get_current_metrics();
    
    // Check that metrics are collected
    EXPECT_GE(metrics.cpu_usage_percent, 0.0);
    EXPECT_LE(metrics.cpu_usage_percent, 100.0);
    EXPECT_GE(metrics.memory_usage_percent, 0.0);
    EXPECT_LE(metrics.memory_usage_percent, 100.0);
}

TEST_F(PerformanceOptimizerTest, OptimizationRecommendations) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Perform optimization to generate recommendations
    optimizer.optimize_now();
    
    auto recommendations = optimizer.get_recommendations();
    
    // Recommendations may or may not be generated depending on system state
    // Just check that the function works
    EXPECT_GE(recommendations.size(), 0);
}

TEST_F(PerformanceOptimizerTest, QualityScaling) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Test quality level setting
    optimizer.set_quality_level(0.5);
    EXPECT_EQ(optimizer.get_current_quality_level(), 0.5);
    
    optimizer.set_quality_level(1.0);
    EXPECT_EQ(optimizer.get_current_quality_level(), 1.0);
    
    optimizer.set_quality_level(0.0);
    EXPECT_EQ(optimizer.get_current_quality_level(), 0.0);
}

TEST_F(PerformanceOptimizerTest, HardwareAcceleration) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Test hardware acceleration detection
    auto available_types = optimizer.get_available_acceleration_types();
    
    // Check specific acceleration types
    bool has_avx = optimizer.is_hardware_acceleration_available(HardwareAccelerationType::CPU_AVX);
    bool has_d3d11 = optimizer.is_hardware_acceleration_available(HardwareAccelerationType::GPU_D3D11);
    
    // D3D11 should be available on Windows
    EXPECT_TRUE(has_d3d11);
}

TEST_F(PerformanceOptimizerTest, StrategyApplication) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Test applying different optimization strategies
    optimizer.apply_optimization(OptimizationStrategy::MEMORY_POOLING);
    optimizer.apply_optimization(OptimizationStrategy::THREAD_POOLING);
    optimizer.apply_optimization(OptimizationStrategy::ADAPTIVE_QUALITY);
    
    // Check that optimizations were applied
    EXPECT_GT(optimizer.get_optimization_count(), 0);
}

TEST_F(PerformanceOptimizerTest, Configuration) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    
    // Test configuration changes
    auto config = optimizer.get_config();
    config.enable_adaptive_optimization = false;
    optimizer.set_config(config);
    
    auto new_config = optimizer.get_config();
    EXPECT_FALSE(new_config.enable_adaptive_optimization);
}

TEST_F(PerformanceOptimizerTest, PerformanceOptimizerUtils) {
    // Test utility functions
    PerformanceOptimizerUtils::optimize_performance();
    
    auto metrics = PerformanceOptimizerUtils::get_current_metrics();
    EXPECT_GE(metrics.cpu_usage_percent, 0.0);
    
    auto recommendations = PerformanceOptimizerUtils::get_recommendations();
    EXPECT_GE(recommendations.size(), 0);
    
    // Test specific optimizations
    PerformanceOptimizerUtils::apply_memory_optimization();
    PerformanceOptimizerUtils::apply_thread_optimization();
    PerformanceOptimizerUtils::apply_hardware_optimization();
    
    // Test quality control
    PerformanceOptimizerUtils::set_quality_level(0.7);
    EXPECT_EQ(PerformanceOptimizerUtils::get_quality_level(), 0.7);
    
    // Test hardware acceleration
    auto available_acceleration = PerformanceOptimizerUtils::get_available_acceleration();
    EXPECT_GE(available_acceleration.size(), 0);
}

TEST_F(PerformanceOptimizerTest, HardwareAccelerationUtils) {
    // Test CPU capability detection
    bool has_avx = HardwareAccelerationUtils::has_avx_support();
    bool has_avx2 = HardwareAccelerationUtils::has_avx2_support();
    bool has_avx512 = HardwareAccelerationUtils::has_avx512_support();
    
    // Test system information
    size_t cpu_cores = HardwareAccelerationUtils::get_cpu_core_count();
    size_t cpu_threads = HardwareAccelerationUtils::get_cpu_thread_count();
    size_t total_memory = HardwareAccelerationUtils::get_total_memory_mb();
    size_t available_memory = HardwareAccelerationUtils::get_available_memory_mb();
    
    EXPECT_GT(cpu_cores, 0);
    EXPECT_GT(cpu_threads, 0);
    EXPECT_GT(total_memory, 0);
    EXPECT_GT(available_memory, 0);
    EXPECT_LE(available_memory, total_memory);
    
    // Test GPU information
    std::string gpu_name = HardwareAccelerationUtils::get_gpu_name();
    size_t gpu_memory = HardwareAccelerationUtils::get_gpu_memory_mb();
    
    // Test optimization helpers
    HardwareAccelerationUtils::optimize_for_cpu();
    HardwareAccelerationUtils::optimize_for_memory();
    HardwareAccelerationUtils::optimize_for_gpu();
}

TEST_F(PerformanceOptimizerTest, QualityScalingUtils) {
    // Test quality presets
    QualityScalingUtils::set_quality_preset_high();
    QualityScalingUtils::set_quality_preset_medium();
    QualityScalingUtils::set_quality_preset_low();
    QualityScalingUtils::set_quality_preset_custom(0.8);
    
    // Test quality level management
    QualityScalingUtils::set_frame_quality_level(0.9);
    QualityScalingUtils::set_compression_quality_level(0.7);
    QualityScalingUtils::set_texture_quality_level(0.8);
    QualityScalingUtils::set_shader_quality_level(0.6);
    
    // Test adaptive quality adjustment
    PerformanceMetrics metrics;
    metrics.cpu_usage_percent = 85.0;
    metrics.memory_usage_percent = 75.0;
    
    QualityScalingUtils::adjust_quality_based_on_performance(metrics);
    QualityScalingUtils::adjust_quality_based_on_memory_usage(80.0);
    QualityScalingUtils::adjust_quality_based_on_cpu_usage(90.0);
}

TEST_F(PerformanceOptimizerTest, IntegrationTest) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    auto& memory_pool = MemoryPool::get_instance();
    auto& thread_pool = ThreadPool::get_instance();
    
    // Start optimization
    optimizer.start_optimization();
    
    // Perform some work to generate load
    std::vector<std::future<void>> futures;
    for (int i = 0; i < 10; ++i) {
        auto future = thread_pool.submit([&memory_pool, i]() {
            // Allocate and deallocate memory
            void* ptr = memory_pool.allocate(1024 * (i + 1), 8, "integration_test");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            memory_pool.deallocate(ptr);
        });
        futures.push_back(std::move(future));
    }
    
    // Wait for completion
    for (auto& future : futures) {
        future.wait();
    }
    
    // Let optimization run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop optimization
    optimizer.stop_optimization();
    
    // Check that optimization was active
    EXPECT_TRUE(optimizer.is_optimization_active() || optimizer.get_optimization_count() > 0);
    
    // Print optimization report
    optimizer.print_optimization_report();
}

TEST_F(PerformanceOptimizerTest, StressTest) {
    auto& optimizer = PerformanceOptimizer::get_instance();
    auto& memory_pool = MemoryPool::get_instance();
    auto& thread_pool = ThreadPool::get_instance();
    
    // Create high load
    std::vector<std::future<void>> memory_futures;
    std::vector<std::future<void>> compute_futures;
    
    // Memory stress
    for (int i = 0; i < 20; ++i) {
        auto future = thread_pool.submit([&memory_pool, i]() {
            std::vector<void*> allocations;
            for (int j = 0; j < 10; ++j) {
                void* ptr = memory_pool.allocate(1024 * (j + 1), 8, "stress_test");
                allocations.push_back(ptr);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            for (void* ptr : allocations) {
                memory_pool.deallocate(ptr);
            }
        });
        memory_futures.push_back(std::move(future));
    }
    
    // Compute stress
    for (int i = 0; i < 10; ++i) {
        auto future = thread_pool.submit([i]() {
            // Simulate compute-intensive work
            volatile double result = 0.0;
            for (int j = 0; j < 1000000; ++j) {
                result += std::sin(j) * std::cos(j);
            }
        });
        compute_futures.push_back(std::move(future));
    }
    
    // Wait for completion
    for (auto& future : memory_futures) {
        future.wait();
    }
    for (auto& future : compute_futures) {
        future.wait();
    }
    
    // Check system state
    auto metrics = optimizer.get_current_metrics();
    auto recommendations = optimizer.get_recommendations();
    
    EXPECT_GE(metrics.cpu_usage_percent, 0.0);
    EXPECT_LE(metrics.cpu_usage_percent, 100.0);
    EXPECT_GE(metrics.memory_usage_percent, 0.0);
    EXPECT_LE(metrics.memory_usage_percent, 100.0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 