#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <algorithm>

namespace UndownUnlock {
namespace Utils {
class ErrorHandler;
class PerformanceMonitor;
}
class MemoryTracker;
}

namespace UndownUnlock::Optimization {

using ::UndownUnlock::Utils::ErrorHandler;
using ::UndownUnlock::Utils::PerformanceMonitor;
using ::UndownUnlock::MemoryTracker;
class MemoryPool;
class ThreadPool;

/**
 * Optimization strategies
 */
enum class OptimizationStrategy {
    NONE = 0,
    MEMORY_POOLING = 1,
    THREAD_POOLING = 2,
    HARDWARE_ACCELERATION = 3,
    COMPRESSION = 4,
    CACHING = 5,
    ADAPTIVE_QUALITY = 6,
    ALL = 7
};

/**
 * Hardware acceleration types
 */
enum class HardwareAccelerationType {
    NONE = 0,
    CPU_AVX = 1,
    CPU_AVX2 = 2,
    CPU_AVX512 = 3,
    GPU_CUDA = 4,
    GPU_OPENCL = 5,
    GPU_D3D11 = 6,
    GPU_D3D12 = 7
};

/**
 * Performance optimization configuration
 */
struct PerformanceOptimizerConfig {
    bool enable_adaptive_optimization = true;
    bool enable_hardware_acceleration = true;
    bool enable_compression = false;
    bool enable_caching = true;
    bool enable_quality_scaling = true;
    size_t optimization_check_interval_ms = 5000; // 5 seconds
    size_t max_memory_usage_mb = 1024; // 1GB
    size_t max_cpu_usage_percent = 80;
    double quality_scaling_threshold = 0.7; // 70% performance threshold
    std::vector<OptimizationStrategy> enabled_strategies = {
        OptimizationStrategy::MEMORY_POOLING,
        OptimizationStrategy::THREAD_POOLING,
        OptimizationStrategy::ADAPTIVE_QUALITY
    };
    
    PerformanceOptimizerConfig() = default;
};

/**
 * Hardware capabilities information
 */
struct HardwareCapabilities {
    bool has_avx = false;
    bool has_avx2 = false;
    bool has_avx512 = false;
    bool has_cuda = false;
    bool has_opencl = false;
    bool has_d3d11 = false;
    bool has_d3d12 = false;
    size_t cpu_cores = 0;
    size_t cpu_threads = 0;
    size_t total_memory_mb = 0;
    size_t available_memory_mb = 0;
    double cpu_frequency_ghz = 0.0;
    std::string gpu_name;
    size_t gpu_memory_mb = 0;
    
    HardwareCapabilities() = default;
};

/**
 * Performance metrics
 */
struct PerformanceMetrics {
    double cpu_usage_percent;
    double memory_usage_percent;
    double frame_rate_fps;
    double frame_latency_ms;
    double memory_allocation_rate_mb_per_sec;
    double task_throughput_per_sec;
    size_t active_threads;
    size_t queued_tasks;
    std::chrono::system_clock::time_point timestamp;
    
    PerformanceMetrics() : cpu_usage_percent(0.0), memory_usage_percent(0.0),
                          frame_rate_fps(0.0), frame_latency_ms(0.0),
                          memory_allocation_rate_mb_per_sec(0.0), task_throughput_per_sec(0.0),
                          active_threads(0), queued_tasks(0) {}
};

/**
 * Optimization recommendation
 */
struct OptimizationRecommendation {
    OptimizationStrategy strategy;
    std::string description;
    double expected_improvement_percent;
    bool is_implemented;
    std::chrono::system_clock::time_point recommendation_time;
    
    OptimizationRecommendation() : strategy(OptimizationStrategy::NONE),
                                  expected_improvement_percent(0.0), is_implemented(false) {}
};

/**
 * Performance optimizer for adaptive system optimization
 */
class PerformanceOptimizer {
public:
    explicit PerformanceOptimizer(const PerformanceOptimizerConfig& config = PerformanceOptimizerConfig());
    ~PerformanceOptimizer();
    
    // Singleton access
    static PerformanceOptimizer& get_instance();
    static void initialize(const PerformanceOptimizerConfig& config = PerformanceOptimizerConfig());
    static void shutdown();
    
    // Core optimization methods
    void start_optimization();
    void stop_optimization();
    void optimize_now();
    void apply_optimization(OptimizationStrategy strategy);
    void revert_optimization(OptimizationStrategy strategy);
    
    // Performance monitoring
    PerformanceMetrics get_current_metrics() const;
    HardwareCapabilities get_hardware_capabilities() const;
    std::vector<OptimizationRecommendation> get_recommendations() const;
    
    // Configuration
    void set_config(const PerformanceOptimizerConfig& config);
    PerformanceOptimizerConfig get_config() const;
    void enable_strategy(OptimizationStrategy strategy, bool enable);
    
    // Hardware acceleration
    bool is_hardware_acceleration_available(HardwareAccelerationType type) const;
    void enable_hardware_acceleration(HardwareAccelerationType type, bool enable);
    std::vector<HardwareAccelerationType> get_available_acceleration_types() const;
    
    // Quality scaling
    void set_quality_level(double level); // 0.0 to 1.0
    double get_current_quality_level() const;
    void enable_adaptive_quality_scaling(bool enable);
    
    // Statistics and monitoring
    void print_optimization_report() const;
    void reset_optimization_history();
    
    // Utility methods
    bool is_optimization_active() const;
    bool is_hardware_acceleration_enabled() const;
    size_t get_optimization_count() const;
    
private:
    // Internal methods
    void optimization_worker();
    void detect_hardware_capabilities();
    void collect_performance_metrics();
    void analyze_performance_bottlenecks();
    void generate_optimization_recommendations();
    void apply_adaptive_optimizations();
    void adjust_quality_settings();
    void optimize_memory_usage();
    void optimize_thread_usage();
    void optimize_hardware_usage();
    double calculate_performance_score() const;
    bool should_apply_optimization(const OptimizationRecommendation& recommendation) const;
    void log_optimization_event(const std::string& event, const std::string& details = "");
    
    // Member variables
    static PerformanceOptimizer* instance_;
    static std::mutex instance_mutex_;
    
    PerformanceOptimizerConfig config_;
    HardwareCapabilities hardware_capabilities_;
    PerformanceMetrics current_metrics_;
    std::vector<OptimizationRecommendation> recommendations_;
    std::vector<OptimizationRecommendation> applied_optimizations_;
    
    mutable std::mutex optimizer_mutex_;
    mutable std::mutex metrics_mutex_;
    mutable std::mutex recommendations_mutex_;
    
    std::atomic<bool> optimization_active_;
    std::atomic<bool> stop_optimization_;
    std::atomic<size_t> optimization_count_;
    std::atomic<double> current_quality_level_;
    
    std::thread optimization_thread_;
    std::chrono::system_clock::time_point last_optimization_;
    std::chrono::system_clock::time_point last_metrics_collection_;
    
    // Performance monitoring
    ErrorHandler* error_handler_;
    PerformanceMonitor* performance_monitor_;
    MemoryTracker* memory_tracker_;
    MemoryPool* memory_pool_;
    ThreadPool* thread_pool_;
    
    // Optimization history
    std::vector<std::pair<std::chrono::system_clock::time_point, PerformanceMetrics>> metrics_history_;
    std::vector<std::pair<std::chrono::system_clock::time_point, OptimizationRecommendation>> optimization_history_;
};

/**
 * Hardware acceleration utilities
 */
namespace HardwareAccelerationUtils {
    
    // Check CPU capabilities
    bool has_avx_support();
    bool has_avx2_support();
    bool has_avx512_support();
    
    // Check GPU capabilities
    bool has_cuda_support();
    bool has_opencl_support();
    bool has_d3d11_support();
    bool has_d3d12_support();
    
    // Get system information
    size_t get_cpu_core_count();
    size_t get_cpu_thread_count();
    double get_cpu_frequency_ghz();
    size_t get_total_memory_mb();
    size_t get_available_memory_mb();
    std::string get_gpu_name();
    size_t get_gpu_memory_mb();
    
    // Performance optimization helpers
    void optimize_for_cpu();
    void optimize_for_memory();
    void optimize_for_gpu();
    void set_process_priority(int priority);
    void set_thread_affinity(size_t thread_id, size_t cpu_core);
}

/**
 * Quality scaling utilities
 */
namespace QualityScalingUtils {
    
    // Quality level management
    void set_frame_quality_level(double level);
    void set_compression_quality_level(double level);
    void set_texture_quality_level(double level);
    void set_shader_quality_level(double level);
    
    // Adaptive quality adjustment
    void adjust_quality_based_on_performance(const PerformanceMetrics& metrics);
    void adjust_quality_based_on_memory_usage(double memory_usage_percent);
    void adjust_quality_based_on_cpu_usage(double cpu_usage_percent);
    
    // Quality presets
    void set_quality_preset_high();
    void set_quality_preset_medium();
    void set_quality_preset_low();
    void set_quality_preset_custom(double level);
}

/**
 * Performance optimization utilities
 */
namespace PerformanceOptimizerUtils {
    
    // Get optimizer instance
    inline PerformanceOptimizer& get_optimizer() {
        return PerformanceOptimizer::get_instance();
    }
    
    // Quick optimization methods
    inline void optimize_performance() {
        get_optimizer().optimize_now();
    }
    
    inline void start_optimization() {
        get_optimizer().start_optimization();
    }
    
    inline void stop_optimization() {
        get_optimizer().stop_optimization();
    }
    
    // Get current performance metrics
    inline PerformanceMetrics get_current_metrics() {
        return get_optimizer().get_current_metrics();
    }
    
    // Get optimization recommendations
    inline std::vector<OptimizationRecommendation> get_recommendations() {
        return get_optimizer().get_recommendations();
    }
    
    // Apply specific optimizations
    inline void apply_memory_optimization() {
        get_optimizer().apply_optimization(OptimizationStrategy::MEMORY_POOLING);
    }
    
    inline void apply_thread_optimization() {
        get_optimizer().apply_optimization(OptimizationStrategy::THREAD_POOLING);
    }
    
    inline void apply_hardware_optimization() {
        get_optimizer().apply_optimization(OptimizationStrategy::HARDWARE_ACCELERATION);
    }
    
    // Quality control
    inline void set_quality_level(double level) {
        get_optimizer().set_quality_level(level);
    }
    
    inline double get_quality_level() {
        return get_optimizer().get_current_quality_level();
    }
    
    // Hardware acceleration
    inline bool is_hardware_acceleration_available(HardwareAccelerationType type) {
        return get_optimizer().is_hardware_acceleration_available(type);
    }
    
    inline std::vector<HardwareAccelerationType> get_available_acceleration() {
        return get_optimizer().get_available_acceleration_types();
    }
    
    // Performance monitoring
    inline void print_optimization_report() {
        get_optimizer().print_optimization_report();
    }
    
    // Check if optimization is active
    inline bool is_optimization_active() {
        return get_optimizer().is_optimization_active();
    }
}

} // namespace UndownUnlock::Optimization 
