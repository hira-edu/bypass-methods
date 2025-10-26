#include "../../include/optimization/performance_optimizer.h"
#include "../../include/optimization/memory_pool.h"
#include "../../include/optimization/thread_pool.h"
#include "../../include/utils/error_handler.h"
#include "../../include/utils/performance_monitor.h"
#include "../../include/memory_tracker.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <intrin.h>
#if !defined(_MSC_VER)
#include <cpuid.h>
#endif
#include <numeric>
#include <psapi.h>
#include <pdh.h>

namespace UndownUnlock::Optimization {

namespace {
inline void QueryCpuIdLeaf(int cpu_info[4], int function_id, int subfunction) {
#if defined(_MSC_VER)
    __cpuidex(cpu_info, function_id, subfunction);
#else
    __cpuid_count(function_id, subfunction, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif
}
} // namespace

// Static member initialization
PerformanceOptimizer* PerformanceOptimizer::instance_ = nullptr;
std::mutex PerformanceOptimizer::instance_mutex_;

PerformanceOptimizer::PerformanceOptimizer(const PerformanceOptimizerConfig& config)
    : config_(config), optimization_active_(false), stop_optimization_(false),
      optimization_count_(0), current_quality_level_(1.0) {
    
    // Initialize utility components
    error_handler_ = utils::ErrorHandler::GetInstance();
    performance_monitor_ = utils::PerformanceMonitor::GetInstance();
    memory_tracker_ = &MemoryTracker::GetInstance();
    memory_pool_ = &MemoryPool::get_instance();
    thread_pool_ = &ThreadPool::get_instance();
    
    // Set error context
    utils::ErrorContext context;
    context.set("component", "PerformanceOptimizer");
    context.set("operation", "initialization");
    error_handler_->set_error_context(context);
    
    error_handler_->info(
        "Initializing Performance Optimizer",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Start performance monitoring
    auto init_operation = performance_monitor_->start_operation("performance_optimizer_initialization");
    performance_monitor_->end_operation(init_operation);
    
    // Track memory allocation for the optimizer
    memory_tracker_->TrackAllocation("performance_optimizer", sizeof(PerformanceOptimizer));
    
    // Detect hardware capabilities
    detect_hardware_capabilities();
    
    last_optimization_ = std::chrono::system_clock::now();
    last_metrics_collection_ = std::chrono::system_clock::now();
}

PerformanceOptimizer::~PerformanceOptimizer() {
    error_handler_->info(
        "Shutting down Performance Optimizer",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    stop_optimization();
}

PerformanceOptimizer& PerformanceOptimizer::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new PerformanceOptimizer();
    }
    return *instance_;
}

void PerformanceOptimizer::initialize(const PerformanceOptimizerConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new PerformanceOptimizer(config);
    } else {
        instance_->set_config(config);
    }
}

void PerformanceOptimizer::shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        delete instance_;
        instance_ = nullptr;
    }
}

void PerformanceOptimizer::start_optimization() {
    if (optimization_active_.load()) {
        error_handler_->warning(
            "Performance optimization is already active",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        return;
    }
    
    optimization_active_.store(true);
    stop_optimization_.store(false);
    
    error_handler_->info(
        "Starting performance optimization",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Start optimization worker thread
    optimization_thread_ = std::thread(&PerformanceOptimizer::optimization_worker, this);
}

void PerformanceOptimizer::stop_optimization() {
    if (!optimization_active_.load()) {
        return;
    }
    
    error_handler_->info(
        "Stopping performance optimization",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    stop_optimization_.store(true);
    optimization_active_.store(false);
    
    if (optimization_thread_.joinable()) {
        optimization_thread_.join();
    }
}

void PerformanceOptimizer::optimize_now() {
    auto optimize_operation = performance_monitor_->start_operation("performance_optimization");
    
    error_handler_->info(
        "Performing immediate performance optimization",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Collect current metrics
    collect_performance_metrics();
    
    // Analyze bottlenecks
    analyze_performance_bottlenecks();
    
    // Generate recommendations
    generate_optimization_recommendations();
    
    // Apply optimizations
    apply_adaptive_optimizations();
    
    optimization_count_.fetch_add(1);
    last_optimization_ = std::chrono::system_clock::now();
    
    performance_monitor_->end_operation(optimize_operation);
}

void PerformanceOptimizer::apply_optimization(OptimizationStrategy strategy) {
    auto apply_operation = performance_monitor_->start_operation("apply_optimization");
    
    error_handler_->info(
        "Applying optimization strategy: " + std::to_string(static_cast<int>(strategy)),
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    switch (strategy) {
        case OptimizationStrategy::MEMORY_POOLING:
            optimize_memory_usage();
            break;
        case OptimizationStrategy::THREAD_POOLING:
            optimize_thread_usage();
            break;
        case OptimizationStrategy::HARDWARE_ACCELERATION:
            optimize_hardware_usage();
            break;
        case OptimizationStrategy::ADAPTIVE_QUALITY:
            adjust_quality_settings();
            break;
        case OptimizationStrategy::COMPRESSION:
            // Enable compression if available
            if (config_.enable_compression) {
                memory_pool_->enable_compression(true);
            }
            break;
        case OptimizationStrategy::CACHING:
            // Implement caching optimization
            error_handler_->debug(
                "Caching optimization not implemented in this build",
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            break;
        default:
            error_handler_->warning(
                "Unknown optimization strategy: " + std::to_string(static_cast<int>(strategy)),
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            break;
    }
    
    performance_monitor_->end_operation(apply_operation);
}

void PerformanceOptimizer::revert_optimization(OptimizationStrategy strategy) {
    error_handler_->info(
        "Reverting optimization strategy: " + std::to_string(static_cast<int>(strategy)),
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Implementation would revert specific optimizations
    // For now, just log the action
    log_optimization_event("revert", "Strategy: " + std::to_string(static_cast<int>(strategy)));
}

PerformanceMetrics PerformanceOptimizer::get_current_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return current_metrics_;
}

HardwareCapabilities PerformanceOptimizer::get_hardware_capabilities() const {
    return hardware_capabilities_;
}

std::vector<OptimizationRecommendation> PerformanceOptimizer::get_recommendations() const {
    std::lock_guard<std::mutex> lock(recommendations_mutex_);
    return recommendations_;
}

void PerformanceOptimizer::set_config(const PerformanceOptimizerConfig& config) {
    config_ = config;
}

PerformanceOptimizerConfig PerformanceOptimizer::get_config() const {
    return config_;
}

void PerformanceOptimizer::enable_strategy(OptimizationStrategy strategy, bool enable) {
    auto it = std::find(config_.enabled_strategies.begin(), config_.enabled_strategies.end(), strategy);
    
    if (enable && it == config_.enabled_strategies.end()) {
        config_.enabled_strategies.push_back(strategy);
    } else if (!enable && it != config_.enabled_strategies.end()) {
        config_.enabled_strategies.erase(it);
    }
}

bool PerformanceOptimizer::is_hardware_acceleration_available(HardwareAccelerationType type) const {
    switch (type) {
        case HardwareAccelerationType::CPU_AVX:
            return hardware_capabilities_.has_avx;
        case HardwareAccelerationType::CPU_AVX2:
            return hardware_capabilities_.has_avx2;
        case HardwareAccelerationType::CPU_AVX512:
            return hardware_capabilities_.has_avx512;
        case HardwareAccelerationType::GPU_CUDA:
            return hardware_capabilities_.has_cuda;
        case HardwareAccelerationType::GPU_OPENCL:
            return hardware_capabilities_.has_opencl;
        case HardwareAccelerationType::GPU_D3D11:
            return hardware_capabilities_.has_d3d11;
        case HardwareAccelerationType::GPU_D3D12:
            return hardware_capabilities_.has_d3d12;
        default:
            return false;
    }
}

void PerformanceOptimizer::enable_hardware_acceleration(HardwareAccelerationType type, bool enable) {
    // Implementation would enable/disable specific hardware acceleration
    error_handler_->debug(
        "Hardware acceleration toggle not implemented in this build",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

std::vector<HardwareAccelerationType> PerformanceOptimizer::get_available_acceleration_types() const {
    std::vector<HardwareAccelerationType> available_types;
    
    if (hardware_capabilities_.has_avx) {
        available_types.push_back(HardwareAccelerationType::CPU_AVX);
    }
    if (hardware_capabilities_.has_avx2) {
        available_types.push_back(HardwareAccelerationType::CPU_AVX2);
    }
    if (hardware_capabilities_.has_avx512) {
        available_types.push_back(HardwareAccelerationType::CPU_AVX512);
    }
    if (hardware_capabilities_.has_cuda) {
        available_types.push_back(HardwareAccelerationType::GPU_CUDA);
    }
    if (hardware_capabilities_.has_opencl) {
        available_types.push_back(HardwareAccelerationType::GPU_OPENCL);
    }
    if (hardware_capabilities_.has_d3d11) {
        available_types.push_back(HardwareAccelerationType::GPU_D3D11);
    }
    if (hardware_capabilities_.has_d3d12) {
        available_types.push_back(HardwareAccelerationType::GPU_D3D12);
    }
    
    return available_types;
}

void PerformanceOptimizer::set_quality_level(double level) {
    level = std::max(0.0, std::min(1.0, level));
    current_quality_level_.store(level);
    
    error_handler_->info(
        "Quality level set to: " + std::to_string(level),
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

double PerformanceOptimizer::get_current_quality_level() const {
    return current_quality_level_.load();
}

void PerformanceOptimizer::enable_adaptive_quality_scaling(bool enable) {
    config_.enable_quality_scaling = enable;
}

void PerformanceOptimizer::print_optimization_report() const {
    auto metrics = get_current_metrics();
    auto recommendations = get_recommendations();
    
    std::stringstream ss;
    ss << "=== Performance Optimization Report ===" << std::endl;
    ss << "CPU Usage: " << std::fixed << std::setprecision(1) << metrics.cpu_usage_percent << "%" << std::endl;
    ss << "Memory Usage: " << std::fixed << std::setprecision(1) << metrics.memory_usage_percent << "%" << std::endl;
    ss << "Frame Rate: " << std::fixed << std::setprecision(1) << metrics.frame_rate_fps << " FPS" << std::endl;
    ss << "Frame Latency: " << std::fixed << std::setprecision(2) << metrics.frame_latency_ms << "ms" << std::endl;
    ss << "Active Threads: " << metrics.active_threads << std::endl;
    ss << "Queued Tasks: " << metrics.queued_tasks << std::endl;
    ss << "Current Quality Level: " << std::fixed << std::setprecision(2) << get_current_quality_level() << std::endl;
    ss << "Optimization Count: " << optimization_count_.load() << std::endl;
    ss << "Recommendations: " << recommendations.size() << std::endl;
    
    for (const auto& rec : recommendations) {
        ss << "  - " << rec.description << " (Expected improvement: " 
           << std::fixed << std::setprecision(1) << rec.expected_improvement_percent << "%)" << std::endl;
    }
    
    error_handler_->info(ss.str(), utils::ErrorCategory::SYSTEM, __FUNCTION__, __FILE__, __LINE__);
}

void PerformanceOptimizer::reset_optimization_history() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_history_.clear();
    optimization_history_.clear();
    optimization_count_.store(0);
}

bool PerformanceOptimizer::is_optimization_active() const {
    return optimization_active_.load();
}

bool PerformanceOptimizer::is_hardware_acceleration_enabled() const {
    return config_.enable_hardware_acceleration;
}

size_t PerformanceOptimizer::get_optimization_count() const {
    return optimization_count_.load();
}

// Private implementation methods

void PerformanceOptimizer::optimization_worker() {
    error_handler_->info(
        "Performance optimization worker thread started",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    while (!stop_optimization_.load()) {
        try {
            // Collect metrics
            collect_performance_metrics();
            
            // Analyze performance
            analyze_performance_bottlenecks();
            
            // Generate recommendations
            generate_optimization_recommendations();
            
            // Apply optimizations if needed
            if (config_.enable_adaptive_optimization) {
                apply_adaptive_optimizations();
            }
            
            // Wait for next optimization cycle
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.optimization_check_interval_ms));
            
        } catch (const std::exception& e) {
            error_handler_->error(
                "Exception in optimization worker: " + std::string(e.what()),
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
        }
    }
    
    error_handler_->info(
        "Performance optimization worker thread stopped",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void PerformanceOptimizer::detect_hardware_capabilities() {
    // CPU capabilities
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    
    hardware_capabilities_.has_avx = (cpu_info[2] & (1 << 28)) != 0;
    int cpu_info_ext[4] = {0};
    QueryCpuIdLeaf(cpu_info_ext, 7, 0);
    hardware_capabilities_.has_avx2 = (cpu_info_ext[1] & (1 << 5)) != 0;
    
    // Get CPU information
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    hardware_capabilities_.cpu_cores = sys_info.dwNumberOfProcessors;
    hardware_capabilities_.cpu_threads = sys_info.dwNumberOfProcessors;
    
    // Get memory information
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&mem_status);
    hardware_capabilities_.total_memory_mb = mem_status.ullTotalPhys / (1024 * 1024);
    hardware_capabilities_.available_memory_mb = mem_status.ullAvailPhys / (1024 * 1024);
    
    // GPU capabilities (simplified detection)
    hardware_capabilities_.has_d3d11 = true; // Assume D3D11 is available
    hardware_capabilities_.has_d3d12 = false; // Would need to check D3D12 availability
    hardware_capabilities_.has_cuda = false; // Would need CUDA detection
    hardware_capabilities_.has_opencl = false; // Would need OpenCL detection
    
    error_handler_->info(
        "Hardware capabilities detected - CPU cores: " + std::to_string(hardware_capabilities_.cpu_cores) +
        ", Memory: " + std::to_string(hardware_capabilities_.total_memory_mb) + "MB",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void PerformanceOptimizer::collect_performance_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    // Get CPU usage
    FILETIME idle_time, kernel_time, user_time;
    if (GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
        static ULARGE_INTEGER last_idle, last_kernel, last_user;
        ULARGE_INTEGER current_idle, current_kernel, current_user;
        
        current_idle.LowPart = idle_time.dwLowDateTime;
        current_idle.HighPart = idle_time.dwHighDateTime;
        current_kernel.LowPart = kernel_time.dwLowDateTime;
        current_kernel.HighPart = kernel_time.dwHighDateTime;
        current_user.LowPart = user_time.dwLowDateTime;
        current_user.HighPart = user_time.dwHighDateTime;
        
        if (last_idle.QuadPart != 0) {
            ULARGE_INTEGER idle_diff, kernel_diff, user_diff;
            idle_diff.QuadPart = current_idle.QuadPart - last_idle.QuadPart;
            kernel_diff.QuadPart = current_kernel.QuadPart - last_kernel.QuadPart;
            user_diff.QuadPart = current_user.QuadPart - last_user.QuadPart;
            
            ULARGE_INTEGER total_diff;
            total_diff.QuadPart = kernel_diff.QuadPart + user_diff.QuadPart;
            
            if (total_diff.QuadPart > 0) {
                current_metrics_.cpu_usage_percent = 100.0 - (idle_diff.QuadPart * 100.0 / total_diff.QuadPart);
            }
        }
        
        last_idle = current_idle;
        last_kernel = current_kernel;
        last_user = current_user;
    }
    
    // Get memory usage
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), 
                            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        current_metrics_.memory_usage_percent = (pmc.WorkingSetSize * 100.0) / hardware_capabilities_.total_memory_mb;
    }
    
    // Get thread pool statistics
    auto thread_pool_stats = thread_pool_->get_stats();
    current_metrics_.active_threads = thread_pool_stats.current_threads_active.load();
    current_metrics_.queued_tasks = thread_pool_stats.current_tasks_queued.load();
    current_metrics_.task_throughput_per_sec = thread_pool_stats.throughput_tasks_per_second.load();
    
    // Get memory pool statistics
    auto memory_pool_stats = memory_pool_->get_stats();
    current_metrics_.memory_allocation_rate_mb_per_sec = 0.0; // Would calculate from history
    
    // Estimate frame rate and latency (would come from actual frame capture system)
    current_metrics_.frame_rate_fps = 60.0; // Placeholder
    current_metrics_.frame_latency_ms = 16.67; // Placeholder
    
    current_metrics_.timestamp = std::chrono::system_clock::now();
    last_metrics_collection_ = current_metrics_.timestamp;
    
    // Store in history
    metrics_history_.push_back({current_metrics_.timestamp, current_metrics_});
    if (metrics_history_.size() > 100) {
        metrics_history_.erase(metrics_history_.begin());
    }
}

void PerformanceOptimizer::analyze_performance_bottlenecks() {
    // Analyze current metrics for bottlenecks
    std::vector<std::string> bottlenecks;
    
    if (current_metrics_.cpu_usage_percent > config_.max_cpu_usage_percent) {
        bottlenecks.push_back("High CPU usage: " + std::to_string(current_metrics_.cpu_usage_percent) + "%");
    }
    
    if (current_metrics_.memory_usage_percent > 80.0) {
        bottlenecks.push_back("High memory usage: " + std::to_string(current_metrics_.memory_usage_percent) + "%");
    }
    
    if (current_metrics_.frame_latency_ms > 33.33) { // 30 FPS threshold
        bottlenecks.push_back("High frame latency: " + std::to_string(current_metrics_.frame_latency_ms) + "ms");
    }
    
    if (!bottlenecks.empty()) {
        error_handler_->warning(
            "Performance bottlenecks detected: " + std::accumulate(bottlenecks.begin(), bottlenecks.end(), std::string(),
                [](const std::string& a, const std::string& b) { return a + (a.empty() ? "" : ", ") + b; }),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

void PerformanceOptimizer::generate_optimization_recommendations() {
    std::lock_guard<std::mutex> lock(recommendations_mutex_);
    recommendations_.clear();
    
    // Memory optimization recommendations
    if (current_metrics_.memory_usage_percent > 70.0) {
        OptimizationRecommendation rec;
        rec.strategy = OptimizationStrategy::MEMORY_POOLING;
        rec.description = "High memory usage detected - enable memory pooling";
        rec.expected_improvement_percent = 20.0;
        rec.is_implemented = false;
        rec.recommendation_time = std::chrono::system_clock::now();
        recommendations_.push_back(rec);
    }
    
    // Thread optimization recommendations
    if (current_metrics_.queued_tasks > 10) {
        OptimizationRecommendation rec;
        rec.strategy = OptimizationStrategy::THREAD_POOLING;
        rec.description = "High task queue detected - optimize thread pool";
        rec.expected_improvement_percent = 15.0;
        rec.is_implemented = false;
        rec.recommendation_time = std::chrono::system_clock::now();
        recommendations_.push_back(rec);
    }
    
    // Hardware acceleration recommendations
    if (config_.enable_hardware_acceleration && !hardware_capabilities_.has_avx) {
        OptimizationRecommendation rec;
        rec.strategy = OptimizationStrategy::HARDWARE_ACCELERATION;
        rec.description = "Hardware acceleration available - enable AVX optimizations";
        rec.expected_improvement_percent = 30.0;
        rec.is_implemented = false;
        rec.recommendation_time = std::chrono::system_clock::now();
        recommendations_.push_back(rec);
    }
    
    // Quality scaling recommendations
    if (current_metrics_.cpu_usage_percent > 90.0 && config_.enable_quality_scaling) {
        OptimizationRecommendation rec;
        rec.strategy = OptimizationStrategy::ADAPTIVE_QUALITY;
        rec.description = "High CPU usage - reduce quality settings";
        rec.expected_improvement_percent = 25.0;
        rec.is_implemented = false;
        rec.recommendation_time = std::chrono::system_clock::now();
        recommendations_.push_back(rec);
    }
}

void PerformanceOptimizer::apply_adaptive_optimizations() {
    for (const auto& recommendation : recommendations_) {
        if (should_apply_optimization(recommendation)) {
            apply_optimization(recommendation.strategy);
            
            // Mark as implemented
            const_cast<OptimizationRecommendation&>(recommendation).is_implemented = true;
            
            log_optimization_event("applied", "Strategy: " + std::to_string(static_cast<int>(recommendation.strategy)));
        }
    }
}

void PerformanceOptimizer::adjust_quality_settings() {
    double current_quality = get_current_quality_level();
    double target_quality = current_quality;
    
    // Adjust based on CPU usage
    if (current_metrics_.cpu_usage_percent > 90.0) {
        target_quality = std::max(0.5, current_quality - 0.1);
    } else if (current_metrics_.cpu_usage_percent < 50.0 && current_quality < 1.0) {
        target_quality = std::min(1.0, current_quality + 0.05);
    }
    
    // Adjust based on memory usage
    if (current_metrics_.memory_usage_percent > 80.0) {
        target_quality = std::max(0.5, target_quality - 0.1);
    }
    
    if (target_quality != current_quality) {
        set_quality_level(target_quality);
        
        error_handler_->info(
            "Quality level adjusted from " + std::to_string(current_quality) + " to " + std::to_string(target_quality),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

void PerformanceOptimizer::optimize_memory_usage() {
    // Perform memory pool cleanup
    memory_pool_->cleanup();
    
    // Force garbage collection
    SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    
    error_handler_->info(
        "Memory optimization applied",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void PerformanceOptimizer::optimize_thread_usage() {
    // Adjust thread pool size based on load
    size_t current_threads = thread_pool_->get_thread_count();
    size_t target_threads = current_threads;
    
    if (current_metrics_.queued_tasks > 20) {
        target_threads = std::min(config_.enabled_strategies.size(), current_threads + 2);
    } else if (current_metrics_.queued_tasks < 5 && current_threads > 2) {
        target_threads = std::max<size_t>(2, current_threads - 1);
    }
    
    if (target_threads != current_threads) {
        thread_pool_->resize(target_threads);
        
        error_handler_->info(
            "Thread pool resized from " + std::to_string(current_threads) + " to " + std::to_string(target_threads),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

void PerformanceOptimizer::optimize_hardware_usage() {
    // Enable hardware acceleration if available
    if (hardware_capabilities_.has_avx) {
        error_handler_->info(
            "AVX hardware acceleration enabled",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
    
    if (hardware_capabilities_.has_d3d11) {
        error_handler_->info(
            "D3D11 hardware acceleration enabled",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

double PerformanceOptimizer::calculate_performance_score() const {
    // Calculate overall performance score (0.0 to 1.0)
    double score = 1.0;
    
    // CPU usage penalty
    if (current_metrics_.cpu_usage_percent > 80.0) {
        score -= 0.3;
    } else if (current_metrics_.cpu_usage_percent > 60.0) {
        score -= 0.1;
    }
    
    // Memory usage penalty
    if (current_metrics_.memory_usage_percent > 80.0) {
        score -= 0.2;
    } else if (current_metrics_.memory_usage_percent > 60.0) {
        score -= 0.05;
    }
    
    // Frame rate penalty
    if (current_metrics_.frame_rate_fps < 30.0) {
        score -= 0.3;
    } else if (current_metrics_.frame_rate_fps < 60.0) {
        score -= 0.1;
    }
    
    return std::max(0.0, score);
}

bool PerformanceOptimizer::should_apply_optimization(const OptimizationRecommendation& recommendation) const {
    // Check if strategy is enabled
    auto it = std::find(config_.enabled_strategies.begin(), config_.enabled_strategies.end(), recommendation.strategy);
    if (it == config_.enabled_strategies.end()) {
        return false;
    }
    
    // Check if already implemented
    if (recommendation.is_implemented) {
        return false;
    }
    
    // Check performance score threshold
    double performance_score = calculate_performance_score();
    return performance_score < config_.quality_scaling_threshold;
}

void PerformanceOptimizer::log_optimization_event(const std::string& event, const std::string& details) {
    error_handler_->debug(
        "Optimization event: " + event + (details.empty() ? "" : " - " + details),
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

// Hardware acceleration utilities implementation
namespace HardwareAccelerationUtils {
    
    bool has_avx_support() {
        int cpu_info[4];
        __cpuid(cpu_info, 1);
        return (cpu_info[2] & (1 << 28)) != 0;
    }
    
    bool has_avx2_support() {
        int cpu_info[4];
        QueryCpuIdLeaf(cpu_info, 7, 0);
        return (cpu_info[1] & (1 << 5)) != 0;
    }
    
    bool has_avx512_support() {
        int cpu_info[4];
        QueryCpuIdLeaf(cpu_info, 7, 0);
        return (cpu_info[1] & (1 << 16)) != 0;
    }
    
    bool has_cuda_support() {
        // Would need CUDA detection logic
        return false;
    }
    
    bool has_opencl_support() {
        // Would need OpenCL detection logic
        return false;
    }
    
    bool has_d3d11_support() {
        // Assume D3D11 is available on Windows
        return true;
    }
    
    bool has_d3d12_support() {
        // Would need D3D12 detection logic
        return false;
    }
    
    size_t get_cpu_core_count() {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        return sys_info.dwNumberOfProcessors;
    }
    
    size_t get_cpu_thread_count() {
        return get_cpu_core_count();
    }
    
    double get_cpu_frequency_ghz() {
        // Would need to query CPU frequency
        return 3.0; // Placeholder
    }
    
    size_t get_total_memory_mb() {
        MEMORYSTATUSEX mem_status;
        mem_status.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&mem_status);
        return mem_status.ullTotalPhys / (1024 * 1024);
    }
    
    size_t get_available_memory_mb() {
        MEMORYSTATUSEX mem_status;
        mem_status.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&mem_status);
        return mem_status.ullAvailPhys / (1024 * 1024);
    }
    
    std::string get_gpu_name() {
        // Would need GPU detection logic
        return "Unknown GPU";
    }
    
    size_t get_gpu_memory_mb() {
        // Would need GPU memory detection logic
        return 0;
    }
    
    void optimize_for_cpu() {
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    }
    
    void optimize_for_memory() {
        SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    }
    
    void optimize_for_gpu() {
        // Would implement GPU-specific optimizations
    }
    
    void set_process_priority(int priority) {
        SetPriorityClass(GetCurrentProcess(), static_cast<DWORD>(priority));
    }
    
    void set_thread_affinity(size_t thread_id, size_t cpu_core) {
        SetThreadAffinityMask(GetCurrentThread(), 1ULL << cpu_core);
    }
}

// Quality scaling utilities implementation
namespace QualityScalingUtils {
    
    void set_frame_quality_level(double level) {
        // Would implement frame quality adjustment
    }
    
    void set_compression_quality_level(double level) {
        // Would implement compression quality adjustment
    }
    
    void set_texture_quality_level(double level) {
        // Would implement texture quality adjustment
    }
    
    void set_shader_quality_level(double level) {
        // Would implement shader quality adjustment
    }
    
    void adjust_quality_based_on_performance(const PerformanceMetrics& metrics) {
        // Would implement adaptive quality adjustment
    }
    
    void adjust_quality_based_on_memory_usage(double memory_usage_percent) {
        // Would implement memory-based quality adjustment
    }
    
    void adjust_quality_based_on_cpu_usage(double cpu_usage_percent) {
        // Would implement CPU-based quality adjustment
    }
    
    void set_quality_preset_high() {
        PerformanceOptimizerUtils::set_quality_level(1.0);
    }
    
    void set_quality_preset_medium() {
        PerformanceOptimizerUtils::set_quality_level(0.7);
    }
    
    void set_quality_preset_low() {
        PerformanceOptimizerUtils::set_quality_level(0.4);
    }
    
    void set_quality_preset_custom(double level) {
        PerformanceOptimizerUtils::set_quality_level(level);
    }
}

} // namespace UndownUnlock::Optimization 
