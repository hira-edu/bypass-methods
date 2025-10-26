#include "utils/performance_monitor.h"
#include "utils/error_handler.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <numeric>
#include <psapi.h>
#include <pdh.h>
#include <sstream>
#include <thread>
#include <TlHelp32.h>
#include <ctime>

namespace UndownUnlock::Utils {

class CpuUsageMonitor {
public:
    static void start_monitoring(std::chrono::milliseconds interval = std::chrono::seconds(1));
    static void stop_monitoring();
    static double get_cpu_usage();

private:
    static void monitoring_worker();
    static double calculate_cpu_usage();

    static std::atomic<double> cpu_usage_;
    static std::chrono::system_clock::time_point last_check_;
    static std::chrono::milliseconds check_interval_;
    static std::atomic<bool> monitoring_enabled_;
    static std::thread monitoring_thread_;
    static std::atomic<bool> thread_running_;
    static ULARGE_INTEGER last_cpu_time_;
    static ULARGE_INTEGER last_system_time_;
};

class MemoryUsageMonitor {
public:
    static void start_monitoring(std::chrono::milliseconds interval = std::chrono::seconds(1));
    static void stop_monitoring();
    static size_t get_memory_usage();
    static size_t get_peak_memory_usage();

private:
    static void monitoring_worker();
    static size_t calculate_memory_usage();

    static std::atomic<size_t> memory_usage_;
    static std::atomic<size_t> peak_memory_usage_;
    static std::chrono::system_clock::time_point last_check_;
    static std::chrono::milliseconds check_interval_;
    static std::atomic<bool> monitoring_enabled_;
    static std::thread monitoring_thread_;
    static std::atomic<bool> thread_running_;
};

class ThreadUsageMonitor {
public:
    static void start_monitoring(std::chrono::milliseconds interval = std::chrono::seconds(1));
    static void stop_monitoring();
    static size_t get_thread_count();
    static size_t get_active_thread_count();

private:
    static void monitoring_worker();
    static void calculate_thread_usage();

    static std::atomic<size_t> thread_count_;
    static std::atomic<size_t> active_thread_count_;
    static std::chrono::system_clock::time_point last_check_;
    static std::chrono::milliseconds check_interval_;
    static std::atomic<bool> monitoring_enabled_;
    static std::thread monitoring_thread_;
    static std::atomic<bool> thread_running_;
};

class PerformanceProfiler {
public:
    struct ProfilePoint {
        std::string name;
        std::chrono::system_clock::time_point timestamp;
        PerformanceStats stats;
    };

    static void add_profile_point(const std::string& name);
    static void clear_profile();
    static std::vector<ProfilePoint> get_profile();
    static void generate_profile_report(const std::string& filename);
    static void print_profile();

private:
    static std::vector<ProfilePoint> profile_points_;
    static std::mutex profile_mutex_;
};

class BottleneckDetector {
public:
    struct BottleneckInfo {
        std::string name;
        std::string type;
        double severity{0.0};
        std::string description;
        std::chrono::system_clock::time_point detection_time{};
    };

    static void detect_bottlenecks(const PerformanceStats& stats);
    static std::vector<BottleneckInfo> get_bottlenecks();
    static void clear_bottlenecks();
    static size_t get_bottleneck_count();
    static void generate_bottleneck_report(const std::string& filename);
    static void print_bottlenecks();

private:
    static void check_cpu_bottlenecks(const PerformanceStats& stats);
    static void check_memory_bottlenecks(const PerformanceStats& stats);
    static void check_thread_bottlenecks(const PerformanceStats& stats);
    static void check_measurement_bottlenecks(const PerformanceStats& stats);

    static std::vector<BottleneckInfo> detected_bottlenecks_;
    static std::mutex bottlenecks_mutex_;
};

class PerformanceAlert {
public:
    struct AlertRule {
        std::string name;
        std::string metric_name;
        std::string condition;
        double threshold{0.0};
        std::function<void(const std::string&, double)> callback;
        bool enabled{true};
    };

    static void add_alert_rule(const std::string& name,
                               const std::string& metric_name,
                               const std::string& condition,
                               double threshold,
                               std::function<void(const std::string&, double)> callback);
    static void check_alerts(const PerformanceStats& stats);
    static void clear_alerts();
    static size_t get_alert_rule_count();
    static void print_alerts();

private:
    static std::vector<AlertRule> alert_rules_;
    static std::mutex alert_mutex_;
};

// Static member initialization
PerformanceMonitor* PerformanceMonitor::instance_ = nullptr;
std::mutex PerformanceMonitor::instance_mutex_;

// Static member initialization for other classes
std::atomic<double> CpuUsageMonitor::cpu_usage_(0.0);
std::chrono::system_clock::time_point CpuUsageMonitor::last_check_;
std::chrono::milliseconds CpuUsageMonitor::check_interval_(std::chrono::seconds(1));
std::atomic<bool> CpuUsageMonitor::monitoring_enabled_(false);
std::thread CpuUsageMonitor::monitoring_thread_;
std::atomic<bool> CpuUsageMonitor::thread_running_(false);

ULARGE_INTEGER CpuUsageMonitor::last_cpu_time_ = {0};
ULARGE_INTEGER CpuUsageMonitor::last_system_time_ = {0};

std::atomic<size_t> MemoryUsageMonitor::memory_usage_(0);
std::atomic<size_t> MemoryUsageMonitor::peak_memory_usage_(0);
std::chrono::system_clock::time_point MemoryUsageMonitor::last_check_;
std::chrono::milliseconds MemoryUsageMonitor::check_interval_(std::chrono::seconds(1));
std::atomic<bool> MemoryUsageMonitor::monitoring_enabled_(false);
std::thread MemoryUsageMonitor::monitoring_thread_;
std::atomic<bool> MemoryUsageMonitor::thread_running_(false);

std::atomic<size_t> ThreadUsageMonitor::thread_count_(0);
std::atomic<size_t> ThreadUsageMonitor::active_thread_count_(0);
std::chrono::system_clock::time_point ThreadUsageMonitor::last_check_;
std::chrono::milliseconds ThreadUsageMonitor::check_interval_(std::chrono::seconds(1));
std::atomic<bool> ThreadUsageMonitor::monitoring_enabled_(false);
std::thread ThreadUsageMonitor::monitoring_thread_;
std::atomic<bool> ThreadUsageMonitor::thread_running_(false);

std::vector<PerformanceProfiler::ProfilePoint> PerformanceProfiler::profile_points_;
std::mutex PerformanceProfiler::profile_mutex_;

std::vector<BottleneckDetector::BottleneckInfo> BottleneckDetector::detected_bottlenecks_;
std::mutex BottleneckDetector::bottlenecks_mutex_;

std::vector<PerformanceAlert::AlertRule> PerformanceAlert::alert_rules_;
std::mutex PerformanceAlert::alert_mutex_;

// PerformanceMonitor implementation
PerformanceMonitor::PerformanceMonitor() : monitoring_enabled_(false), 
                                          sampling_thread_running_(false) {
    stats_.start_time = std::chrono::system_clock::now();
    last_sampling_ = std::chrono::system_clock::now();
}

PerformanceMonitor::~PerformanceMonitor() {
    stop_monitoring();
    if (sampling_thread_.joinable()) {
        sampling_thread_.join();
    }
}

PerformanceMonitor& PerformanceMonitor::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new PerformanceMonitor();
    }
    return *instance_;
}

PerformanceMonitor* PerformanceMonitor::GetInstance() {
    return &get_instance();
}

void PerformanceMonitor::Initialize() {
    Initialize(PerformanceConfig{});
}

void PerformanceMonitor::Initialize(const PerformanceConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new PerformanceMonitor();
    }
    instance_->set_config(config);
    instance_->initialized_.store(true, std::memory_order_release);
}

bool PerformanceMonitor::is_initialized() const {
    return initialized_.load(std::memory_order_acquire);
}

void PerformanceMonitor::Shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        instance_->stop_monitoring();
        delete instance_;
        instance_ = nullptr;
    }
}

void PerformanceMonitor::start_monitoring() {
    if (monitoring_enabled_.load()) {
        return;
    }
    
    monitoring_enabled_.store(true);
    sampling_thread_running_.store(true);
    sampling_thread_ = std::thread(&PerformanceMonitor::sampling_worker, this);
    
    // Start system monitors
    if (config_.track_cpu_usage) {
        CpuUsageMonitor::start_monitoring();
    }
    if (config_.track_memory_usage) {
        MemoryUsageMonitor::start_monitoring();
    }
    if (config_.track_thread_usage) {
        ThreadUsageMonitor::start_monitoring();
    }
}

void PerformanceMonitor::stop_monitoring() {
    if (!monitoring_enabled_.load()) {
        return;
    }
    
    monitoring_enabled_.store(false);
    sampling_thread_running_.store(false);
    
    if (sampling_thread_.joinable()) {
        sampling_thread_.join();
    }
    
    // Stop system monitors
    CpuUsageMonitor::stop_monitoring();
    MemoryUsageMonitor::stop_monitoring();
    ThreadUsageMonitor::stop_monitoring();
}

void PerformanceMonitor::add_metric(const std::string& name, MetricType type,
                                    const std::string& description) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    if (metrics_.size() >= config_.max_metrics && !metrics_.count(name)) {
        LOG_WARNING("Maximum number of metrics reached, cannot add: " + name, ErrorCategory::GENERAL);
        return;
    }
    auto& metric = get_or_create_metric(name, type);
    metric.description = description;
}

void PerformanceMonitor::update_metric(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::GAUGE);
    metric.value = value;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += value;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = value;
    } else {
        metric.min_value = std::min(metric.min_value, value);
        metric.max_value = std::max(metric.max_value, value);
    }
    append_sample(metric, value);
}

void PerformanceMonitor::increment_metric(const std::string& name, double increment) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::COUNTER);
    metric.value += increment;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += increment;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = metric.value;
    } else {
        metric.min_value = std::min(metric.min_value, metric.value);
        metric.max_value = std::max(metric.max_value, metric.value);
    }
    append_sample(metric, metric.value);
}

PerformanceMetric& PerformanceMonitor::get_or_create_metric(const std::string& name, MetricType type) {
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        PerformanceMetric metric;
        metric.name = name;
        metric.type = type;
        metric.first_update = std::chrono::system_clock::now();
        metric.last_update = metric.first_update;
        metric.max_samples = config_.max_samples_per_metric;
        metric.min_value = std::numeric_limits<double>::max();
        metric.max_value = std::numeric_limits<double>::lowest();
        it = metrics_.emplace(name, std::move(metric)).first;
    }
    return it->second;
}

void PerformanceMonitor::append_sample(PerformanceMetric& metric, double value) {
    metric.samples.push_back(value);
    if (metric.samples.size() > metric.max_samples) {
        metric.samples.erase(metric.samples.begin());
    }
}

void PerformanceMonitor::record_counter(const std::string& name, double value,
                                        const std::string& label) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::COUNTER);
    if (!label.empty()) {
        metric.description = label;
    }
    metric.value += value;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += value;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = metric.value;
    } else {
        metric.min_value = std::min(metric.min_value, metric.value);
        metric.max_value = std::max(metric.max_value, metric.value);
    }
    append_sample(metric, metric.value);
}

void PerformanceMonitor::record_gauge(const std::string& name, double value,
                                      const std::string& label) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::GAUGE);
    if (!label.empty()) {
        metric.description = label;
    }
    metric.value = value;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += value;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = value;
    } else {
        metric.min_value = std::min(metric.min_value, value);
        metric.max_value = std::max(metric.max_value, value);
    }
    append_sample(metric, value);
}

void PerformanceMonitor::record_histogram(const std::string& name, double value,
                                          const std::string& label) {
    record_gauge(name, value, label);
}

void PerformanceMonitor::record_timer(const std::string& name, double duration_ms,
                                      const std::string& label) {
    record_timing_sample(name, duration_ms, label);
}

void PerformanceMonitor::record_rate(const std::string& name, double rate,
                                     const std::string& label) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::RATE);
    if (!label.empty()) {
        metric.description = label;
    }
    metric.value = rate;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += rate;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = rate;
    } else {
        metric.min_value = std::min(metric.min_value, rate);
        metric.max_value = std::max(metric.max_value, rate);
    }
    append_sample(metric, rate);
}

void PerformanceMonitor::record_timing_sample(const std::string& name, double duration_ms,
                                              const std::string& label) {
    record_timer_stat(name, duration_ms, label);

    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto& metric = get_or_create_metric(name, MetricType::TIMER);
    if (!label.empty()) {
        metric.description = label;
    }
    metric.value = duration_ms;
    metric.last_update = std::chrono::system_clock::now();
    metric.count++;
    metric.sum += duration_ms;
    if (metric.count == 1) {
        metric.min_value = metric.max_value = duration_ms;
    } else {
        metric.min_value = std::min(metric.min_value, duration_ms);
        metric.max_value = std::max(metric.max_value, duration_ms);
    }
    append_sample(metric, duration_ms);
}

PerformanceMonitor::ScopedTimer PerformanceMonitor::StartTimer(const std::string& metric_name,
                                                               const std::string& label) {
    return ScopedTimer(metric_name, label);
}

TimerStats PerformanceMonitor::GetTimerStats(const std::string& name) const {
    std::lock_guard<std::mutex> lock(timer_stats_mutex_);
    auto it = timer_stats_.find(name);
    if (it == timer_stats_.end()) {
        return {};
    }
    TimerStats stats = it->second;
    if (stats.sample_count == 0) {
        stats.min_time = 0.0;
        stats.max_time = 0.0;
    }
    return stats;
}

std::unordered_map<std::string, TimerStats> PerformanceMonitor::GetAllStats() const {
    std::lock_guard<std::mutex> lock(timer_stats_mutex_);
    auto snapshot = timer_stats_;
    for (auto& entry : snapshot) {
        if (entry.second.sample_count == 0) {
            entry.second.min_time = 0.0;
            entry.second.max_time = 0.0;
        }
    }
    return snapshot;
}

uint64_t PerformanceMonitor::start_operation(const std::string& name,
                                             const std::string& context) {
    uint64_t id = next_operation_id_.fetch_add(1, std::memory_order_relaxed);
    OperationInfo info;
    info.id = id;
    info.name = name;
    info.context = context;
    info.thread_id = std::this_thread::get_id();
    info.start_time = std::chrono::high_resolution_clock::now();
    {
        std::lock_guard<std::mutex> lock(operations_mutex_);
        active_operations_[id] = info;
    }
    return id;
}

void PerformanceMonitor::end_operation(uint64_t operation_id) {
    OperationInfo completed;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(operations_mutex_);
        auto it = active_operations_.find(operation_id);
        if (it != active_operations_.end()) {
            it->second.end_time = std::chrono::high_resolution_clock::now();
            it->second.completed = true;
            it->second.duration_ms = std::chrono::duration<double, std::milli>(
                it->second.end_time - it->second.start_time).count();
            completed = it->second;
            active_operations_.erase(it);
            found = true;
        }
    }

    if (!found) {
        LOG_WARNING("Operation id not found: " + std::to_string(operation_id),
                    ErrorCategory::PERFORMANCE);
        return;
    }

    handle_operation_completion(completed);
}

bool PerformanceMonitor::has_operation(uint64_t operation_id) const {
    std::lock_guard<std::mutex> lock(operations_mutex_);
    if (active_operations_.count(operation_id)) {
        return true;
    }
    return std::any_of(completed_operations_.begin(), completed_operations_.end(),
                       [operation_id](const OperationInfo& info) { return info.id == operation_id; });
}

void PerformanceMonitor::handle_operation_completion(const OperationInfo& info) {
    record_timing_sample(info.name, info.duration_ms, info.context);
    std::lock_guard<std::mutex> lock(operations_mutex_);
    completed_operations_.push_back(info);
    if (completed_operations_.size() > max_operation_history_) {
        completed_operations_.pop_front();
    }
}

namespace PerformanceUtils {
    double get_system_cpu_usage() {
        return CpuUsageMonitor::get_cpu_usage();
    }
    
    size_t get_system_memory_usage() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return memInfo.ullTotalPhys - memInfo.ullAvailPhys;
        }
        return 0;
    }
    
    size_t get_system_available_memory() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return memInfo.ullAvailPhys;
        }
        return 0;
    }
    
    size_t get_process_cpu_usage() {
        return static_cast<size_t>(CpuUsageMonitor::get_cpu_usage());
    }
    
    size_t get_process_memory_usage() {
        return MemoryUsageMonitor::get_memory_usage();
    }
    
    std::string format_duration(std::chrono::nanoseconds duration) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(duration);
        auto ns = duration.count();
        
        if (ms.count() > 0) {
            return std::to_string(ms.count()) + "ms";
        } else if (us.count() > 0) {
            return std::to_string(us.count()) + "μs";
        } else {
            return std::to_string(ns) + "ns";
        }
    }
    
    std::string format_memory_size(size_t bytes) {
        return MemoryUtils::format_memory_size(bytes);
    }
    
    std::string format_percentage(double value) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << value << "%";
        return oss.str();
    }
    
    bool is_performance_critical() {
        auto cpu_usage = get_system_cpu_usage();
        auto memory_usage = get_system_memory_usage();
        auto available_memory = get_system_available_memory();
        
        return cpu_usage > 90.0 || available_memory < 512 * 1024 * 1024;
    }
    
    void optimize_performance() {
        MemoryUtils::optimize_memory_usage();
        SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
        SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    }
    
    std::vector<std::string> get_performance_recommendations() {
        std::vector<std::string> recommendations;
        
        auto cpu_usage = get_system_cpu_usage();
        auto memory_usage = get_system_memory_usage();
        auto available_memory = get_system_available_memory();
        
        if (cpu_usage > 80.0) {
            recommendations.push_back("Consider reducing CPU-intensive operations");
        }
        
        if (available_memory < 1024 * 1024 * 1024) {
            recommendations.push_back("Consider freeing up memory or reducing memory usage");
        }
        
        if (recommendations.empty()) {
            recommendations.push_back("Performance is within acceptable limits");
        }
        
        return recommendations;
    }
}

} // namespace UndownUnlock::Utils

