#pragma once

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace UndownUnlock::Utils {

enum class MetricType {
    COUNTER = 0,
    GAUGE,
    HISTOGRAM,
    TIMER,
    RATE
};

struct TimerStats {
    size_t sample_count{0};
    double total_time_ms{0.0};
    double average_time{0.0};
    double min_time{std::numeric_limits<double>::max()};
    double max_time{0.0};
    std::string last_label;
};

struct PerformanceMetric {
    std::string name;
    std::string description;
    std::string unit;
    MetricType type{MetricType::COUNTER};
    double value{0.0};
    double min_value{0.0};
    double max_value{0.0};
    size_t count{0};
    double sum{0.0};
    size_t max_samples{120};
    std::vector<double> samples;
    std::chrono::system_clock::time_point first_update{};
    std::chrono::system_clock::time_point last_update{};
};

struct PerformancePoint {
    std::string name;
    std::string context;
    std::string thread_id;
    std::chrono::high_resolution_clock::time_point start_time{};
    std::chrono::high_resolution_clock::time_point end_time{};
    bool completed{false};
};

struct OperationInfo {
    uint64_t id{0};
    std::string name;
    std::string context;
    std::thread::id thread_id;
    std::chrono::high_resolution_clock::time_point start_time{};
    std::chrono::high_resolution_clock::time_point end_time{};
    bool completed{false};
    double duration_ms{0.0};
};

struct PerformanceStats {
    std::chrono::system_clock::time_point start_time{};
    std::chrono::system_clock::time_point end_time{};
    size_t total_measurements{0};
    size_t active_measurements{0};
    double cpu_usage{0.0};
    size_t memory_usage{0};
    size_t thread_count{0};
    std::unordered_map<std::string, PerformanceMetric> metrics;
    std::vector<std::string> bottlenecks;
    std::vector<std::string> warnings;
};

struct PerformanceConfig {
    bool track_cpu_usage{true};
    bool track_memory_usage{true};
    bool track_thread_usage{true};
    size_t max_metrics{512};
    size_t max_samples_per_metric{180};
    std::chrono::milliseconds sampling_interval{std::chrono::seconds(1)};
    std::function<void(const PerformanceStats&)> callback;
};

class PerformanceMonitor {
public:
    class ScopedTimer {
    public:
        ScopedTimer(const std::string& metric_name, const std::string& label = "");
        ~ScopedTimer();

        ScopedTimer(const ScopedTimer&) = delete;
        ScopedTimer& operator=(const ScopedTimer&) = delete;

    private:
        std::string metric_name_;
        std::string label_;
        std::chrono::high_resolution_clock::time_point start_time_;
    };

    static ScopedTimer StartTimer(const std::string& metric_name, const std::string& label = "");

    static PerformanceMonitor& get_instance();
    static PerformanceMonitor* GetInstance();

    static void Initialize();
    static void Initialize(const PerformanceConfig& config);
    static void Shutdown();

    bool is_initialized() const;

    void Reset();

    void set_config(const PerformanceConfig& config);
    PerformanceConfig get_config() const;

    void start_monitoring();
    void stop_monitoring();
    bool is_monitoring() const { return monitoring_enabled_.load(); }

    void add_metric(const std::string& name, MetricType type,
                    const std::string& description = "");
    void update_metric(const std::string& name, double value);
    void increment_metric(const std::string& name, double value);

    void record_counter(const std::string& name, double value,
                        const std::string& label = "");
    void record_gauge(const std::string& name, double value,
                      const std::string& label = "");
    void record_histogram(const std::string& name, double value,
                          const std::string& label = "");
    void record_timer(const std::string& name, double duration_ms,
                      const std::string& label = "");
    void record_rate(const std::string& name, double rate,
                     const std::string& label = "");
    void record_timing_sample(const std::string& name, double duration_ms,
                              const std::string& label = "");

    TimerStats GetTimerStats(const std::string& name) const;
    std::unordered_map<std::string, TimerStats> GetAllStats() const;

    uint64_t start_operation(const std::string& name,
                             const std::string& context = "");
    void end_operation(uint64_t operation_id);
    bool has_operation(uint64_t operation_id) const;

    PerformanceStats get_stats() const;

    void start_measurement(const std::string& name,
                           const std::string& context = "");
    void end_measurement(const std::string& name);
    double get_measurement_duration(const std::string& name);

    void set_callback(std::function<void(const PerformanceStats&)> callback);

    void generate_report(const std::string& filename);
    void print_stats();
    void print_metrics();
    void print_measurements();

    std::string get_metric_summary_string() const;

private:
    PerformanceMonitor();
    ~PerformanceMonitor();

    PerformanceMonitor(const PerformanceMonitor&) = delete;
    PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;

    PerformanceMetric& get_or_create_metric(const std::string& name, MetricType type);
    void append_sample(PerformanceMetric& metric, double value);
    void sampling_worker();
    void update_system_metrics();
    void detect_bottlenecks();
    void check_warnings();
    void cleanup_old_samples();
    void handle_operation_completion(const OperationInfo& info);

    std::string format_metric(const PerformanceMetric& metric) const;
    std::string format_measurement(const PerformancePoint& measurement) const;
    std::string format_stats(const PerformanceStats& stats) const;
    std::string format_timestamp(const std::chrono::system_clock::time_point& timestamp) const;

    double calculate_average(const std::vector<double>& samples) const;
    double calculate_percentile(const std::vector<double>& samples, double percentile) const;

    void record_timer_stat(const std::string& name, double duration_ms, const std::string& label);
    std::string metric_type_to_string(MetricType type) const;

private:
    static PerformanceMonitor* instance_;
    static std::mutex instance_mutex_;

    PerformanceConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> monitoring_enabled_{false};
    std::atomic<bool> sampling_thread_running_{false};

    std::thread sampling_thread_;
    std::chrono::system_clock::time_point last_sampling_{};

    std::unordered_map<std::string, PerformanceMetric> metrics_;
    mutable std::mutex metrics_mutex_;

    std::unordered_map<std::string, PerformancePoint> active_measurements_;
    std::vector<PerformancePoint> completed_measurements_;
    mutable std::mutex measurements_mutex_;

    std::unordered_map<uint64_t, OperationInfo> active_operations_;
    std::deque<OperationInfo> completed_operations_;
    mutable std::mutex operations_mutex_;
    std::atomic<uint64_t> next_operation_id_{1};
    size_t max_operation_history_{512};

    std::unordered_map<std::string, TimerStats> timer_stats_;
    mutable std::mutex timer_stats_mutex_;

    PerformanceStats stats_;
    std::atomic<double> current_cpu_usage_{0.0};
    std::atomic<size_t> current_memory_usage_{0};
    std::atomic<size_t> current_thread_count_{0};
};

inline PerformanceMonitor::ScopedTimer::ScopedTimer(const std::string& metric_name,
                                                    const std::string& label)
    : metric_name_(metric_name),
      label_(label),
      start_time_(std::chrono::high_resolution_clock::now()) {}

inline PerformanceMonitor::ScopedTimer::~ScopedTimer() {
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end - start_time_).count();
    PerformanceMonitor::get_instance().record_timing_sample(metric_name_, duration, label_);
}

namespace PerformanceUtils {
    double get_system_cpu_usage();
    size_t get_system_memory_usage();
    size_t get_system_available_memory();
    size_t get_process_cpu_usage();
    size_t get_process_memory_usage();
    std::string format_duration(std::chrono::nanoseconds duration);
    std::string format_memory_size(size_t bytes);
    std::string format_percentage(double value);
    bool is_performance_critical();
    void optimize_performance();
    std::vector<std::string> get_performance_recommendations();
}

namespace MemoryUtils {
    std::string format_memory_size(size_t bytes);
    void optimize_memory_usage();
}

} // namespace UndownUnlock::Utils

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
