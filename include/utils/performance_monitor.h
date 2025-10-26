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
#include <deque>

namespace UndownUnlock {
namespace Utils {

// Forward declarations
class ErrorHandler;

/**
 * Performance metric types
 */
enum class MetricType {
    COUNTER = 0,
    GAUGE = 1,
    HISTOGRAM = 2,
    TIMER = 3,
    RATE = 4
};

/**
 * Performance metric information
 */
struct MetricInfo {
    std::string name;
    MetricType type;
    std::string unit;
    std::string description;
    std::chrono::system_clock::time_point created_time;
    std::chrono::system_clock::time_point last_update_time;
    bool enabled;
    
    MetricInfo() : type(MetricType::COUNTER), enabled(true) {}
};

/**
 * Performance metric value
 */
struct MetricValue {
    double value;
    std::chrono::system_clock::time_point timestamp;
    std::string label;
    
    MetricValue() : value(0.0) {}
    MetricValue(double val, const std::string& lbl = "") : value(val), label(lbl) {}
};

/**
 * Performance statistics
 */
struct PerformanceStats {
    double min_value;
    double max_value;
    double mean_value;
    double median_value;
    double standard_deviation;
    double percentile_95;
    double percentile_99;
    size_t sample_count;
    std::chrono::system_clock::time_point first_sample;
    std::chrono::system_clock::time_point last_sample;
    
    PerformanceStats() : min_value(0.0), max_value(0.0), mean_value(0.0), median_value(0.0),
                        standard_deviation(0.0), percentile_95(0.0), percentile_99(0.0), sample_count(0) {}
};

/**
 * System resource information
 */
struct SystemResourceInfo {
    // CPU information
    double cpu_usage_percent;
    double cpu_usage_per_core[64]; // Support up to 64 cores
    size_t cpu_core_count;
    double cpu_frequency_mhz;
    double cpu_temperature_celsius;
    
    // Memory information
    size_t total_physical_memory;
    size_t available_physical_memory;
    size_t used_physical_memory;
    double memory_usage_percent;
    size_t total_virtual_memory;
    size_t available_virtual_memory;
    size_t used_virtual_memory;
    double virtual_memory_usage_percent;
    
    // Disk information
    size_t total_disk_space;
    size_t available_disk_space;
    size_t used_disk_space;
    double disk_usage_percent;
    double disk_read_bytes_per_sec;
    double disk_write_bytes_per_sec;
    double disk_read_operations_per_sec;
    double disk_write_operations_per_sec;
    
    // Network information
    double network_bytes_received_per_sec;
    double network_bytes_sent_per_sec;
    double network_packets_received_per_sec;
    double network_packets_sent_per_sec;
    
    // Process information
    size_t process_memory_usage;
    double process_cpu_usage_percent;
    size_t process_thread_count;
    size_t process_handle_count;
    double process_io_read_bytes_per_sec;
    double process_io_write_bytes_per_sec;
    
    // Thread information
    size_t total_thread_count;
    size_t active_thread_count;
    size_t idle_thread_count;
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    
    SystemResourceInfo() : cpu_usage_percent(0.0), cpu_core_count(0), cpu_frequency_mhz(0.0),
                          cpu_temperature_celsius(0.0), total_physical_memory(0), available_physical_memory(0),
                          used_physical_memory(0), memory_usage_percent(0.0), total_virtual_memory(0),
                          available_virtual_memory(0), used_virtual_memory(0), virtual_memory_usage_percent(0.0),
                          total_disk_space(0), available_disk_space(0), used_disk_space(0), disk_usage_percent(0.0),
                          disk_read_bytes_per_sec(0.0), disk_write_bytes_per_sec(0.0), disk_read_operations_per_sec(0.0),
                          disk_write_operations_per_sec(0.0), network_bytes_received_per_sec(0.0), network_bytes_sent_per_sec(0.0),
                          network_packets_received_per_sec(0.0), network_packets_sent_per_sec(0.0), process_memory_usage(0),
                          process_cpu_usage_percent(0.0), process_thread_count(0), process_handle_count(0),
                          process_io_read_bytes_per_sec(0.0), process_io_write_bytes_per_sec(0.0), total_thread_count(0),
                          active_thread_count(0), idle_thread_count(0) {
        std::fill(std::begin(cpu_usage_per_core), std::end(cpu_usage_per_core), 0.0);
    }
};

/**
 * Performance bottleneck information
 */
struct BottleneckInfo {
    std::string name;
    std::string description;
    std::string metric_name;
    double current_value;
    double threshold_value;
    double severity_percent;
    std::chrono::system_clock::time_point detection_time;
    std::chrono::system_clock::time_point last_occurrence;
    size_t occurrence_count;
    bool is_active;
    
    BottleneckInfo() : current_value(0.0), threshold_value(0.0), severity_percent(0.0),
                      occurrence_count(0), is_active(false) {}
};

/**
 * Performance alert information
 */
struct PerformanceAlert {
    std::string name;
    std::string description;
    std::string metric_name;
    double value;
    double threshold;
    std::string severity; // "INFO", "WARNING", "ERROR", "CRITICAL"
    std::chrono::system_clock::time_point timestamp;
    bool acknowledged;
    
    PerformanceAlert() : value(0.0), threshold(0.0), acknowledged(false) {}
};

/**
 * Performance monitoring configuration
 */
struct PerformanceMonitorConfig {
    bool enabled;
    std::chrono::milliseconds monitoring_interval;
    std::chrono::milliseconds metrics_retention_period;
    size_t max_metrics_history;
    size_t max_alerts_history;
    bool enable_system_monitoring;
    bool enable_process_monitoring;
    bool enable_thread_monitoring;
    bool enable_disk_monitoring;
    bool enable_network_monitoring;
    bool enable_bottleneck_detection;
    bool enable_alerting;
    std::string alert_log_file;
    bool auto_generate_reports;
    std::string report_directory;
    
    PerformanceMonitorConfig() : enabled(true), monitoring_interval(std::chrono::milliseconds(1000)),
                                metrics_retention_period(std::chrono::milliseconds(3600000)), // 1 hour
                                max_metrics_history(10000), max_alerts_history(1000),
                                enable_system_monitoring(true), enable_process_monitoring(true),
                                enable_thread_monitoring(true), enable_disk_monitoring(true),
                                enable_network_monitoring(true), enable_bottleneck_detection(true),
                                enable_alerting(true), auto_generate_reports(true) {}
};

/**
 * Performance monitoring system
 */
class PerformanceMonitor {
public:
    static PerformanceMonitor& get_instance();
    
    // Configuration
    void set_config(const PerformanceMonitorConfig& config);
    PerformanceMonitorConfig get_config() const;
    void enable(bool enabled = true);
    void disable();
    bool is_enabled() const;
    
    // Metric management
    void register_metric(const std::string& name, MetricType type, const std::string& unit = "",
                        const std::string& description = "");
    void unregister_metric(const std::string& name);
    bool is_metric_registered(const std::string& name) const;
    std::vector<std::string> get_registered_metrics() const;
    
    // Metric recording
    void record_counter(const std::string& name, double value, const std::string& label = "");
    void record_gauge(const std::string& name, double value, const std::string& label = "");
    void record_histogram(const std::string& name, double value, const std::string& label = "");
    void record_timer(const std::string& name, double duration_ms, const std::string& label = "");
    void record_rate(const std::string& name, double rate, const std::string& label = "");
    
    // Timer utilities
    class ScopedTimer {
    public:
        ScopedTimer(const std::string& metric_name, const std::string& label = "");
        ~ScopedTimer();
        
        ScopedTimer(const ScopedTimer&) = delete;
        ScopedTimer& operator=(const ScopedTimer&) = delete;
        
        void stop();
        double get_elapsed_ms() const;
        
    private:
        std::string metric_name_;
        std::string label_;
        std::chrono::high_resolution_clock::time_point start_time_;
        bool stopped_;
    };
    
    // Statistics and queries
    PerformanceStats get_metric_stats(const std::string& name, 
                                     std::chrono::milliseconds duration = std::chrono::milliseconds(0)) const;
    std::vector<MetricValue> get_metric_history(const std::string& name, 
                                               std::chrono::milliseconds duration = std::chrono::milliseconds(0)) const;
    double get_metric_current_value(const std::string& name) const;
    double get_metric_average(const std::string& name, 
                             std::chrono::milliseconds duration = std::chrono::milliseconds(0)) const;
    double get_metric_max(const std::string& name, 
                         std::chrono::milliseconds duration = std::chrono::milliseconds(0)) const;
    double get_metric_min(const std::string& name, 
                         std::chrono::milliseconds duration = std::chrono::milliseconds(0)) const;
    
    // System monitoring
    SystemResourceInfo get_system_resources() const;
    void start_system_monitoring();
    void stop_system_monitoring();
    bool is_system_monitoring() const;
    
    // Bottleneck detection
    void add_bottleneck_threshold(const std::string& metric_name, double threshold, 
                                 const std::string& name = "", const std::string& description = "");
    void remove_bottleneck_threshold(const std::string& metric_name);
    std::vector<BottleneckInfo> get_active_bottlenecks() const;
    std::vector<BottleneckInfo> get_all_bottlenecks() const;
    void clear_bottlenecks();
    
    // Alerting
    void add_alert_threshold(const std::string& metric_name, double threshold, 
                            const std::string& severity, const std::string& name = "",
                            const std::string& description = "");
    void remove_alert_threshold(const std::string& metric_name);
    std::vector<PerformanceAlert> get_active_alerts() const;
    std::vector<PerformanceAlert> get_all_alerts() const;
    void acknowledge_alert(const std::string& alert_name);
    void clear_alerts();
    
    // Monitoring control
    void start_monitoring();
    void stop_monitoring();
    bool is_monitoring() const;
    void set_monitoring_interval(std::chrono::milliseconds interval);
    
    // Callbacks
    void set_bottleneck_callback(std::function<void(const BottleneckInfo&)> callback);
    void set_alert_callback(std::function<void(const PerformanceAlert&)> callback);
    void set_metric_callback(std::function<void(const std::string&, const MetricValue&)> callback);
    void set_system_resource_callback(std::function<void(const SystemResourceInfo&)> callback);
    
    // Reporting
    void generate_report(const std::string& file_path = "");
    void generate_metrics_report(const std::string& file_path = "");
    void generate_system_report(const std::string& file_path = "");
    void generate_bottleneck_report(const std::string& file_path = "");
    void generate_alert_report(const std::string& file_path = "");
    
    // Utility methods
    std::string get_metric_summary_string() const;
    std::string get_system_summary_string() const;
    std::string get_bottleneck_summary_string() const;
    std::string get_alert_summary_string() const;
    
    // Performance profiling
    void start_profiling(const std::string& profile_name);
    void stop_profiling(const std::string& profile_name);
    void add_profiling_point(const std::string& profile_name, const std::string& point_name);
    void generate_profiling_report(const std::string& profile_name, const std::string& file_path = "");

private:
    PerformanceMonitor();
    ~PerformanceMonitor();
    
    // Delete copy semantics
    PerformanceMonitor(const PerformanceMonitor&) = delete;
    PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;
    
    // Internal methods
    void initialize();
    void cleanup();
    void monitoring_thread_func();
    void update_system_resources();
    void check_bottlenecks();
    void check_alerts();
    void cleanup_old_metrics();
    void cleanup_old_alerts();
    void log_alert(const PerformanceAlert& alert);
    void log_bottleneck(const BottleneckInfo& bottleneck);
    std::string get_timestamp_string() const;
    
    // Member variables
    PerformanceMonitorConfig config_;
    std::atomic<bool> enabled_;
    std::atomic<bool> monitoring_;
    std::atomic<bool> system_monitoring_;
    
    // Metrics storage
    std::unordered_map<std::string, MetricInfo> metrics_;
    std::unordered_map<std::string, std::deque<MetricValue>> metric_history_;
    mutable std::mutex metrics_mutex_;
    
    // System resources
    SystemResourceInfo current_system_resources_;
    std::deque<SystemResourceInfo> system_resources_history_;
    mutable std::mutex system_resources_mutex_;
    
    // Bottlenecks
    std::unordered_map<std::string, BottleneckInfo> bottlenecks_;
    std::vector<BottleneckInfo> active_bottlenecks_;
    mutable std::mutex bottlenecks_mutex_;
    
    // Alerts
    std::unordered_map<std::string, PerformanceAlert> alerts_;
    std::vector<PerformanceAlert> active_alerts_;
    std::deque<PerformanceAlert> alerts_history_;
    mutable std::mutex alerts_mutex_;
    
    // Callbacks
    std::function<void(const BottleneckInfo&)> bottleneck_callback_;
    std::function<void(const PerformanceAlert&)> alert_callback_;
    std::function<void(const std::string&, const MetricValue&)> metric_callback_;
    std::function<void(const SystemResourceInfo&)> system_resource_callback_;
    
    // Monitoring
    std::chrono::milliseconds monitoring_interval_;
    std::thread monitoring_thread_;
    std::atomic<bool> stop_monitoring_;
    
    // System monitoring handles
    HANDLE cpu_query_;
    HANDLE memory_query_;
    HANDLE disk_query_;
    HANDLE network_query_;
    HANDLE process_query_;
    
    // Error handler
    ErrorHandler* error_handler_;
    
    // Profiling
    struct ProfilingSession {
        std::string name;
        std::chrono::high_resolution_clock::time_point start_time;
        std::vector<std::pair<std::string, std::chrono::high_resolution_clock::time_point>> points;
        bool active;
    };
    
    std::unordered_map<std::string, ProfilingSession> profiling_sessions_;
    mutable std::mutex profiling_mutex_;
};

/**
 * Performance monitoring macros
 */
#define PERFORMANCE_TIMER(name, label) \
    utils::PerformanceMonitor::ScopedTimer performance_timer_##__LINE__(name, label)

#define PERFORMANCE_RECORD_COUNTER(name, value, label) \
    utils::PerformanceMonitor::get_instance().record_counter(name, value, label)

#define PERFORMANCE_RECORD_GAUGE(name, value, label) \
    utils::PerformanceMonitor::get_instance().record_gauge(name, value, label)

#define PERFORMANCE_RECORD_HISTOGRAM(name, value, label) \
    utils::PerformanceMonitor::get_instance().record_histogram(name, value, label)

#define PERFORMANCE_RECORD_TIMER(name, duration_ms, label) \
    utils::PerformanceMonitor::get_instance().record_timer(name, duration_ms, label)

#define PERFORMANCE_RECORD_RATE(name, rate, label) \
    utils::PerformanceMonitor::get_instance().record_rate(name, rate, label)

#define PERFORMANCE_PROFILE_START(name) \
    utils::PerformanceMonitor::get_instance().start_profiling(name)

#define PERFORMANCE_PROFILE_STOP(name) \
    utils::PerformanceMonitor::get_instance().stop_profiling(name)

#define PERFORMANCE_PROFILE_POINT(name, point) \
    utils::PerformanceMonitor::get_instance().add_profiling_point(name, point)

/**
 * Utility functions
 */
namespace performance_utils {
    
    // System resource utilities
    double get_cpu_usage_percent();
    double get_memory_usage_percent();
    double get_disk_usage_percent();
    size_t get_process_memory_usage();
    double get_process_cpu_usage_percent();
    
    // Performance utilities
    double get_elapsed_time_ms(const std::chrono::high_resolution_clock::time_point& start);
    std::string format_duration_ms(double duration_ms);
    std::string format_bytes(size_t bytes);
    std::string format_percentage(double percentage);
    
    // Performance analysis
    double calculate_percentile(const std::vector<double>& values, double percentile);
    double calculate_standard_deviation(const std::vector<double>& values);
    double calculate_mean(const std::vector<double>& values);
    double calculate_median(const std::vector<double>& values);
    
    // Performance reporting
    void generate_performance_summary();
    void generate_performance_report(const std::string& file_path = "");
    
} // namespace performance_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
