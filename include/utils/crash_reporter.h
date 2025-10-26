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
#include <dbghelp.h>

namespace UndownUnlock {
namespace Utils {

// Forward declarations
class ErrorHandler;

/**
 * Crash information structure
 */
struct CrashInfo {
    std::string crash_type; // "Access Violation", "Stack Overflow", "Divide by Zero", etc.
    DWORD exception_code;
    void* exception_address;
    void* fault_address;
    std::string exception_description;
    std::string stack_trace;
    std::string register_dump;
    std::string module_info;
    std::string thread_info;
    std::string process_info;
    std::string system_info;
    std::chrono::system_clock::time_point crash_time;
    std::string crash_file;
    std::string dump_file;
    bool handled;
    bool fatal;
    
    CrashInfo() : exception_code(0), exception_address(nullptr), fault_address(nullptr),
                  handled(false), fatal(true) {}
};

/**
 * Crash statistics
 */
struct CrashStats {
    std::atomic<size_t> total_crashes;
    std::atomic<size_t> handled_crashes;
    std::atomic<size_t> fatal_crashes;
    std::atomic<size_t> access_violations;
    std::atomic<size_t> stack_overflows;
    std::atomic<size_t> divide_by_zeros;
    std::atomic<size_t> illegal_instructions;
    std::atomic<size_t> unknown_exceptions;
    std::chrono::system_clock::time_point first_crash;
    std::chrono::system_clock::time_point last_crash;
    
    CrashStats() : total_crashes(0), handled_crashes(0), fatal_crashes(0),
                   access_violations(0), stack_overflows(0), divide_by_zeros(0),
                   illegal_instructions(0), unknown_exceptions(0) {}
};

/**
 * Crash recovery information
 */
struct CrashRecoveryInfo {
    std::string recovery_type; // "Restart", "Continue", "Safe Mode", "Terminate"
    bool recovery_successful;
    std::string recovery_message;
    std::chrono::system_clock::time_point recovery_time;
    size_t recovery_attempts;
    std::string recovery_log;
    
    CrashRecoveryInfo() : recovery_successful(false), recovery_attempts(0) {}
};

/**
 * Crash prevention information
 */
struct CrashPreventionInfo {
    std::string prevention_type; // "Memory Protection", "Stack Guard", "Exception Handler", etc.
    bool prevention_active;
    std::string prevention_description;
    std::chrono::system_clock::time_point activation_time;
    size_t prevented_crashes;
    
    CrashPreventionInfo() : prevention_active(false), prevented_crashes(0) {}
};

/**
 * Crash reporting configuration
 */
struct CrashReporterConfig {
    bool enabled;
    bool generate_minidumps;
    bool generate_full_dumps;
    bool generate_crash_logs;
    std::string dump_directory;
    std::string log_directory;
    size_t max_dump_files;
    size_t max_log_files;
    bool auto_cleanup_old_files;
    std::chrono::milliseconds cleanup_interval;
    bool enable_crash_recovery;
    bool enable_crash_prevention;
    bool enable_crash_notification;
    std::string notification_email;
    std::string notification_webhook;
    bool collect_system_info;
    bool collect_module_info;
    bool collect_thread_info;
    bool collect_register_info;
    bool collect_stack_trace;
    size_t max_stack_frames;
    bool enable_crash_statistics;
    bool enable_crash_analysis;
    
    CrashReporterConfig() : enabled(true), generate_minidumps(true), generate_full_dumps(false),
                           generate_crash_logs(true), max_dump_files(10), max_log_files(50),
                           auto_cleanup_old_files(true), cleanup_interval(std::chrono::milliseconds(86400000)), // 24 hours
                           enable_crash_recovery(true), enable_crash_prevention(true),
                           enable_crash_notification(false), collect_system_info(true),
                           collect_module_info(true), collect_thread_info(true),
                           collect_register_info(true), collect_stack_trace(true),
                           max_stack_frames(64), enable_crash_statistics(true),
                           enable_crash_analysis(true) {}
};

/**
 * Crash reporting system
 */
class CrashReporter {
public:
    static CrashReporter& get_instance();
    
    // Configuration
    void set_config(const CrashReporterConfig& config);
    CrashReporterConfig get_config() const;
    void enable(bool enabled = true);
    void disable();
    bool is_enabled() const;
    
    // Exception handling
    LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* exception_info);
    LONG WINAPI vectored_exception_handler(EXCEPTION_POINTERS* exception_info);
    void set_unhandled_exception_filter();
    void set_vectored_exception_handler();
    void remove_exception_handlers();
    
    // Crash reporting
    void report_crash(const CrashInfo& crash_info);
    void report_crash(EXCEPTION_POINTERS* exception_info, const std::string& crash_type = "");
    void report_crash(DWORD exception_code, void* exception_address = nullptr, 
                     void* fault_address = nullptr, const std::string& crash_type = "");
    
    // Crash dump generation
    bool generate_minidump(const std::string& file_path, EXCEPTION_POINTERS* exception_info = nullptr);
    bool generate_full_dump(const std::string& file_path, EXCEPTION_POINTERS* exception_info = nullptr);
    bool generate_crash_dump(const CrashInfo& crash_info, const std::string& file_path);
    
    // Crash information collection
    CrashInfo collect_crash_info(EXCEPTION_POINTERS* exception_info, const std::string& crash_type = "");
    std::string collect_stack_trace(EXCEPTION_POINTERS* exception_info = nullptr, size_t max_frames = 64);
    std::string collect_register_dump(EXCEPTION_POINTERS* exception_info);
    std::string collect_module_info();
    std::string collect_thread_info();
    std::string collect_process_info();
    std::string collect_system_info();
    
    // Crash recovery
    bool attempt_crash_recovery(const CrashInfo& crash_info);
    void set_recovery_strategy(const std::string& crash_type, 
                              std::function<bool(const CrashInfo&)> strategy);
    void remove_recovery_strategy(const std::string& crash_type);
    CrashRecoveryInfo get_last_recovery_info() const;
    
    // Crash prevention
    void enable_crash_prevention(const std::string& prevention_type);
    void disable_crash_prevention(const std::string& prevention_type);
    bool is_crash_prevention_enabled(const std::string& prevention_type) const;
    std::vector<CrashPreventionInfo> get_active_preventions() const;
    
    // Crash notification
    void set_crash_notification_callback(std::function<void(const CrashInfo&)> callback);
    void send_crash_notification(const CrashInfo& crash_info);
    void set_notification_email(const std::string& email);
    void set_notification_webhook(const std::string& webhook);
    
    // Statistics
    CrashStats get_crash_statistics() const;
    void reset_crash_statistics();
    size_t get_total_crashes() const;
    size_t get_handled_crashes() const;
    size_t get_fatal_crashes() const;
    
    // File management
    void cleanup_old_crash_files();
    void cleanup_old_dump_files();
    void cleanup_old_log_files();
    std::vector<std::string> get_crash_files() const;
    std::vector<std::string> get_dump_files() const;
    std::vector<std::string> get_log_files() const;
    
    // Reporting
    void generate_crash_report(const std::string& file_path = "");
    void generate_crash_summary(const std::string& file_path = "");
    void generate_crash_analysis(const std::string& file_path = "");
    
    // Callbacks
    void set_crash_callback(std::function<void(const CrashInfo&)> callback);
    void set_pre_crash_callback(std::function<void(const CrashInfo&)> callback);
    void set_post_crash_callback(std::function<void(const CrashInfo&)> callback);
    
    // Utility methods
    std::string get_crash_type_string(DWORD exception_code) const;
    std::string get_exception_description(DWORD exception_code) const;
    bool is_crash_fatal(DWORD exception_code) const;
    bool is_crash_recoverable(DWORD exception_code) const;
    std::string get_crash_summary_string() const;
    
    // Crash analysis
    void analyze_crash_patterns();
    std::vector<std::string> get_crash_recommendations() const;
    void generate_crash_trends_report(const std::string& file_path = "");

private:
    CrashReporter();
    ~CrashReporter();
    
    // Delete copy semantics
    CrashReporter(const CrashReporter&) = delete;
    CrashReporter& operator=(const CrashReporter&) = delete;
    
    // Internal methods
    void initialize();
    void cleanup();
    void initialize_dbghelp();
    void cleanup_dbghelp();
    bool create_dump_directory();
    bool create_log_directory();
    std::string generate_dump_filename() const;
    std::string generate_log_filename() const;
    void write_crash_log(const CrashInfo& crash_info);
    void update_crash_statistics(const CrashInfo& crash_info);
    void log_crash_info(const CrashInfo& crash_info);
    std::string format_crash_info(const CrashInfo& crash_info) const;
    std::string get_timestamp_string() const;
    
    // Member variables
    CrashReporterConfig config_;
    std::atomic<bool> enabled_;
    std::atomic<bool> initialized_;
    
    // Exception handling
    PVOID vectored_handler_;
    LPTOP_LEVEL_EXCEPTION_FILTER previous_filter_;
    
    // Crash storage
    std::vector<CrashInfo> crash_history_;
    std::deque<CrashRecoveryInfo> recovery_history_;
    std::vector<CrashPreventionInfo> active_preventions_;
    mutable std::mutex crash_mutex_;
    
    // Statistics
    CrashStats crash_stats_;
    mutable std::mutex stats_mutex_;
    
    // Recovery strategies
    std::unordered_map<std::string, std::function<bool(const CrashInfo&)>> recovery_strategies_;
    CrashRecoveryInfo last_recovery_info_;
    mutable std::mutex recovery_mutex_;
    
    // Callbacks
    std::function<void(const CrashInfo&)> crash_callback_;
    std::function<void(const CrashInfo&)> pre_crash_callback_;
    std::function<void(const CrashInfo&)> post_crash_callback_;
    std::function<void(const CrashInfo&)> notification_callback_;
    
    // Error handler
    ErrorHandler* error_handler_;
    
    // DbgHelp
    HMODULE dbghelp_module_;
    bool dbghelp_initialized_;
    
    // File management
    std::string dump_directory_;
    std::string log_directory_;
    std::chrono::system_clock::time_point last_cleanup_;
    
    // Crash analysis
    std::vector<std::string> crash_recommendations_;
    mutable std::mutex analysis_mutex_;
};

/**
 * RAII wrapper for crash prevention
 */
class ScopedCrashPrevention {
public:
    explicit ScopedCrashPrevention(const std::string& prevention_type);
    ~ScopedCrashPrevention();
    
    // Move semantics
    ScopedCrashPrevention(ScopedCrashPrevention&& other) noexcept;
    ScopedCrashPrevention& operator=(ScopedCrashPrevention&& other) noexcept;
    
    // Delete copy semantics
    ScopedCrashPrevention(const ScopedCrashPrevention&) = delete;
    ScopedCrashPrevention& operator=(const ScopedCrashPrevention&) = delete;
    
    // Methods
    void disable();
    bool is_active() const;
    std::string get_prevention_type() const;

private:
    std::string prevention_type_;
    bool active_;
};

/**
 * RAII wrapper for crash recovery
 */
class ScopedCrashRecovery {
public:
    explicit ScopedCrashRecovery(const std::string& recovery_type,
                                 std::function<bool(const CrashInfo&)> recovery_function);
    ~ScopedCrashRecovery();
    
    // Move semantics
    ScopedCrashRecovery(ScopedCrashRecovery&& other) noexcept;
    ScopedCrashRecovery& operator=(ScopedCrashRecovery&& other) noexcept;
    
    // Delete copy semantics
    ScopedCrashRecovery(const ScopedCrashRecovery&) = delete;
    ScopedCrashRecovery& operator=(const ScopedCrashRecovery&) = delete;
    
    // Methods
    void remove();
    bool is_active() const;
    std::string get_recovery_type() const;

private:
    std::string recovery_type_;
    bool active_;
};

/**
 * Crash reporting macros
 */
#define CRASH_PREVENTION(type) \
    utils::ScopedCrashPrevention crash_prevention_##__LINE__(type)

#define CRASH_RECOVERY(type, function) \
    utils::ScopedCrashRecovery crash_recovery_##__LINE__(type, function)

#define CRASH_REPORT(exception_info, crash_type) \
    utils::CrashReporter::get_instance().report_crash(exception_info, crash_type)

#define CRASH_GENERATE_DUMP(file_path, exception_info) \
    utils::CrashReporter::get_instance().generate_minidump(file_path, exception_info)

/**
 * Utility functions
 */
namespace crash_utils {
    
    // Exception utilities
    std::string get_exception_code_string(DWORD exception_code);
    std::string get_exception_description(DWORD exception_code);
    bool is_exception_fatal(DWORD exception_code);
    bool is_exception_recoverable(DWORD exception_code);
    
    // Stack trace utilities
    std::string get_stack_trace_from_context(CONTEXT* context, size_t max_frames = 64);
    std::string get_stack_trace_from_exception(EXCEPTION_POINTERS* exception_info, size_t max_frames = 64);
    std::vector<void*> get_call_stack(size_t max_frames = 64);
    
    // Register utilities
    std::string format_register_dump(CONTEXT* context);
    std::string format_register_dump(EXCEPTION_POINTERS* exception_info);
    
    // Module utilities
    std::string get_module_name_from_address(void* address);
    std::string get_function_name_from_address(void* address);
    std::string get_source_line_from_address(void* address);
    
    // Thread utilities
    std::string get_thread_info(DWORD thread_id = 0);
    std::string get_all_threads_info();
    
    // Process utilities
    std::string get_process_info();
    std::string get_process_memory_info();
    
    // System utilities
    std::string get_system_info();
    std::string get_os_version_info();
    std::string get_hardware_info();
    
    // Crash analysis utilities
    std::vector<std::string> analyze_crash_cause(const CrashInfo& crash_info);
    std::vector<std::string> get_crash_prevention_suggestions(const CrashInfo& crash_info);
    std::string generate_crash_summary(const CrashInfo& crash_info);
    
    // Crash reporting utilities
    void generate_crash_report(const CrashInfo& crash_info, const std::string& file_path = "");
    void send_crash_notification(const CrashInfo& crash_info);
    
} // namespace crash_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
