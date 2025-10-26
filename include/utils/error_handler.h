#pragma once

#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <windows.h>

#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif


namespace UndownUnlock {
namespace Utils {

/**
 * Error severity levels
 */
enum class ErrorSeverity {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4,
    FATAL = 5
};

/**
 * Error categories
 */
enum class ErrorCategory {
    GENERAL = 0,
    MEMORY = 1,
    FILE_IO = 2,
    NETWORK = 3,
    GRAPHICS = 4,
    HOOK = 5,
    INJECTION = 6,
    CAPTURE = 7,
    SYSTEM = 8,
    SECURITY = 9,
    PERFORMANCE = 10,
    THREADING = 11,
    SYNCHRONIZATION = 12,
    WINDOWS_API = 13,
    COM = 14,
    DIRECTX = 15,
    UNKNOWN = 16
};

/**
 * Error information structure
 */
struct ErrorInfo {
    ErrorSeverity severity;
    ErrorCategory category;
    std::string message;
    std::string function;
    std::string file;
    int line;
    DWORD windows_error;
    std::string stack_trace;
    std::chrono::system_clock::time_point timestamp;
    std::string thread_id;
    std::string process_id;
    
    ErrorInfo() : severity(ErrorSeverity::INFO), category(ErrorCategory::GENERAL), 
                  line(0), windows_error(0) {}
};

/**
 * Recovery strategy types
 */
enum class RecoveryStrategy {
    NONE = 0,
    RETRY = 1,
    FALLBACK = 2,
    RESTART = 3,
    TERMINATE = 4,
    LOG_AND_CONTINUE = 5,
    LOG_AND_THROW = 6
};

/**
 * Log output types
 */
enum class LogOutput {
    CONSOLE = 1,
    FILE = 2,
    EVENT_LOG = 4,
    DEBUGGER = 8,
    ALL = 15
};

/**
 * Forward declarations
 */
class ErrorHandler;
class LogOutputBase;
class ConsoleLogOutput;
class FileLogOutput;
class EventLogOutput;
class DebuggerLogOutput;

/**
 * Centralized error handling system
 */
class ErrorHandler {
public:
    static ErrorHandler& get_instance();
    
    // Error reporting
    void report_error(ErrorSeverity severity, ErrorCategory category, 
                     const std::string& message, const std::string& function = "",
                     const std::string& file = "", int line = 0, DWORD windows_error = 0);
    
    void report_error(const ErrorInfo& error_info);
    
    // Convenience methods
    void debug(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
               const std::string& function = "", const std::string& file = "", int line = 0);
    
    void info(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
              const std::string& function = "", const std::string& file = "", int line = 0);
    
    void warning(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
                 const std::string& function = "", const std::string& file = "", int line = 0);
    
    void error(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
               const std::string& function = "", const std::string& file = "", int line = 0,
               DWORD windows_error = 0);
    
    void critical(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
                  const std::string& function = "", const std::string& file = "", int line = 0,
                  DWORD windows_error = 0);
    
    void fatal(const std::string& message, ErrorCategory category = ErrorCategory::GENERAL,
               const std::string& function = "", const std::string& file = "", int line = 0,
               DWORD windows_error = 0);
    
    // Configuration
    void set_minimum_severity(ErrorSeverity severity);
    void set_log_outputs(LogOutput outputs);
    void set_log_file_path(const std::string& path);
    void set_max_log_file_size(size_t max_size);
    void set_max_log_files(size_t max_files);
    void set_include_stack_trace(bool include);
    void set_include_timestamp(bool include);
    void set_include_thread_info(bool include);
    
    // Recovery strategies
    void set_recovery_strategy(ErrorSeverity severity, RecoveryStrategy strategy);
    void set_recovery_strategy(ErrorCategory category, RecoveryStrategy strategy);
    void set_custom_recovery_handler(ErrorSeverity severity, 
                                    std::function<void(const ErrorInfo&)> handler);
    void set_custom_recovery_handler(ErrorCategory category, 
                                    std::function<void(const ErrorInfo&)> handler);
    
    // Statistics
    size_t get_error_count(ErrorSeverity severity) const;
    size_t get_error_count(ErrorCategory category) const;
    size_t get_total_error_count() const;
    void reset_statistics();
    
    // Log management
    void flush_logs();
    void rotate_log_files();
    void clear_logs();
    
    // Utility methods
    std::string severity_to_string(ErrorSeverity severity) const;
    std::string category_to_string(ErrorCategory category) const;
    std::string get_stack_trace() const;
    std::string get_thread_id() const;
    std::string get_process_id() const;
    
    // Windows error utilities
    std::string get_windows_error_message(DWORD error_code) const;
    std::string get_last_windows_error_message() const;
    
    // Error context
    void push_error_context(const std::string& context);
    void pop_error_context();
    std::string get_current_error_context() const;

private:
    ErrorHandler();
    ~ErrorHandler();
    
    // Delete copy semantics
    ErrorHandler(const ErrorHandler&) = delete;
    ErrorHandler& operator=(const ErrorHandler&) = delete;
    
    // Internal methods
    void initialize_log_outputs();
    void cleanup_log_outputs();
    void write_to_outputs(const ErrorInfo& error_info);
    void handle_recovery(const ErrorInfo& error_info);
    std::string format_error_message(const ErrorInfo& error_info) const;
    std::string get_timestamp_string() const;
    void check_log_rotation();
    
    // Member variables
    std::atomic<ErrorSeverity> minimum_severity_;
    std::atomic<LogOutput> log_output_mask_;
    std::string log_file_path_;
    std::atomic<size_t> max_log_file_size_;
    std::atomic<size_t> max_log_files_;
    std::atomic<bool> include_stack_trace_;
    std::atomic<bool> include_timestamp_;
    std::atomic<bool> include_thread_info_;
    
    std::vector<std::unique_ptr<LogOutputBase>> log_sinks_;
    std::mutex log_mutex_;
    std::mutex config_mutex_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    std::vector<std::atomic<size_t>> severity_counts_;
    std::vector<std::atomic<size_t>> category_counts_;
    std::atomic<size_t> total_error_count_;
    
    // Recovery strategies
    std::vector<RecoveryStrategy> severity_recovery_strategies_;
    std::vector<RecoveryStrategy> category_recovery_strategies_;
    std::vector<std::function<void(const ErrorInfo&)>> severity_recovery_handlers_;
    std::vector<std::function<void(const ErrorInfo&)>> category_recovery_handlers_;
    
    // Error context stack
    mutable std::mutex context_mutex_;
    std::vector<std::string> error_context_stack_;
    
    // Current log file size
    std::atomic<size_t> current_log_file_size_;
};

/**
 * Base class for log outputs
 */
class LogOutputBase {
public:
    virtual ~LogOutputBase() = default;
    virtual void write(const ErrorInfo& error_info, const std::string& formatted_message) = 0;
    virtual void flush() = 0;
    virtual void close() = 0;
};

/**
 * Console log output
 */
class ConsoleLogOutput : public LogOutputBase {
public:
    ConsoleLogOutput();
    ~ConsoleLogOutput() override;
    
    void write(const ErrorInfo& error_info, const std::string& formatted_message) override;
    void flush() override;
    void close() override;
    
    void set_use_colors(bool use_colors);
    void set_use_unicode(bool use_unicode);

private:
    bool use_colors_;
    bool use_unicode_;
    HANDLE console_handle_;
    
    void set_console_color(ErrorSeverity severity);
    void reset_console_color();
};

/**
 * File log output
 */
class FileLogOutput : public LogOutputBase {
public:
    explicit FileLogOutput(const std::string& file_path);
    ~FileLogOutput() override;
    
    void write(const ErrorInfo& error_info, const std::string& formatted_message) override;
    void flush() override;
    void close() override;
    
    void set_file_path(const std::string& file_path);
    void set_max_file_size(size_t max_size);
    void set_max_files(size_t max_files);
    void rotate_files();

private:
    std::string file_path_;
    size_t max_file_size_;
    size_t max_files_;
    HANDLE file_handle_;
    std::mutex file_mutex_;
    
    bool open_file();
    void close_file();
    void check_file_size();
    std::string get_rotated_file_path(size_t index) const;
};

/**
 * Event log output
 */
class EventLogOutput : public LogOutputBase {
public:
    explicit EventLogOutput(const std::string& source_name = "BypassMethods");
    ~EventLogOutput() override;
    
    void write(const ErrorInfo& error_info, const std::string& formatted_message) override;
    void flush() override;
    void close() override;
    
    void set_source_name(const std::string& source_name);

private:
    std::string source_name_;
    HANDLE event_log_handle_;
    
    WORD severity_to_event_type(ErrorSeverity severity) const;
    bool register_event_source();
    void deregister_event_source();
};

/**
 * Debugger log output
 */
class DebuggerLogOutput : public LogOutputBase {
public:
    DebuggerLogOutput();
    ~DebuggerLogOutput() override;
    
    void write(const ErrorInfo& error_info, const std::string& formatted_message) override;
    void flush() override;
    void close() override;
    
    void set_include_debug_info(bool include);

private:
    bool include_debug_info_;
    
    std::string format_debug_info(const ErrorInfo& error_info) const;
};

/**
 * Utility functions
 */
namespace error_utils {
    
    // Error reporting macros
    #define ERROR_REPORT(severity, category, message, windows_error) \
        utils::ErrorHandler::get_instance().report_error(severity, category, message, \
                                                        __FUNCTION__, __FILE__, __LINE__, windows_error)
    
    #define ERROR_DEBUG(message, category) \
        utils::ErrorHandler::get_instance().debug(message, category, __FUNCTION__, __FILE__, __LINE__)
    
    #define ERROR_INFO(message, category) \
        utils::ErrorHandler::get_instance().info(message, category, __FUNCTION__, __FILE__, __LINE__)
    
    #define ERROR_WARNING(message, category) \
        utils::ErrorHandler::get_instance().warning(message, category, __FUNCTION__, __FILE__, __LINE__)
    
    #define ERROR_ERROR(message, category, windows_error) \
        utils::ErrorHandler::get_instance().error(message, category, __FUNCTION__, __FILE__, __LINE__, windows_error)
    
    #define ERROR_CRITICAL(message, category, windows_error) \
        utils::ErrorHandler::get_instance().critical(message, category, __FUNCTION__, __FILE__, __LINE__, windows_error)
    
    #define ERROR_FATAL(message, category, windows_error) \
        utils::ErrorHandler::get_instance().fatal(message, category, __FUNCTION__, __FILE__, __LINE__, windows_error)
    
    // Windows error utilities
    std::string get_windows_error_message(DWORD error_code);
    std::string get_last_windows_error_message();
    
    // Stack trace utilities
    std::string get_stack_trace();
    std::string get_call_stack(size_t max_frames = 32);
    
    // Thread utilities
    std::string get_thread_id();
    std::string get_process_id();
    
    // Error context utilities
    class ScopedErrorContext {
    public:
        explicit ScopedErrorContext(const std::string& context);
        ~ScopedErrorContext();
        
        ScopedErrorContext(const ScopedErrorContext&) = delete;
        ScopedErrorContext& operator=(const ScopedErrorContext&) = delete;
    
    private:
        std::string context_;
    };
    
    #define ERROR_CONTEXT(context) \
        utils::error_utils::ScopedErrorContext error_context_##__LINE__(context)
    
} // namespace error_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
