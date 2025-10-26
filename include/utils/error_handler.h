#pragma once

#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <array>
#include <type_traits>
#include <windows.h>

#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif
#ifdef EXCEPTION
#undef EXCEPTION
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
    UNKNOWN = 16,
    FILE_SYSTEM = 17,
    DEPENDENCY = 18,
    SIGNATURE_PARSING = 19,
    PROCESS = 20,
    EXCEPTION = 21,
    INVALID_PARAMETER = 22
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
 * Structured error context used for attaching metadata to logs/errors.
 */
class ErrorContext {
public:
    void set(const std::string& key, const std::string& value);
    std::string get(const std::string& key) const;
    void remove(const std::string& key);
    void clear();
    bool empty() const;
    std::string serialize() const;
    
private:
    std::unordered_map<std::string, std::string> entries_;
};

/**
 * Log level abstraction compatible with legacy APIs.
 */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4,
    FATAL = 5
};

/**
 * Lightweight log entry exposed to tests and legacy hooks.
 */
struct LogEntry {
    LogLevel level;
    ErrorCategory category;
    std::string component;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    std::string thread_id;
    std::string context;
};

/**
 * Snapshot of recorded error contexts.
 */
struct ContextSnapshot {
    std::string name;
    std::string details;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * Aggregated statistics returned by get_error_statistics().
 */
struct ErrorStatistics {
    size_t total_errors;
    size_t total_warnings;
    size_t total_info_messages;
    size_t total_debug_messages;
    
    ErrorStatistics()
        : total_errors(0),
          total_warnings(0),
          total_info_messages(0),
          total_debug_messages(0) {}
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

constexpr LogOutput operator|(LogOutput lhs, LogOutput rhs) noexcept {
    return static_cast<LogOutput>(
        static_cast<std::underlying_type_t<LogOutput>>(lhs) |
        static_cast<std::underlying_type_t<LogOutput>>(rhs));
}

constexpr LogOutput operator&(LogOutput lhs, LogOutput rhs) noexcept {
    return static_cast<LogOutput>(
        static_cast<std::underlying_type_t<LogOutput>>(lhs) &
        static_cast<std::underlying_type_t<LogOutput>>(rhs));
}

constexpr LogOutput operator~(LogOutput value) noexcept {
    return static_cast<LogOutput>(
        ~static_cast<std::underlying_type_t<LogOutput>>(value));
}

inline LogOutput& operator|=(LogOutput& lhs, LogOutput rhs) noexcept {
    lhs = lhs | rhs;
    return lhs;
}

inline LogOutput& operator&=(LogOutput& lhs, LogOutput rhs) noexcept {
    lhs = lhs & rhs;
    return lhs;
}

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
    static void Initialize();
    static void Shutdown();
    static ErrorHandler* GetInstance();
    static bool IsInitialized();
    
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
                 const std::string& function = "", const std::string& file = "", int line = 0,
                 DWORD windows_error = 0);
    
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
    void set_minimum_log_level(LogLevel level);
    void set_console_output_enabled(bool enabled);
    
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
    void ClearLogs();
    std::vector<LogEntry> GetLogs() const;
    std::vector<ErrorInfo> GetErrors() const;
    ErrorStatistics get_error_statistics() const;
    ErrorStatistics GetErrorStatistics() const { return get_error_statistics(); }
    
    // Utility methods
    std::string severity_to_string(ErrorSeverity severity) const;
    std::string category_to_string(ErrorCategory category) const;
    std::string get_stack_trace() const;
    std::string get_thread_id() const;
    std::string get_process_id() const;
    bool is_initialized() const { return initialized_.load(); }
    bool is_console_output_enabled() const { return console_output_enabled_.load(); }
    
    // Windows error utilities
    std::string get_windows_error_message(DWORD error_code) const;
    std::string get_last_windows_error_message() const;

    // Error context - ContextGuard RAII helper class
    class ContextGuard {
    public:
        ContextGuard(ErrorHandler& handler, std::string name, ErrorContext context);
        ContextGuard(ContextGuard&& other) noexcept;
        ContextGuard& operator=(ContextGuard&& other) noexcept;
        ~ContextGuard();

        ContextGuard(const ContextGuard&) = delete;
        ContextGuard& operator=(const ContextGuard&) = delete;

    private:
        ErrorHandler* handler_;
        std::string name_;
        ErrorContext context_;
        bool active_;
    };

    ContextGuard CreateContext(const std::string& name, const ErrorContext& context = ErrorContext());
    std::vector<ContextSnapshot> GetContexts() const;
    void set_error_context(const ErrorContext& context);
    void clear_error_context();
    ErrorContext get_error_context() const;
    void push_error_context(const std::string& context);
    void pop_error_context();
    std::string get_current_error_context() const;

    // Convenience logging APIs
    void LogInfo(const std::string& component, const std::string& message);
    void LogWarning(const std::string& component, const std::string& message);
    void LogError(const std::string& component, const std::string& message,
                  ErrorSeverity severity = ErrorSeverity::ERROR,
                  ErrorCategory category = ErrorCategory::GENERAL,
                  DWORD windows_error = 0);
    static void LogInfo(ErrorCategory category, const std::string& message);
    static void LogWarning(ErrorCategory category, const std::string& message);
    static void LogError(ErrorSeverity severity, ErrorCategory category,
                         const std::string& message, DWORD windows_error = 0);

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
    void execute_recovery_strategy(RecoveryStrategy strategy, const ErrorInfo& error_info);
    std::string format_error_message(const ErrorInfo& error_info) const;
    std::string get_timestamp_string() const;
    void check_log_rotation();
    void record_log_entry(LogLevel level, ErrorCategory category, const std::string& message);
    void record_error(const ErrorInfo& error_info);
    void record_context(const std::string& name, const ErrorContext& context);
    void push_context_frame(const std::string& name, const ErrorContext& context);
    void pop_context_frame();
    
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
    std::vector<size_t> severity_counts_;  // Protected by stats_mutex_
    std::vector<size_t> category_counts_;  // Protected by stats_mutex_
    std::atomic<size_t> total_error_count_;
    
    // Recovery strategies
    std::vector<RecoveryStrategy> severity_recovery_strategies_;
    std::vector<RecoveryStrategy> category_recovery_strategies_;
    std::vector<std::function<void(const ErrorInfo&)>> severity_recovery_handlers_;
    std::vector<std::function<void(const ErrorInfo&)>> category_recovery_handlers_;
    
    // Error context stack
    mutable std::mutex context_mutex_;
    std::vector<std::string> error_context_stack_;
    std::vector<std::pair<std::string, ErrorContext>> context_frames_;
    std::vector<ContextSnapshot> context_history_;
    ErrorContext current_context_;
    
    // History buffers
    mutable std::mutex history_mutex_;
    std::deque<LogEntry> log_history_;
    std::deque<ErrorInfo> error_history_;
    size_t max_history_size_;
    
    // Current log file size and flags
    std::atomic<bool> stop_monitoring_;
    std::atomic<size_t> current_log_file_size_;
    std::atomic<bool> console_output_enabled_;
    std::atomic<bool> initialized_;
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
    size_t current_log_file_size_;

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

#ifndef LOG_INFO
#define LOG_INFO(message, category) \
    ::UndownUnlock::Utils::ErrorHandler::LogInfo((category), (message))
#endif

#ifndef LOG_WARNING
#define LOG_WARNING(message, category) \
    ::UndownUnlock::Utils::ErrorHandler::LogWarning((category), (message))
#endif

#ifndef LOG_ERROR
#define LOG_ERROR(message, category) \
    ::UndownUnlock::Utils::ErrorHandler::LogError( \
        ::UndownUnlock::Utils::ErrorSeverity::ERROR, (category), (message))
#endif

#ifndef LOG_WINDOWS_ERROR
#define LOG_WINDOWS_ERROR(message, category)                                      \
    ::UndownUnlock::Utils::ErrorHandler::LogError(                                \
        ::UndownUnlock::Utils::ErrorSeverity::ERROR, (category), (message),       \
        ::GetLastError())
#endif

#ifndef UNDOWNUNLOCK_GLOBAL_ERROR_HANDLER_ALIAS
#define UNDOWNUNLOCK_GLOBAL_ERROR_HANDLER_ALIAS
using ErrorHandler = UndownUnlock::Utils::ErrorHandler;
using ErrorSeverity = UndownUnlock::Utils::ErrorSeverity;
using ErrorCategory = UndownUnlock::Utils::ErrorCategory;
using ErrorContext = UndownUnlock::Utils::ErrorContext;
using LogLevel = UndownUnlock::Utils::LogLevel;
using LogEntry = UndownUnlock::Utils::LogEntry;
using ContextSnapshot = UndownUnlock::Utils::ContextSnapshot;
using ErrorStatistics = UndownUnlock::Utils::ErrorStatistics;
#endif

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
