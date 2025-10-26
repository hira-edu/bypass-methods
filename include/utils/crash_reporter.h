#pragma once

#include <windows.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace UndownUnlock {
namespace Utils {

struct CrashInfo {
    std::string crash_type;
    std::string crash_reason;
    DWORD exception_code;
    void* exception_address;
    std::string exception_info;
    std::string stack_trace;
    std::string register_dump;
    std::string system_info;
    std::string process_info;
    std::string module_info;
    std::string dump_file_path;
    std::string log_file_path;
    DWORD process_id;
    DWORD thread_id;
    std::chrono::system_clock::time_point crash_time;

    CrashInfo()
        : exception_code(0),
          exception_address(nullptr),
          process_id(0),
          thread_id(0),
          crash_time(std::chrono::system_clock::now()) {}
};

enum class CrashDumpType {
    MINI_DUMP = 0,
    FULL_DUMP = 1,
    CUSTOM_DUMP = 2
};

struct CrashReporterConfig {
    bool enabled = true;
    bool generate_mini_dumps = true;
    bool generate_full_dumps = false;
    bool capture_stack_trace = true;
    bool capture_register_dump = true;
    bool capture_system_info = true;
    bool capture_process_info = true;
    bool capture_module_info = true;
    bool send_crash_reports = false;
    bool auto_restart = false;
    std::string dump_directory = "crash_dumps";
    std::string log_directory = "crash_logs";
    std::function<void(const CrashInfo&)> crash_callback;
    std::function<bool(const CrashInfo&)> crash_filter;
};

class CrashReporter {
public:
    static CrashReporter& get_instance();
    static void Initialize(const CrashReporterConfig& config = CrashReporterConfig());
    static void Shutdown();

    void report_crash(CrashInfo crash_info);
    void set_config(const CrashReporterConfig& config);
    std::vector<CrashInfo> get_crash_history();
    void clear_crash_history();
    void set_crash_callback(std::function<void(const CrashInfo&)> callback);
    void set_crash_filter(std::function<bool(const CrashInfo&)> filter);
    void generate_report(const std::string& filename);
    void print_crash_history();
    std::string get_exception_string(DWORD exception_code) const;

    static LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* exception_info);
    static LONG WINAPI vectored_exception_handler(EXCEPTION_POINTERS* exception_info);
    static void abort_handler(int signal);
    static void terminate_handler();

private:
    CrashReporter();
    ~CrashReporter();

    void initialize_handlers();
    void shutdown_handlers();
    void set_exception_handler();
    void remove_exception_handler();
    CrashInfo create_crash_info(EXCEPTION_POINTERS* exception_info);
    void generate_crash_dump(CrashInfo& crash_info, CrashDumpType dump_type);
    void save_crash_info(CrashInfo& crash_info);
    void send_crash_report(const CrashInfo& crash_info);
    void restart_application();
    void cleanup_old_files();
    void cleanup_old_dumps();
    void cleanup_old_logs();
    std::string get_stack_trace(CONTEXT* context);
    std::string get_register_dump(CONTEXT* context);
    std::string get_system_info();
    std::string get_process_info();
    std::string get_module_info();
    std::string format_crash_info(const CrashInfo& crash_info);
    std::string generate_dump_filename() const;
    std::string generate_log_filename() const;
    std::string format_timestamp(const std::chrono::system_clock::time_point& timestamp) const;

    static CrashReporter* instance_;
    static std::mutex instance_mutex_;

    CrashReporterConfig config_;
    std::vector<CrashInfo> crash_history_;
    std::mutex crash_mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> handler_installed_{false};
    LPTOP_LEVEL_EXCEPTION_FILTER exception_handler_;
    PVOID vectored_handler_{nullptr};
};

}  // namespace Utils
}  // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
