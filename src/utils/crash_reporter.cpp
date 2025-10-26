#include "../../include/utils/crash_reporter.h"
#include "../../include/utils/error_handler.h"
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <exception>
#include <dbghelp.h>

namespace {
std::string FormatMemorySize(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double value = static_cast<double>(bytes);
    while (value >= 1024.0 && unit_index < 4) {
        value /= 1024.0;
        ++unit_index;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(unit_index == 0 ? 0 : 2) << value << " "
        << units[unit_index];
    return oss.str();
}
}  // namespace

namespace UndownUnlock::Utils {

// Static member initialization
CrashReporter* CrashReporter::instance_ = nullptr;
std::mutex CrashReporter::instance_mutex_;

// CrashReporter implementation
CrashReporter::CrashReporter()
    : exception_handler_(nullptr), initialized_(false), handler_installed_(false) {
}

CrashReporter::~CrashReporter() {
    shutdown_handlers();
}

CrashReporter& CrashReporter::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new CrashReporter();
    }
    return *instance_;
}

void CrashReporter::Initialize(const CrashReporterConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new CrashReporter();
    }
    instance_->set_config(config);
    instance_->initialize_handlers();
}

void CrashReporter::Shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        instance_->shutdown_handlers();
        delete instance_;
        instance_ = nullptr;
    }
}

void CrashReporter::initialize_handlers() {
    if (initialized_.load()) {
        return;
    }
    
    initialized_.store(true);
    set_exception_handler();
}

void CrashReporter::shutdown_handlers() {
    if (!initialized_.load()) {
        return;
    }
    
    remove_exception_handler();
    initialized_.store(false);
}

void CrashReporter::set_exception_handler() {
    if (handler_installed_.load()) {
        return;
    }
    
    // Set unhandled exception filter
    exception_handler_ =
        SetUnhandledExceptionFilter(CrashReporter::unhandled_exception_filter);
    
    // Set vectored exception handler
    vectored_handler_ =
        AddVectoredExceptionHandler(1, CrashReporter::vectored_exception_handler);
    
    // Set signal handlers
    signal(SIGABRT, CrashReporter::abort_handler);
    std::set_terminate(CrashReporter::terminate_handler);
    
    handler_installed_.store(true);
}

void CrashReporter::remove_exception_handler() {
    if (!handler_installed_.load()) {
        return;
    }
    
    if (exception_handler_) {
        SetUnhandledExceptionFilter(exception_handler_);
        exception_handler_ = nullptr;
    }
    
    if (vectored_handler_) {
        RemoveVectoredExceptionHandler(vectored_handler_);
        vectored_handler_ = nullptr;
    }
    
    signal(SIGABRT, SIG_DFL);
    std::set_terminate(nullptr);
    
    handler_installed_.store(false);
}

void CrashReporter::report_crash(CrashInfo crash_info) {
    if (!config_.enabled) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(crash_mutex_);
    
    if (config_.crash_filter && !config_.crash_filter(crash_info)) {
        return;
    }
    
    // Generate crash dump if enabled
    if (config_.generate_mini_dumps) {
        generate_crash_dump(crash_info, CrashDumpType::MINI_DUMP);
    }
    
    if (config_.generate_full_dumps) {
        generate_crash_dump(crash_info, CrashDumpType::FULL_DUMP);
    }
    
    // Save crash info
    save_crash_info(crash_info);
    
    crash_history_.push_back(crash_info);
    
    // Send crash report if enabled
    if (config_.send_crash_reports) {
        send_crash_report(crash_info);
    }
    
    // Call crash callback
    if (config_.crash_callback) {
        config_.crash_callback(crash_info);
    }
    
    // Auto restart if enabled
    if (config_.auto_restart) {
        restart_application();
    }
}

void CrashReporter::set_config(const CrashReporterConfig& config) {
    std::lock_guard<std::mutex> lock(crash_mutex_);
    config_ = config;
}

std::vector<CrashInfo> CrashReporter::get_crash_history() {
    std::lock_guard<std::mutex> lock(crash_mutex_);
    return crash_history_;
}

void CrashReporter::clear_crash_history() {
    std::lock_guard<std::mutex> lock(crash_mutex_);
    crash_history_.clear();
}

void CrashReporter::generate_crash_dump(CrashInfo& crash_info, CrashDumpType dump_type) {
    std::string dump_filename = generate_dump_filename();
    
    HANDLE dump_file = CreateFileA(dump_filename.c_str(), GENERIC_WRITE, 0, nullptr, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dump_file == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create crash dump file: " + dump_filename, ErrorCategory::FILE_IO);
        return;
    }
    
    MINIDUMP_TYPE dump_type_flags = MiniDumpNormal;
    switch (dump_type) {
        case CrashDumpType::MINI_DUMP:
            dump_type_flags = MiniDumpNormal;
            break;
        case CrashDumpType::FULL_DUMP:
            dump_type_flags = MiniDumpWithFullMemory;
            break;
        case CrashDumpType::CUSTOM_DUMP:
            dump_type_flags = static_cast<MINIDUMP_TYPE>(
                MiniDumpWithDataSegs | MiniDumpWithCodeSegs);
            break;
    }
    
    MINIDUMP_EXCEPTION_INFORMATION exception_info;
    exception_info.ThreadId = crash_info.thread_id;
    exception_info.ExceptionPointers = nullptr; // Would be set from actual exception
    exception_info.ClientPointers = FALSE;
    
    bool success = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), 
                                    dump_file, dump_type_flags, &exception_info, 
                                    nullptr, nullptr);
    
    CloseHandle(dump_file);
    
    if (!success) {
        LOG_ERROR("Failed to write crash dump", ErrorCategory::FILE_IO);
        LOG_WINDOWS_ERROR("MiniDumpWriteDump failed", ErrorCategory::FILE_IO);
    } else {
        crash_info.dump_file_path = dump_filename;
        LOG_INFO("Crash dump generated: " + dump_filename, ErrorCategory::GENERAL);
    }
}

void CrashReporter::save_crash_info(CrashInfo& crash_info) {
    std::string log_filename = generate_log_filename();
    
    std::ofstream file(log_filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open crash log file: " + log_filename, ErrorCategory::FILE_IO);
        return;
    }
    
    file << format_crash_info(crash_info);
    file.close();
    
    crash_info.log_file_path = log_filename;
    LOG_INFO("Crash info saved: " + log_filename, ErrorCategory::GENERAL);
}

void CrashReporter::send_crash_report(const CrashInfo& crash_info) {
    // This would implement sending crash reports to a server
    // For now, just log that it's not implemented
    LOG_INFO("Crash report sending not implemented in this build", ErrorCategory::NETWORK);
}

void CrashReporter::restart_application() {
    // This would implement application restart logic
    // For now, just log that it's not implemented
    LOG_INFO("Application restart not implemented in this build", ErrorCategory::PROCESS);
}

void CrashReporter::set_crash_callback(std::function<void(const CrashInfo&)> callback) {
    std::lock_guard<std::mutex> lock(crash_mutex_);
    config_.crash_callback = callback;
}

void CrashReporter::set_crash_filter(std::function<bool(const CrashInfo&)> filter) {
    std::lock_guard<std::mutex> lock(crash_mutex_);
    config_.crash_filter = filter;
}

void CrashReporter::generate_report(const std::string& filename) {
    auto history = get_crash_history();
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open crash report file: " + filename, ErrorCategory::FILE_IO);
        return;
    }
    
    file << "=== Crash Report ===\n";
    file << "Generated: " << format_timestamp(std::chrono::system_clock::now()) << "\n\n";
    
    file << "Total Crashes: " << history.size() << "\n\n";
    
    for (size_t i = 0; i < history.size(); ++i) {
        file << "=== Crash " << (i + 1) << " ===\n";
        file << format_crash_info(history[i]) << "\n\n";
    }
    
    file.close();
}

void CrashReporter::print_crash_history() {
    auto history = get_crash_history();
    printf("=== Crash History ===\n");
    printf("Total Crashes: %zu\n\n", history.size());
    
    for (size_t i = 0; i < history.size(); ++i) {
        printf("=== Crash %zu ===\n", i + 1);
        printf("%s\n", format_crash_info(history[i]).c_str());
        printf("\n");
    }
}

void CrashReporter::cleanup_old_files() {
    cleanup_old_dumps();
    cleanup_old_logs();
}

// Static exception handlers
LONG WINAPI CrashReporter::unhandled_exception_filter(EXCEPTION_POINTERS* exception_info) {
    auto& reporter = get_instance();
    CrashInfo crash_info = reporter.create_crash_info(exception_info);
    reporter.report_crash(crash_info);
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI CrashReporter::vectored_exception_handler(EXCEPTION_POINTERS* exception_info) {
    auto& reporter = get_instance();
    CrashInfo crash_info = reporter.create_crash_info(exception_info);
    reporter.report_crash(crash_info);
    return EXCEPTION_CONTINUE_SEARCH;
}

void CrashReporter::abort_handler(int signal) {
    auto& reporter = get_instance();
    CrashInfo crash_info;
    crash_info.crash_type = "SIGABRT";
    crash_info.crash_reason = "Application abort";
    crash_info.exception_code = signal;
    crash_info.crash_time = std::chrono::system_clock::now();
    crash_info.process_id = GetCurrentProcessId();
    crash_info.thread_id = GetCurrentThreadId();
    reporter.report_crash(crash_info);
}

void CrashReporter::terminate_handler() {
    auto& reporter = get_instance();
    CrashInfo crash_info;
    crash_info.crash_type = "Terminate";
    crash_info.crash_reason = "Unhandled exception";
    crash_info.crash_time = std::chrono::system_clock::now();
    crash_info.process_id = GetCurrentProcessId();
    crash_info.thread_id = GetCurrentThreadId();
    reporter.report_crash(crash_info);
}

CrashInfo CrashReporter::create_crash_info(EXCEPTION_POINTERS* exception_info) {
    CrashInfo crash_info;
    
    if (exception_info) {
        crash_info.exception_code = exception_info->ExceptionRecord->ExceptionCode;
        crash_info.exception_address = exception_info->ExceptionRecord->ExceptionAddress;
        crash_info.thread_id = GetCurrentThreadId();
        
        crash_info.exception_info = get_exception_string(crash_info.exception_code);
        
        if (config_.capture_stack_trace) {
            crash_info.stack_trace = get_stack_trace(exception_info->ContextRecord);
        }
        
        if (config_.capture_register_dump) {
            crash_info.register_dump = get_register_dump(exception_info->ContextRecord);
        }
    }
    
    crash_info.crash_type = "Exception";
    crash_info.crash_reason = "Unhandled exception";
    crash_info.crash_time = std::chrono::system_clock::now();
    crash_info.process_id = GetCurrentProcessId();
    
    if (config_.capture_system_info) {
        crash_info.system_info = get_system_info();
    }
    
    if (config_.capture_process_info) {
        crash_info.process_info = get_process_info();
    }
    
    if (config_.capture_module_info) {
        crash_info.module_info = get_module_info();
    }
    
    return crash_info;
}

std::string CrashReporter::get_exception_string(DWORD exception_code) const {
    switch (exception_code) {
        case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP: return "EXCEPTION_SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
        default: return "UNKNOWN_EXCEPTION (" + std::to_string(exception_code) + ")";
    }
}

std::string CrashReporter::get_stack_trace(CONTEXT* context) {
    // Simplified stack trace implementation
    std::ostringstream oss;
    oss << "Stack trace not available in this build";
    return oss.str();
}

std::string CrashReporter::get_register_dump(CONTEXT* context) {
    if (!context) return "No context available";
    
    std::ostringstream oss;
    oss << "Register dump not available in this build";
    return oss.str();
}

std::string CrashReporter::get_system_info() {
    std::ostringstream oss;
    oss << "System info not available in this build";
    return oss.str();
}

std::string CrashReporter::get_process_info() {
    std::ostringstream oss;
    oss << "Process ID: " << GetCurrentProcessId() << "\n";
    oss << "Thread ID: " << GetCurrentThreadId() << "\n";
    return oss.str();
}

std::string CrashReporter::get_module_info() {
    std::ostringstream oss;
    oss << "Module info not available in this build";
    return oss.str();
}

std::string CrashReporter::format_crash_info(const CrashInfo& crash_info) {
    std::ostringstream oss;
    oss << "Crash Type: " << crash_info.crash_type << "\n";
    oss << "Crash Reason: " << crash_info.crash_reason << "\n";
    oss << "Exception Code: " << crash_info.exception_code << "\n";
    oss << "Exception Address: " << crash_info.exception_address << "\n";
    oss << "Process ID: " << crash_info.process_id << "\n";
    oss << "Thread ID: " << crash_info.thread_id << "\n";
    oss << "Crash Time: " << format_timestamp(crash_info.crash_time) << "\n";
    
    if (!crash_info.exception_info.empty()) {
        oss << "Exception Info: " << crash_info.exception_info << "\n";
    }
    
    if (!crash_info.stack_trace.empty()) {
        oss << "Stack Trace:\n" << crash_info.stack_trace << "\n";
    }
    
    if (!crash_info.register_dump.empty()) {
        oss << "Register Dump:\n" << crash_info.register_dump << "\n";
    }
    
    if (!crash_info.system_info.empty()) {
        oss << "System Info:\n" << crash_info.system_info << "\n";
    }
    
    if (!crash_info.process_info.empty()) {
        oss << "Process Info:\n" << crash_info.process_info << "\n";
    }
    
    if (!crash_info.module_info.empty()) {
        oss << "Module Info:\n" << crash_info.module_info << "\n";
    }
    
    return oss.str();
}

void CrashReporter::cleanup_old_dumps() {
    // Implementation for cleaning up old dump files
    LOG_INFO("Old dump cleanup not implemented in this build", ErrorCategory::FILE_IO);
}

void CrashReporter::cleanup_old_logs() {
    // Implementation for cleaning up old log files
    LOG_INFO("Old log cleanup not implemented in this build", ErrorCategory::FILE_IO);
}

std::string CrashReporter::generate_dump_filename() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << "crash_dump_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
    oss << "_" << std::setfill('0') << std::setw(3) << ms.count() << ".dmp";
    
    if (!config_.dump_directory.empty()) {
        return config_.dump_directory + "/" + oss.str();
    }
    
    return oss.str();
}

std::string CrashReporter::generate_log_filename() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << "crash_log_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
    oss << "_" << std::setfill('0') << std::setw(3) << ms.count() << ".txt";
    
    if (!config_.log_directory.empty()) {
        return config_.log_directory + "/" + oss.str();
    }
    
    return oss.str();
}

std::string CrashReporter::format_timestamp(
    const std::chrono::system_clock::time_point& timestamp) const {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// CrashUtils implementation
namespace CrashUtils {
    std::string get_exception_code_string(DWORD exception_code) {
        return CrashReporter::get_instance().get_exception_string(exception_code);
    }
    
    std::string get_exception_address_string(PVOID address) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(16) << std::setfill('0') 
            << reinterpret_cast<uintptr_t>(address);
        return oss.str();
    }
    
    std::string get_process_name(DWORD process_id) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (process == nullptr) {
            return "Unknown";
        }
        
        char process_name[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(process, 0, process_name, &size)) {
            CloseHandle(process);
            return std::string(process_name);
        }
        
        CloseHandle(process);
        return "Unknown";
    }
    
    std::string get_thread_name(DWORD thread_id) {
        // Thread names are not easily retrievable in Windows
        return "Thread-" + std::to_string(thread_id);
    }
    
    std::string get_module_name(PVOID address) {
        HMODULE module = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCSTR>(address), &module)) {
            char module_name[MAX_PATH];
            if (GetModuleFileNameA(module, module_name, MAX_PATH)) {
                return std::string(module_name);
            }
        }
        return "Unknown";
    }
    
    std::string get_function_name(PVOID address) {
        // Function name resolution requires debug symbols
        return "Unknown";
    }
    
    std::string get_system_version() {
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        if (GetVersionExA(&osvi)) {
            std::ostringstream oss;
            oss << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
            oss << " (Build " << osvi.dwBuildNumber << ")";
            return oss.str();
        }
        
        return "Unknown";
    }
    
    std::string get_processor_info() {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        
        std::ostringstream oss;
        oss << "Processors: " << sys_info.dwNumberOfProcessors;
        oss << ", Architecture: " << sys_info.wProcessorArchitecture;
        return oss.str();
    }
    
    std::string get_memory_info() {
        MEMORYSTATUSEX mem_info;
        mem_info.dwLength = sizeof(MEMORYSTATUSEX);
        
        if (GlobalMemoryStatusEx(&mem_info)) {
            std::ostringstream oss;
            oss << "Total: " << FormatMemorySize(mem_info.ullTotalPhys);
            oss << ", Available: " << FormatMemorySize(mem_info.ullAvailPhys);
            oss << ", Load: " << mem_info.dwMemoryLoad << "%";
            return oss.str();
        }
        
        return "Unknown";
    }
    
    std::string get_disk_info() {
        return "Disk info not available in this build";
    }
    
    std::string get_network_info() {
        return "Network info not available in this build";
    }
    
    bool is_debugger_present() {
        return IsDebuggerPresent() != 0;
    }
    
    bool is_64bit_process() {
        return sizeof(void*) == 8;
    }
    
    bool is_elevated_process() {
        BOOL is_elevated = FALSE;
        HANDLE token = nullptr;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
                is_elevated = elevation.TokenIsElevated;
            }
            CloseHandle(token);
        }
        
        return is_elevated != 0;
    }
    
    std::vector<std::string> get_loaded_modules() {
        std::vector<std::string> modules;
        // Implementation would enumerate loaded modules
        return modules;
    }
    
    std::vector<std::string> get_system_drivers() {
        std::vector<std::string> drivers;
        // Implementation would enumerate system drivers
        return drivers;
    }
    
    std::string get_environment_info() {
        return "Environment info not available in this build";
    }
    
    std::string get_user_info() {
        char username[256];
        DWORD size = 256;
        if (GetUserNameA(username, &size)) {
            return std::string(username);
        }
        return "Unknown";
    }
    
    std::string get_security_info() {
        return "Security info not available in this build";
    }
    
    std::string get_performance_info() {
        return "Performance info not available in this build";
    }
}

} // namespace UndownUnlock::Utils 
