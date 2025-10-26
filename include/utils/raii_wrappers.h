#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <functional>
#include <system_error>

namespace UndownUnlock {
namespace Utils {

// Forward declarations
class ErrorHandler;

/**
 * RAII wrapper for Windows HANDLE
 */
class HandleWrapper {
public:
    explicit HandleWrapper(HANDLE handle = INVALID_HANDLE_VALUE);
    ~HandleWrapper();
    
    // Move semantics
    HandleWrapper(HandleWrapper&& other) noexcept;
    HandleWrapper& operator=(HandleWrapper&& other) noexcept;
    
    // Delete copy semantics
    HandleWrapper(const HandleWrapper&) = delete;
    HandleWrapper& operator=(const HandleWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return handle_; }
    HANDLE release();
    bool is_valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return handle_; }
    
    // Reset functionality
    void reset(HANDLE new_handle = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE handle_;
    ErrorHandler* error_handler_;
    std::string resource_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for HMODULE
 */
class ModuleWrapper {
public:
    explicit ModuleWrapper(HMODULE module = nullptr);
    ~ModuleWrapper();
    
    // Move semantics
    ModuleWrapper(ModuleWrapper&& other) noexcept;
    ModuleWrapper& operator=(ModuleWrapper&& other) noexcept;
    
    // Delete copy semantics
    ModuleWrapper(const ModuleWrapper&) = delete;
    ModuleWrapper& operator=(const ModuleWrapper&) = delete;
    
    // Accessors
    HMODULE get() const { return module_; }
    HMODULE release();
    bool is_valid() const { return module_ != nullptr; }
    
    // Conversion operator
    operator HMODULE() const { return module_; }
    
    // Reset functionality
    void reset(HMODULE new_module = nullptr);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HMODULE module_;
    ErrorHandler* error_handler_;
    std::string module_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for HDC (Device Context)
 */
class DeviceContextWrapper {
public:
    explicit DeviceContextWrapper(HDC dc = nullptr);
    ~DeviceContextWrapper();
    
    // Move semantics
    DeviceContextWrapper(DeviceContextWrapper&& other) noexcept;
    DeviceContextWrapper& operator=(DeviceContextWrapper&& other) noexcept;
    
    // Delete copy semantics
    DeviceContextWrapper(const DeviceContextWrapper&) = delete;
    DeviceContextWrapper& operator=(const DeviceContextWrapper&) = delete;
    
    // Accessors
    HDC get() const { return dc_; }
    HDC release();
    bool is_valid() const { return dc_ != nullptr; }
    
    // Conversion operator
    operator HDC() const { return dc_; }
    
    // Reset functionality
    void reset(HDC new_dc = nullptr);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HDC dc_;
    ErrorHandler* error_handler_;
    std::string context_name_;
    bool is_window_dc_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Virtual Memory
 */
class VirtualMemoryWrapper {
public:
    explicit VirtualMemoryWrapper(LPVOID address = nullptr, SIZE_T size = 0);
    ~VirtualMemoryWrapper();
    
    // Move semantics
    VirtualMemoryWrapper(VirtualMemoryWrapper&& other) noexcept;
    VirtualMemoryWrapper& operator=(VirtualMemoryWrapper&& other) noexcept;
    
    // Delete copy semantics
    VirtualMemoryWrapper(const VirtualMemoryWrapper&) = delete;
    VirtualMemoryWrapper& operator=(const VirtualMemoryWrapper&) = delete;
    
    // Accessors
    LPVOID get() const { return address_; }
    SIZE_T size() const { return size_; }
    LPVOID release();
    bool is_valid() const { return address_ != nullptr && size_ > 0; }
    
    // Conversion operator
    operator LPVOID() const { return address_; }
    
    // Reset functionality
    void reset(LPVOID new_address = nullptr, SIZE_T new_size = 0);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    LPVOID address_;
    SIZE_T size_;
    ErrorHandler* error_handler_;
    std::string memory_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Critical Section
 */
class CriticalSectionWrapper {
public:
    CriticalSectionWrapper();
    ~CriticalSectionWrapper();
    
    // Move semantics
    CriticalSectionWrapper(CriticalSectionWrapper&& other) noexcept;
    CriticalSectionWrapper& operator=(CriticalSectionWrapper&& other) noexcept;
    
    // Delete copy semantics
    CriticalSectionWrapper(const CriticalSectionWrapper&) = delete;
    CriticalSectionWrapper& operator=(const CriticalSectionWrapper&) = delete;
    
    // Accessors
    CRITICAL_SECTION* get() { return &cs_; }
    bool is_valid() const { return initialized_; }
    
    // Lock/Unlock operations
    void enter();
    void leave();
    bool try_enter();
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    CRITICAL_SECTION cs_;
    bool initialized_;
    ErrorHandler* error_handler_;
    std::string section_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Mutex
 */
class MutexWrapper {
public:
    explicit MutexWrapper(const std::string& name = "", bool initial_owner = false);
    ~MutexWrapper();
    
    // Move semantics
    MutexWrapper(MutexWrapper&& other) noexcept;
    MutexWrapper& operator=(MutexWrapper&& other) noexcept;
    
    // Delete copy semantics
    MutexWrapper(const MutexWrapper&) = delete;
    MutexWrapper& operator=(const MutexWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return mutex_; }
    HANDLE release();
    bool is_valid() const { return mutex_ != INVALID_HANDLE_VALUE && mutex_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return mutex_; }
    
    // Lock/Unlock operations
    bool wait(DWORD timeout = INFINITE);
    bool release_mutex();
    
    // Reset functionality
    void reset(HANDLE new_mutex = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE mutex_;
    ErrorHandler* error_handler_;
    std::string mutex_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Event
 */
class EventWrapper {
public:
    explicit EventWrapper(const std::string& name = "", bool manual_reset = false, bool initial_state = false);
    ~EventWrapper();
    
    // Move semantics
    EventWrapper(EventWrapper&& other) noexcept;
    EventWrapper& operator=(EventWrapper&& other) noexcept;
    
    // Delete copy semantics
    EventWrapper(const EventWrapper&) = delete;
    EventWrapper& operator=(const EventWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return event_; }
    HANDLE release();
    bool is_valid() const { return event_ != INVALID_HANDLE_VALUE && event_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return event_; }
    
    // Event operations
    bool wait(DWORD timeout = INFINITE);
    bool set();
    bool reset();
    bool pulse();
    
    // Reset functionality
    void reset(HANDLE new_event = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE event_;
    ErrorHandler* error_handler_;
    std::string event_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Semaphore
 */
class SemaphoreWrapper {
public:
    explicit SemaphoreWrapper(const std::string& name = "", LONG initial_count = 1, LONG maximum_count = 1);
    ~SemaphoreWrapper();
    
    // Move semantics
    SemaphoreWrapper(SemaphoreWrapper&& other) noexcept;
    SemaphoreWrapper& operator=(SemaphoreWrapper&& other) noexcept;
    
    // Delete copy semantics
    SemaphoreWrapper(const SemaphoreWrapper&) = delete;
    SemaphoreWrapper& operator=(const SemaphoreWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return semaphore_; }
    HANDLE release();
    bool is_valid() const { return semaphore_ != INVALID_HANDLE_VALUE && semaphore_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return semaphore_; }
    
    // Semaphore operations
    bool wait(DWORD timeout = INFINITE);
    bool release(LONG release_count = 1);
    
    // Reset functionality
    void reset(HANDLE new_semaphore = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE semaphore_;
    ErrorHandler* error_handler_;
    std::string semaphore_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for Thread
 */
class ThreadWrapper {
public:
    using ThreadFunction = std::function<DWORD()>;
    
    explicit ThreadWrapper(ThreadFunction func = nullptr, const std::string& name = "");
    ~ThreadWrapper();
    
    // Move semantics
    ThreadWrapper(ThreadWrapper&& other) noexcept;
    ThreadWrapper& operator=(ThreadWrapper&& other) noexcept;
    
    // Delete copy semantics
    ThreadWrapper(const ThreadWrapper&) = delete;
    ThreadWrapper& operator=(const ThreadWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return thread_; }
    DWORD get_id() const { return thread_id_; }
    HANDLE release();
    bool is_valid() const { return thread_ != INVALID_HANDLE_VALUE && thread_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return thread_; }
    
    // Thread operations
    bool wait(DWORD timeout = INFINITE);
    bool suspend();
    bool resume();
    bool terminate(DWORD exit_code = 0);
    DWORD get_exit_code() const;
    
    // Reset functionality
    void reset(HANDLE new_thread = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE thread_;
    DWORD thread_id_;
    ThreadFunction thread_func_;
    ErrorHandler* error_handler_;
    std::string thread_name_;
    
    static DWORD WINAPI thread_proc(LPVOID param);
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for File Mapping
 */
class FileMappingWrapper {
public:
    explicit FileMappingWrapper(HANDLE file = INVALID_HANDLE_VALUE, const std::string& name = "");
    ~FileMappingWrapper();
    
    // Move semantics
    FileMappingWrapper(FileMappingWrapper&& other) noexcept;
    FileMappingWrapper& operator=(FileMappingWrapper&& other) noexcept;
    
    // Delete copy semantics
    FileMappingWrapper(const FileMappingWrapper&) = delete;
    FileMappingWrapper& operator=(const FileMappingWrapper&) = delete;
    
    // Accessors
    HANDLE get() const { return mapping_; }
    HANDLE release();
    bool is_valid() const { return mapping_ != INVALID_HANDLE_VALUE && mapping_ != nullptr; }
    
    // Conversion operator
    operator HANDLE() const { return mapping_; }
    
    // Reset functionality
    void reset(HANDLE new_mapping = INVALID_HANDLE_VALUE);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    HANDLE mapping_;
    ErrorHandler* error_handler_;
    std::string mapping_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * RAII wrapper for File Mapping View
 */
class FileMappingViewWrapper {
public:
    explicit FileMappingViewWrapper(HANDLE mapping = INVALID_HANDLE_VALUE, const std::string& name = "");
    ~FileMappingViewWrapper();
    
    // Move semantics
    FileMappingViewWrapper(FileMappingViewWrapper&& other) noexcept;
    FileMappingViewWrapper& operator=(FileMappingViewWrapper&& other) noexcept;
    
    // Delete copy semantics
    FileMappingViewWrapper(const FileMappingViewWrapper&) = delete;
    FileMappingViewWrapper& operator=(const FileMappingViewWrapper&) = delete;
    
    // Accessors
    LPVOID get() const { return view_; }
    LPVOID release();
    bool is_valid() const { return view_ != nullptr; }
    
    // Conversion operator
    operator LPVOID() const { return view_; }
    
    // Reset functionality
    void reset(LPVOID new_view = nullptr);
    
    // Error handling
    void set_error_handler(ErrorHandler* handler) { error_handler_ = handler; }
    std::string get_last_error_message() const;

private:
    LPVOID view_;
    ErrorHandler* error_handler_;
    std::string view_name_;
    
    void log_error(const std::string& operation, DWORD error_code = GetLastError()) const;
};

/**
 * Utility functions for handle operations
 */
namespace handle_utils {
    
    // Safe handle operations with error logging
    bool close_handle_safe(HANDLE handle, const std::string& operation = "CloseHandle");
    bool free_library_safe(HMODULE module, const std::string& operation = "FreeLibrary");
    bool delete_dc_safe(HDC dc, const std::string& operation = "DeleteDC");
    bool release_dc_safe(HWND window, HDC dc, const std::string& operation = "ReleaseDC");
    bool virtual_free_safe(LPVOID address, SIZE_T size, DWORD free_type, const std::string& operation = "VirtualFree");
    bool unmap_view_of_file_safe(LPVOID base_address, const std::string& operation = "UnmapViewOfFile");
    
    // Handle validation
    bool is_valid_handle(HANDLE handle);
    bool is_valid_module(HMODULE module);
    bool is_valid_dc(HDC dc);
    
    // Handle duplication
    HANDLE duplicate_handle_safe(HANDLE source, const std::string& operation = "DuplicateHandle");
    
    // Error message utilities
    std::string get_system_error_message(DWORD error_code);
    std::string get_last_error_message();
    
    // Resource name utilities
    std::string get_resource_name(HANDLE handle);
    std::string get_resource_name(HMODULE module);
    std::string get_resource_name(HDC dc);
    
} // namespace handle_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
