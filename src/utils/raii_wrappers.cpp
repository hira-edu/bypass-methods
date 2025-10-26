#include "utils/raii_wrappers.h"
#include "utils/error_handler.h"
#include <sstream>
#include <iomanip>

namespace UndownUnlock::Utils {

// Forward declaration
extern ErrorHandler* g_error_handler;

// HandleWrapper implementation
HandleWrapper::HandleWrapper(HANDLE handle)
    : handle_(handle), error_handler_(nullptr), resource_name_("Handle") {
}

HandleWrapper::~HandleWrapper() {
    reset();
}

HandleWrapper::HandleWrapper(HandleWrapper&& other) noexcept
    : handle_(other.handle_), error_handler_(other.error_handler_), 
      resource_name_(std::move(other.resource_name_)) {
    other.handle_ = INVALID_HANDLE_VALUE;
    other.error_handler_ = nullptr;
}

HandleWrapper& HandleWrapper::operator=(HandleWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        handle_ = other.handle_;
        error_handler_ = other.error_handler_;
        resource_name_ = std::move(other.resource_name_);
        other.handle_ = INVALID_HANDLE_VALUE;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE HandleWrapper::release() {
    HANDLE temp = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return temp;
}

void HandleWrapper::reset(HANDLE new_handle) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(handle_, "HandleWrapper::reset")) {
            log_error("Failed to close handle in reset");
        }
    }
    handle_ = new_handle;
}

std::string HandleWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void HandleWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + resource_name_,
            ErrorCategory::WINDOWS_API,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// ModuleWrapper implementation
ModuleWrapper::ModuleWrapper(HMODULE module)
    : module_(module), error_handler_(nullptr), module_name_("Module") {
}

ModuleWrapper::~ModuleWrapper() {
    reset();
}

ModuleWrapper::ModuleWrapper(ModuleWrapper&& other) noexcept
    : module_(other.module_), error_handler_(other.error_handler_),
      module_name_(std::move(other.module_name_)) {
    other.module_ = nullptr;
    other.error_handler_ = nullptr;
}

ModuleWrapper& ModuleWrapper::operator=(ModuleWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        module_ = other.module_;
        error_handler_ = other.error_handler_;
        module_name_ = std::move(other.module_name_);
        other.module_ = nullptr;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HMODULE ModuleWrapper::release() {
    HMODULE temp = module_;
    module_ = nullptr;
    return temp;
}

void ModuleWrapper::reset(HMODULE new_module) {
    if (is_valid()) {
        if (!handle_utils::free_library_safe(module_, "ModuleWrapper::reset")) {
            log_error("Failed to free library in reset");
        }
    }
    module_ = new_module;
}

std::string ModuleWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void ModuleWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + module_name_,
            ErrorCategory::WINDOWS_API,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// DeviceContextWrapper implementation
DeviceContextWrapper::DeviceContextWrapper(HDC dc)
    : dc_(dc), error_handler_(nullptr), context_name_("DeviceContext"), is_window_dc_(false) {
}

DeviceContextWrapper::~DeviceContextWrapper() {
    reset();
}

DeviceContextWrapper::DeviceContextWrapper(DeviceContextWrapper&& other) noexcept
    : dc_(other.dc_), error_handler_(other.error_handler_),
      context_name_(std::move(other.context_name_)), is_window_dc_(other.is_window_dc_) {
    other.dc_ = nullptr;
    other.error_handler_ = nullptr;
    other.is_window_dc_ = false;
}

DeviceContextWrapper& DeviceContextWrapper::operator=(DeviceContextWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        dc_ = other.dc_;
        error_handler_ = other.error_handler_;
        context_name_ = std::move(other.context_name_);
        is_window_dc_ = other.is_window_dc_;
        other.dc_ = nullptr;
        other.error_handler_ = nullptr;
        other.is_window_dc_ = false;
    }
    return *this;
}

HDC DeviceContextWrapper::release() {
    HDC temp = dc_;
    dc_ = nullptr;
    return temp;
}

void DeviceContextWrapper::reset(HDC new_dc) {
    if (is_valid()) {
        if (is_window_dc_) {
            // For window DCs, we need the window handle to release properly
            // This is a simplified implementation
            if (!handle_utils::delete_dc_safe(dc_, "DeviceContextWrapper::reset")) {
                log_error("Failed to delete DC in reset");
            }
        } else {
            if (!handle_utils::delete_dc_safe(dc_, "DeviceContextWrapper::reset")) {
                log_error("Failed to delete DC in reset");
            }
        }
    }
    dc_ = new_dc;
    is_window_dc_ = false;
}

std::string DeviceContextWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void DeviceContextWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + context_name_,
            ErrorCategory::GRAPHICS,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// VirtualMemoryWrapper implementation
VirtualMemoryWrapper::VirtualMemoryWrapper(LPVOID address, SIZE_T size)
    : address_(address), size_(size), error_handler_(nullptr), memory_name_("VirtualMemory") {
}

VirtualMemoryWrapper::~VirtualMemoryWrapper() {
    reset();
}

VirtualMemoryWrapper::VirtualMemoryWrapper(VirtualMemoryWrapper&& other) noexcept
    : address_(other.address_), size_(other.size_), error_handler_(other.error_handler_),
      memory_name_(std::move(other.memory_name_)) {
    other.address_ = nullptr;
    other.size_ = 0;
    other.error_handler_ = nullptr;
}

VirtualMemoryWrapper& VirtualMemoryWrapper::operator=(VirtualMemoryWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        address_ = other.address_;
        size_ = other.size_;
        error_handler_ = other.error_handler_;
        memory_name_ = std::move(other.memory_name_);
        other.address_ = nullptr;
        other.size_ = 0;
        other.error_handler_ = nullptr;
    }
    return *this;
}

LPVOID VirtualMemoryWrapper::release() {
    LPVOID temp = address_;
    address_ = nullptr;
    size_ = 0;
    return temp;
}

void VirtualMemoryWrapper::reset(LPVOID new_address, SIZE_T new_size) {
    if (is_valid()) {
        if (!handle_utils::virtual_free_safe(address_, size_, MEM_RELEASE, "VirtualMemoryWrapper::reset")) {
            log_error("Failed to free virtual memory in reset");
        }
    }
    address_ = new_address;
    size_ = new_size;
}

std::string VirtualMemoryWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void VirtualMemoryWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + memory_name_,
            ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// CriticalSectionWrapper implementation
CriticalSectionWrapper::CriticalSectionWrapper()
    : error_handler_(nullptr), section_name_("CriticalSection"), initialized_(false) {
    try {
        InitializeCriticalSection(&cs_);
        initialized_ = true;
    } catch (...) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to initialize critical section",
                ErrorCategory::SYNCHRONIZATION,
                __FUNCTION__, __FILE__, __LINE__
            );
        }
    }
}

CriticalSectionWrapper::~CriticalSectionWrapper() {
    if (initialized_) {
        try {
            DeleteCriticalSection(&cs_);
        } catch (...) {
            // Destructor should not throw
        }
    }
}

CriticalSectionWrapper::CriticalSectionWrapper(CriticalSectionWrapper&& other) noexcept
    : cs_(other.cs_), error_handler_(other.error_handler_),
      section_name_(std::move(other.section_name_)), initialized_(other.initialized_) {
    other.initialized_ = false;
    other.error_handler_ = nullptr;
}

CriticalSectionWrapper& CriticalSectionWrapper::operator=(CriticalSectionWrapper&& other) noexcept {
    if (this != &other) {
        if (initialized_) {
            try {
                DeleteCriticalSection(&cs_);
            } catch (...) {
                // Assignment operator should not throw
            }
        }
        cs_ = other.cs_;
        error_handler_ = other.error_handler_;
        section_name_ = std::move(other.section_name_);
        initialized_ = other.initialized_;
        other.initialized_ = false;
        other.error_handler_ = nullptr;
    }
    return *this;
}

void CriticalSectionWrapper::enter() {
    if (initialized_) {
        EnterCriticalSection(&cs_);
    }
}

void CriticalSectionWrapper::leave() {
    if (initialized_) {
        LeaveCriticalSection(&cs_);
    }
}

bool CriticalSectionWrapper::try_enter() {
    if (initialized_) {
        return TryEnterCriticalSection(&cs_) != 0;
    }
    return false;
}

std::string CriticalSectionWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void CriticalSectionWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + section_name_,
            ErrorCategory::SYNCHRONIZATION,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// MutexWrapper implementation
MutexWrapper::MutexWrapper(const std::string& name, bool initial_owner)
    : error_handler_(nullptr), mutex_name_(name.empty() ? "Mutex" : name) {
    mutex_ = CreateMutexA(nullptr, initial_owner, name.empty() ? nullptr : name.c_str());
    if (!is_valid()) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to create mutex: " + mutex_name_,
                ErrorCategory::SYNCHRONIZATION,
                __FUNCTION__, __FILE__, __LINE__,
                GetLastError()
            );
        }
    }
}

MutexWrapper::~MutexWrapper() {
    reset();
}

MutexWrapper::MutexWrapper(MutexWrapper&& other) noexcept
    : mutex_(other.mutex_), error_handler_(other.error_handler_),
      mutex_name_(std::move(other.mutex_name_)) {
    other.mutex_ = INVALID_HANDLE_VALUE;
    other.error_handler_ = nullptr;
}

MutexWrapper& MutexWrapper::operator=(MutexWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        mutex_ = other.mutex_;
        error_handler_ = other.error_handler_;
        mutex_name_ = std::move(other.mutex_name_);
        other.mutex_ = INVALID_HANDLE_VALUE;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE MutexWrapper::release() {
    HANDLE temp = mutex_;
    mutex_ = INVALID_HANDLE_VALUE;
    return temp;
}

bool MutexWrapper::wait(DWORD timeout) {
    if (is_valid()) {
        DWORD result = WaitForSingleObject(mutex_, timeout);
        if (result == WAIT_OBJECT_0) {
            return true;
        } else if (result == WAIT_TIMEOUT) {
            return false;
        } else {
            log_error("WaitForSingleObject failed");
            return false;
        }
    }
    return false;
}

bool MutexWrapper::release_mutex() {
    if (is_valid()) {
        return ReleaseMutex(mutex_) != 0;
    }
    return false;
}

void MutexWrapper::reset(HANDLE new_mutex) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(mutex_, "MutexWrapper::reset")) {
            log_error("Failed to close mutex in reset");
        }
    }
    mutex_ = new_mutex;
}

std::string MutexWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void MutexWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + mutex_name_,
            ErrorCategory::SYNCHRONIZATION,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// EventWrapper implementation
EventWrapper::EventWrapper(const std::string& name, bool manual_reset, bool initial_state)
    : error_handler_(nullptr), event_name_(name.empty() ? "Event" : name) {
    event_ = CreateEventA(nullptr, manual_reset, initial_state, name.empty() ? nullptr : name.c_str());
    if (!is_valid()) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to create event: " + event_name_,
                ErrorCategory::SYNCHRONIZATION,
                __FUNCTION__, __FILE__, __LINE__,
                GetLastError()
            );
        }
    }
}

EventWrapper::~EventWrapper() {
    reset(INVALID_HANDLE_VALUE);
}

EventWrapper::EventWrapper(EventWrapper&& other) noexcept
    : event_(other.event_), error_handler_(other.error_handler_),
      event_name_(std::move(other.event_name_)) {
    other.event_ = INVALID_HANDLE_VALUE;
    other.error_handler_ = nullptr;
}

EventWrapper& EventWrapper::operator=(EventWrapper&& other) noexcept {
    if (this != &other) {
        reset(INVALID_HANDLE_VALUE);
        event_ = other.event_;
        error_handler_ = other.error_handler_;
        event_name_ = std::move(other.event_name_);
        other.event_ = INVALID_HANDLE_VALUE;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE EventWrapper::release() {
    HANDLE temp = event_;
    event_ = INVALID_HANDLE_VALUE;
    return temp;
}

bool EventWrapper::wait(DWORD timeout) {
    if (is_valid()) {
        DWORD result = WaitForSingleObject(event_, timeout);
        return result == WAIT_OBJECT_0;
    }
    return false;
}

bool EventWrapper::set() {
    if (is_valid()) {
        return SetEvent(event_) != 0;
    }
    return false;
}

bool EventWrapper::reset() {
    if (is_valid()) {
        return ResetEvent(event_) != 0;
    }
    return false;
}

bool EventWrapper::pulse() {
    if (is_valid()) {
        return PulseEvent(event_) != 0;
    }
    return false;
}

void EventWrapper::reset(HANDLE new_event) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(event_, "EventWrapper::reset")) {
            log_error("Failed to close event in reset");
        }
    }
    event_ = new_event;
}

std::string EventWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void EventWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + event_name_,
            ErrorCategory::SYNCHRONIZATION,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// SemaphoreWrapper implementation
SemaphoreWrapper::SemaphoreWrapper(const std::string& name, LONG initial_count, LONG maximum_count)
    : error_handler_(nullptr), semaphore_name_(name.empty() ? "Semaphore" : name) {
    semaphore_ = CreateSemaphoreA(nullptr, initial_count, maximum_count, name.empty() ? nullptr : name.c_str());
    if (!is_valid()) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to create semaphore: " + semaphore_name_,
                ErrorCategory::SYNCHRONIZATION,
                __FUNCTION__, __FILE__, __LINE__,
                GetLastError()
            );
        }
    }
}

SemaphoreWrapper::~SemaphoreWrapper() {
    reset();
}

SemaphoreWrapper::SemaphoreWrapper(SemaphoreWrapper&& other) noexcept
    : semaphore_(other.semaphore_), error_handler_(other.error_handler_),
      semaphore_name_(std::move(other.semaphore_name_)) {
    other.semaphore_ = INVALID_HANDLE_VALUE;
    other.error_handler_ = nullptr;
}

SemaphoreWrapper& SemaphoreWrapper::operator=(SemaphoreWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        semaphore_ = other.semaphore_;
        error_handler_ = other.error_handler_;
        semaphore_name_ = std::move(other.semaphore_name_);
        other.semaphore_ = INVALID_HANDLE_VALUE;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE SemaphoreWrapper::release() {
    HANDLE temp = semaphore_;
    semaphore_ = INVALID_HANDLE_VALUE;
    return temp;
}

bool SemaphoreWrapper::wait(DWORD timeout) {
    if (is_valid()) {
        DWORD result = WaitForSingleObject(semaphore_, timeout);
        return result == WAIT_OBJECT_0;
    }
    return false;
}

bool SemaphoreWrapper::release(LONG release_count) {
    if (is_valid()) {
        return ReleaseSemaphore(semaphore_, release_count, nullptr) != 0;
    }
    return false;
}

void SemaphoreWrapper::reset(HANDLE new_semaphore) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(semaphore_, "SemaphoreWrapper::reset")) {
            log_error("Failed to close semaphore in reset");
        }
    }
    semaphore_ = new_semaphore;
}

std::string SemaphoreWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void SemaphoreWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + semaphore_name_,
            ErrorCategory::SYNCHRONIZATION,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// ThreadWrapper implementation
ThreadWrapper::ThreadWrapper(ThreadFunction func, const std::string& name)
    : thread_(INVALID_HANDLE_VALUE), thread_id_(0), thread_func_(std::move(func)),
      error_handler_(nullptr), thread_name_(name.empty() ? "Thread" : name) {
    if (thread_func_) {
        thread_ = CreateThread(nullptr, 0, thread_proc, this, 0, &thread_id_);
        if (!is_valid()) {
            if (error_handler_) {
                error_handler_->error(
                    "Failed to create thread: " + thread_name_,
                    ErrorCategory::THREADING,
                    __FUNCTION__, __FILE__, __LINE__,
                    GetLastError()
                );
            }
        }
    }
}

ThreadWrapper::~ThreadWrapper() {
    reset();
}

ThreadWrapper::ThreadWrapper(ThreadWrapper&& other) noexcept
    : thread_(other.thread_), thread_id_(other.thread_id_), thread_func_(std::move(other.thread_func_)),
      error_handler_(other.error_handler_), thread_name_(std::move(other.thread_name_)) {
    other.thread_ = INVALID_HANDLE_VALUE;
    other.thread_id_ = 0;
    other.error_handler_ = nullptr;
}

ThreadWrapper& ThreadWrapper::operator=(ThreadWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        thread_ = other.thread_;
        thread_id_ = other.thread_id_;
        thread_func_ = std::move(other.thread_func_);
        error_handler_ = other.error_handler_;
        thread_name_ = std::move(other.thread_name_);
        other.thread_ = INVALID_HANDLE_VALUE;
        other.thread_id_ = 0;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE ThreadWrapper::release() {
    HANDLE temp = thread_;
    thread_ = INVALID_HANDLE_VALUE;
    thread_id_ = 0;
    return temp;
}

bool ThreadWrapper::wait(DWORD timeout) {
    if (is_valid()) {
        DWORD result = WaitForSingleObject(thread_, timeout);
        return result == WAIT_OBJECT_0;
    }
    return false;
}

bool ThreadWrapper::suspend() {
    if (is_valid()) {
        DWORD result = SuspendThread(thread_);
        return result != (DWORD)-1;
    }
    return false;
}

bool ThreadWrapper::resume() {
    if (is_valid()) {
        DWORD result = ResumeThread(thread_);
        return result != (DWORD)-1;
    }
    return false;
}

bool ThreadWrapper::terminate(DWORD exit_code) {
    if (is_valid()) {
        return TerminateThread(thread_, exit_code) != 0;
    }
    return false;
}

DWORD ThreadWrapper::get_exit_code() const {
    if (is_valid()) {
        DWORD exit_code = 0;
        if (GetExitCodeThread(thread_, &exit_code)) {
            return exit_code;
        }
    }
    return 0;
}

void ThreadWrapper::reset(HANDLE new_thread) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(thread_, "ThreadWrapper::reset")) {
            log_error("Failed to close thread in reset");
        }
    }
    thread_ = new_thread;
    thread_id_ = 0;
}

std::string ThreadWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void ThreadWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + thread_name_,
            ErrorCategory::THREADING,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

DWORD WINAPI ThreadWrapper::thread_proc(LPVOID param) {
    ThreadWrapper* wrapper = static_cast<ThreadWrapper*>(param);
    if (wrapper && wrapper->thread_func_) {
        try {
            return wrapper->thread_func_();
        } catch (...) {
            if (wrapper->error_handler_) {
                wrapper->error_handler_->error(
                    "Unhandled exception in thread: " + wrapper->thread_name_,
                    ErrorCategory::THREADING,
                    __FUNCTION__, __FILE__, __LINE__
                );
            }
        }
    }
    return 1;
}

// FileMappingWrapper implementation
FileMappingWrapper::FileMappingWrapper(HANDLE file, const std::string& name)
    : error_handler_(nullptr), mapping_name_(name.empty() ? "FileMapping" : name) {
    mapping_ = CreateFileMappingA(file, nullptr, PAGE_READWRITE, 0, 0, name.empty() ? nullptr : name.c_str());
    if (!is_valid()) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to create file mapping: " + mapping_name_,
                ErrorCategory::FILE_IO,
                __FUNCTION__, __FILE__, __LINE__,
                GetLastError()
            );
        }
    }
}

FileMappingWrapper::~FileMappingWrapper() {
    reset();
}

FileMappingWrapper::FileMappingWrapper(FileMappingWrapper&& other) noexcept
    : mapping_(other.mapping_), error_handler_(other.error_handler_),
      mapping_name_(std::move(other.mapping_name_)) {
    other.mapping_ = INVALID_HANDLE_VALUE;
    other.error_handler_ = nullptr;
}

FileMappingWrapper& FileMappingWrapper::operator=(FileMappingWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        mapping_ = other.mapping_;
        error_handler_ = other.error_handler_;
        mapping_name_ = std::move(other.mapping_name_);
        other.mapping_ = INVALID_HANDLE_VALUE;
        other.error_handler_ = nullptr;
    }
    return *this;
}

HANDLE FileMappingWrapper::release() {
    HANDLE temp = mapping_;
    mapping_ = INVALID_HANDLE_VALUE;
    return temp;
}

void FileMappingWrapper::reset(HANDLE new_mapping) {
    if (is_valid()) {
        if (!handle_utils::close_handle_safe(mapping_, "FileMappingWrapper::reset")) {
            log_error("Failed to close file mapping in reset");
        }
    }
    mapping_ = new_mapping;
}

std::string FileMappingWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void FileMappingWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + mapping_name_,
            ErrorCategory::FILE_IO,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// FileMappingViewWrapper implementation
FileMappingViewWrapper::FileMappingViewWrapper(HANDLE mapping, const std::string& name)
    : error_handler_(nullptr), view_name_(name.empty() ? "FileMappingView" : name) {
    view_ = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!is_valid()) {
        if (error_handler_) {
            error_handler_->error(
                "Failed to map view of file: " + view_name_,
                ErrorCategory::FILE_IO,
                __FUNCTION__, __FILE__, __LINE__,
                GetLastError()
            );
        }
    }
}

FileMappingViewWrapper::~FileMappingViewWrapper() {
    reset();
}

FileMappingViewWrapper::FileMappingViewWrapper(FileMappingViewWrapper&& other) noexcept
    : view_(other.view_), error_handler_(other.error_handler_),
      view_name_(std::move(other.view_name_)) {
    other.view_ = nullptr;
    other.error_handler_ = nullptr;
}

FileMappingViewWrapper& FileMappingViewWrapper::operator=(FileMappingViewWrapper&& other) noexcept {
    if (this != &other) {
        reset();
        view_ = other.view_;
        error_handler_ = other.error_handler_;
        view_name_ = std::move(other.view_name_);
        other.view_ = nullptr;
        other.error_handler_ = nullptr;
    }
    return *this;
}

LPVOID FileMappingViewWrapper::release() {
    LPVOID temp = view_;
    view_ = nullptr;
    return temp;
}

void FileMappingViewWrapper::reset(LPVOID new_view) {
    if (is_valid()) {
        if (!handle_utils::unmap_view_of_file_safe(view_, "FileMappingViewWrapper::reset")) {
            log_error("Failed to unmap view of file in reset");
        }
    }
    view_ = new_view;
}

std::string FileMappingViewWrapper::get_last_error_message() const {
    return handle_utils::get_last_error_message();
}

void FileMappingViewWrapper::log_error(const std::string& operation, DWORD error_code) const {
    if (error_handler_) {
        error_handler_->error(
            operation + " failed for " + view_name_,
            ErrorCategory::FILE_IO,
            __FUNCTION__, __FILE__, __LINE__,
            error_code
        );
    }
}

// Handle utilities implementation
namespace handle_utils {

bool close_handle_safe(HANDLE handle, const std::string& operation) {
    if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
        if (!CloseHandle(handle)) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool free_library_safe(HMODULE module, const std::string& operation) {
    if (module != nullptr) {
        if (!FreeLibrary(module)) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool delete_dc_safe(HDC dc, const std::string& operation) {
    if (dc != nullptr) {
        if (!DeleteDC(dc)) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool release_dc_safe(HWND window, HDC dc, const std::string& operation) {
    if (dc != nullptr && window != nullptr) {
        if (ReleaseDC(window, dc) == 0) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool virtual_free_safe(LPVOID address, SIZE_T size, DWORD free_type, const std::string& operation) {
    if (address != nullptr && size > 0) {
        if (!VirtualFree(address, 0, free_type)) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool unmap_view_of_file_safe(LPVOID base_address, const std::string& operation) {
    if (base_address != nullptr) {
        if (!UnmapViewOfFile(base_address)) {
            DWORD error = GetLastError();
            // Log error if error handler is available
            return false;
        }
    }
    return true;
}

bool is_valid_handle(HANDLE handle) {
    return handle != INVALID_HANDLE_VALUE && handle != nullptr;
}

bool is_valid_module(HMODULE module) {
    return module != nullptr;
}

bool is_valid_dc(HDC dc) {
    return dc != nullptr;
}

HANDLE duplicate_handle_safe(HANDLE source, const std::string& operation) {
    if (!is_valid_handle(source)) {
        return INVALID_HANDLE_VALUE;
    }
    
    HANDLE duplicate = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        DWORD error = GetLastError();
        // Log error if error handler is available
        return INVALID_HANDLE_VALUE;
    }
    
    return duplicate;
}

std::string get_system_error_message(DWORD error_code) {
    if (error_code == 0) {
        return "No error";
    }
    
    LPSTR message_buffer = nullptr;
    DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&message_buffer),
        0,
        nullptr
    );
    
    if (length == 0 || message_buffer == nullptr) {
        return "Unknown error code: " + std::to_string(error_code);
    }
    
    std::string message(message_buffer);
    LocalFree(message_buffer);
    
    // Remove trailing newlines and spaces
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r' || message.back() == ' ')) {
        message.pop_back();
    }
    
    return message;
}

std::string get_last_error_message() {
    return get_system_error_message(GetLastError());
}

std::string get_resource_name(HANDLE handle) {
    // This is a simplified implementation
    // In a real implementation, you might query the handle type and get more specific information
    return "Handle(" + std::to_string(reinterpret_cast<uintptr_t>(handle)) + ")";
}

std::string get_resource_name(HMODULE module) {
    // This is a simplified implementation
    // In a real implementation, you might get the module name
    return "Module(" + std::to_string(reinterpret_cast<uintptr_t>(module)) + ")";
}

std::string get_resource_name(HDC dc) {
    // This is a simplified implementation
    // In a real implementation, you might get the DC type and associated window
    return "DC(" + std::to_string(reinterpret_cast<uintptr_t>(dc)) + ")";
}

} // namespace handle_utils

} // namespace UndownUnlock::Utils
