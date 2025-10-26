#pragma once

#include <memory>
#include <windows.h>
#include "raii_wrappers.h"

namespace UndownUnlock {
namespace Utils {

/**
 * Custom deleters for Windows resources
 */
namespace deleters {

    struct HandleDeleter {
        void operator()(HANDLE handle) const {
            if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
                CloseHandle(handle);
            }
        }
    };

    struct ModuleDeleter {
        void operator()(HMODULE module) const {
            if (module != nullptr) {
                FreeLibrary(module);
            }
        }
    };

    struct DeviceContextDeleter {
        void operator()(HDC dc) const {
            if (dc != nullptr) {
                DeleteDC(dc);
            }
        }
    };

    struct WindowDeviceContextDeleter {
        HWND window;
        
        explicit WindowDeviceContextDeleter(HWND wnd) : window(wnd) {}
        
        void operator()(HDC dc) const {
            if (dc != nullptr && window != nullptr) {
                ReleaseDC(window, dc);
            }
        }
    };

    struct VirtualMemoryDeleter {
        SIZE_T size;
        
        explicit VirtualMemoryDeleter(SIZE_T mem_size) : size(mem_size) {}
        
        void operator()(LPVOID address) const {
            if (address != nullptr && size > 0) {
                VirtualFree(address, 0, MEM_RELEASE);
            }
        }
    };

    struct FileMappingDeleter {
        void operator()(HANDLE mapping) const {
            if (mapping != INVALID_HANDLE_VALUE && mapping != nullptr) {
                CloseHandle(mapping);
            }
        }
    };

    struct FileMappingViewDeleter {
        void operator()(LPVOID view) const {
            if (view != nullptr) {
                UnmapViewOfFile(view);
            }
        }
    };

    struct CriticalSectionDeleter {
        void operator()(CRITICAL_SECTION* cs) const {
            if (cs != nullptr) {
                DeleteCriticalSection(cs);
            }
        }
    };

    struct MutexDeleter {
        void operator()(HANDLE mutex) const {
            if (mutex != INVALID_HANDLE_VALUE && mutex != nullptr) {
                CloseHandle(mutex);
            }
        }
    };

    struct EventDeleter {
        void operator()(HANDLE event) const {
            if (event != INVALID_HANDLE_VALUE && event != nullptr) {
                CloseHandle(event);
            }
        }
    };

    struct SemaphoreDeleter {
        void operator()(HANDLE semaphore) const {
            if (semaphore != INVALID_HANDLE_VALUE && semaphore != nullptr) {
                CloseHandle(semaphore);
            }
        }
    };

    struct ThreadDeleter {
        void operator()(HANDLE thread) const {
            if (thread != INVALID_HANDLE_VALUE && thread != nullptr) {
                CloseHandle(thread);
            }
        }
    };

} // namespace deleters

/**
 * Smart pointer type aliases for Windows resources
 */
using UniqueHandle = std::unique_ptr<void, deleters::HandleDeleter>;
using UniqueModule = std::unique_ptr<void, deleters::ModuleDeleter>;
using UniqueDeviceContext = std::unique_ptr<void, deleters::DeviceContextDeleter>;
using UniqueVirtualMemory = std::unique_ptr<void, deleters::VirtualMemoryDeleter>;
using UniqueFileMapping = std::unique_ptr<void, deleters::FileMappingDeleter>;
using UniqueFileMappingView = std::unique_ptr<void, deleters::FileMappingViewDeleter>;
using UniqueCriticalSection = std::unique_ptr<CRITICAL_SECTION, deleters::CriticalSectionDeleter>;
using UniqueMutex = std::unique_ptr<void, deleters::MutexDeleter>;
using UniqueEvent = std::unique_ptr<void, deleters::EventDeleter>;
using UniqueSemaphore = std::unique_ptr<void, deleters::SemaphoreDeleter>;
using UniqueThread = std::unique_ptr<void, deleters::ThreadDeleter>;

/**
 * Smart pointer type aliases for RAII wrappers
 */
using UniqueHandleWrapper = std::unique_ptr<HandleWrapper>;
using UniqueModuleWrapper = std::unique_ptr<ModuleWrapper>;
using UniqueDeviceContextWrapper = std::unique_ptr<DeviceContextWrapper>;
using UniqueVirtualMemoryWrapper = std::unique_ptr<VirtualMemoryWrapper>;
using UniqueCriticalSectionWrapper = std::unique_ptr<CriticalSectionWrapper>;
using UniqueMutexWrapper = std::unique_ptr<MutexWrapper>;
using UniqueEventWrapper = std::unique_ptr<EventWrapper>;
using UniqueSemaphoreWrapper = std::unique_ptr<SemaphoreWrapper>;
using UniqueThreadWrapper = std::unique_ptr<ThreadWrapper>;
using UniqueFileMappingWrapper = std::unique_ptr<FileMappingWrapper>;
using UniqueFileMappingViewWrapper = std::unique_ptr<FileMappingViewWrapper>;

/**
 * RAII wrapper for temporary resource state changes
 */
template<typename Resource, typename StateChanger, typename StateRestorer>
class ScopedStateChange {
public:
    ScopedStateChange(Resource& resource, StateChanger changer, StateRestorer restorer)
        : resource_(resource), restorer_(restorer), active_(true) {
        changer(resource_);
    }
    
    ~ScopedStateChange() {
        if (active_) {
            restorer_(resource_);
        }
    }
    
    // Move semantics
    ScopedStateChange(ScopedStateChange&& other) noexcept
        : resource_(other.resource_), restorer_(std::move(other.restorer_)), active_(other.active_) {
        other.active_ = false;
    }
    
    ScopedStateChange& operator=(ScopedStateChange&& other) noexcept {
        if (this != &other) {
            if (active_) {
                restorer_(resource_);
            }
            resource_ = other.resource_;
            restorer_ = std::move(other.restorer_);
            active_ = other.active_;
            other.active_ = false;
        }
        return *this;
    }
    
    // Delete copy semantics
    ScopedStateChange(const ScopedStateChange&) = delete;
    ScopedStateChange& operator=(const ScopedStateChange&) = delete;
    
    // Early release
    void release() {
        if (active_) {
            restorer_(resource_);
            active_ = false;
        }
    }
    
    // Check if still active
    bool is_active() const { return active_; }

private:
    Resource& resource_;
    StateRestorer restorer_;
    bool active_;
};

/**
 * Utility functions for creating smart pointers
 */
namespace smart_ptr_utils {

    // Create unique handle from raw handle
    UniqueHandle make_unique_handle(HANDLE handle);
    
    // Create unique module from raw module
    UniqueModule make_unique_module(HMODULE module);
    
    // Create unique device context from raw DC
    UniqueDeviceContext make_unique_device_context(HDC dc);
    
    // Create unique virtual memory from raw memory
    UniqueVirtualMemory make_unique_virtual_memory(LPVOID address, SIZE_T size);
    
    // Create unique file mapping from raw mapping
    UniqueFileMapping make_unique_file_mapping(HANDLE mapping);
    
    // Create unique file mapping view from raw view
    UniqueFileMappingView make_unique_file_mapping_view(LPVOID view);
    
    // Create unique critical section
    UniqueCriticalSection make_unique_critical_section();
    
    // Create unique mutex from raw mutex
    UniqueMutex make_unique_mutex(HANDLE mutex);
    
    // Create unique event from raw event
    UniqueEvent make_unique_event(HANDLE event);
    
    // Create unique semaphore from raw semaphore
    UniqueSemaphore make_unique_semaphore(HANDLE semaphore);
    
    // Create unique thread from raw thread
    UniqueThread make_unique_thread(HANDLE thread);
    
    // Create RAII wrapper smart pointers
    UniqueHandleWrapper make_unique_handle_wrapper(HANDLE handle = INVALID_HANDLE_VALUE);
    UniqueModuleWrapper make_unique_module_wrapper(HMODULE module = nullptr);
    UniqueDeviceContextWrapper make_unique_device_context_wrapper(HDC dc = nullptr);
    UniqueVirtualMemoryWrapper make_unique_virtual_memory_wrapper(LPVOID address = nullptr, SIZE_T size = 0);
    UniqueCriticalSectionWrapper make_unique_critical_section_wrapper();
    UniqueMutexWrapper make_unique_mutex_wrapper(const std::string& name = "", bool initial_owner = false);
    UniqueEventWrapper make_unique_event_wrapper(const std::string& name = "", bool manual_reset = false, bool initial_state = false);
    UniqueSemaphoreWrapper make_unique_semaphore_wrapper(const std::string& name = "", LONG initial_count = 1, LONG maximum_count = 1);
    UniqueThreadWrapper make_unique_thread_wrapper(ThreadWrapper::ThreadFunction func = nullptr, const std::string& name = "");
    UniqueFileMappingWrapper make_unique_file_mapping_wrapper(HANDLE file = INVALID_HANDLE_VALUE, const std::string& name = "");
    UniqueFileMappingViewWrapper make_unique_file_mapping_view_wrapper(HANDLE mapping = INVALID_HANDLE_VALUE, const std::string& name = "");
    
    // Create scoped state changes
    template<typename Resource, typename StateChanger, typename StateRestorer>
    auto make_scoped_state_change(Resource& resource, StateChanger changer, StateRestorer restorer) {
        return ScopedStateChange<Resource, StateChanger, StateRestorer>(resource, changer, restorer);
    }
    
    // Common state change patterns
    template<typename T>
    auto make_scoped_increment(T& counter) {
        return make_scoped_state_change(
            counter,
            [](T& c) { ++c; },
            [](T& c) { --c; }
        );
    }
    
    template<typename T>
    auto make_scoped_decrement(T& counter) {
        return make_scoped_state_change(
            counter,
            [](T& c) { --c; },
            [](T& c) { ++c; }
        );
    }
    
    template<typename T>
    auto make_scoped_negation(T& value) {
        return make_scoped_state_change(
            value,
            [](T& v) { v = !v; },
            [](T& v) { v = !v; }
        );
    }
    
    template<typename T>
    auto make_scoped_value_change(T& value, T new_value) {
        T old_value = value;
        return make_scoped_state_change(
            value,
            [new_value](T& v) { v = new_value; },
            [old_value](T& v) { v = old_value; }
        );
    }

} // namespace smart_ptr_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
