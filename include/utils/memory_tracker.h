#pragma once

#include <windows.h>
#include <string>
#include <cstdint>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace UndownUnlock {
namespace Utils {

// Forward declarations
class ErrorHandler;

enum class MemoryCategory {
    GENERAL = 0,
    SYSTEM,
    GRAPHICS,
    AUDIO,
    NETWORK,
    STORAGE,
    CACHE,
    TEMPORARY,
    OTHER
};

using AllocationHandle = uint64_t;

/**
 * Memory allocation information
 */
struct AllocationInfo {
    void* address;
    size_t size;
    std::string file;
    int line;
    std::string function;
    std::string stack_trace;
    std::chrono::system_clock::time_point allocation_time;
    std::string thread_id;
    std::string allocation_type; // "new", "malloc", "VirtualAlloc", etc.
    bool is_array;
    size_t array_size;
    
    AllocationInfo() : address(nullptr), size(0), line(0), is_array(false), array_size(0) {}
};

/**
 * Memory statistics
 */
struct MemoryStats {
    std::atomic<size_t> total_allocations;
    std::atomic<size_t> total_deallocations;
    std::atomic<size_t> current_allocations;
    std::atomic<size_t> total_bytes_allocated;
    std::atomic<size_t> total_bytes_deallocated;
    std::atomic<size_t> current_bytes_allocated;
    std::atomic<size_t> peak_bytes_allocated;
    std::atomic<size_t> peak_allocations;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_allocation_time;
    std::chrono::system_clock::time_point last_deallocation_time;

    MemoryStats()
        : total_allocations(0),
          total_deallocations(0),
          current_allocations(0),
          total_bytes_allocated(0),
          total_bytes_deallocated(0),
          current_bytes_allocated(0),
          peak_bytes_allocated(0),
          peak_allocations(0) {}

    MemoryStats(const MemoryStats& other)
        : total_allocations(other.total_allocations.load()),
          total_deallocations(other.total_deallocations.load()),
          current_allocations(other.current_allocations.load()),
          total_bytes_allocated(other.total_bytes_allocated.load()),
          total_bytes_deallocated(other.total_bytes_deallocated.load()),
          current_bytes_allocated(other.current_bytes_allocated.load()),
          peak_bytes_allocated(other.peak_bytes_allocated.load()),
          peak_allocations(other.peak_allocations.load()),
          start_time(other.start_time),
          last_allocation_time(other.last_allocation_time),
          last_deallocation_time(other.last_deallocation_time) {}

    MemoryStats& operator=(const MemoryStats& other) {
        if (this != &other) {
            total_allocations.store(other.total_allocations.load());
            total_deallocations.store(other.total_deallocations.load());
            current_allocations.store(other.current_allocations.load());
            total_bytes_allocated.store(other.total_bytes_allocated.load());
            total_bytes_deallocated.store(other.total_bytes_deallocated.load());
            current_bytes_allocated.store(other.current_bytes_allocated.load());
            peak_bytes_allocated.store(other.peak_bytes_allocated.load());
            peak_allocations.store(other.peak_allocations.load());
            start_time = other.start_time;
            last_allocation_time = other.last_allocation_time;
            last_deallocation_time = other.last_deallocation_time;
        }
        return *this;
    }

    MemoryStats(MemoryStats&& other) noexcept
        : MemoryStats(other) {}

    MemoryStats& operator=(MemoryStats&& other) noexcept {
        return *this = other;
    }
}; 

/**
 * Memory leak information
 */
struct LeakInfo {
    std::vector<AllocationInfo> leaks;
    size_t total_leak_count;
    size_t total_leak_bytes;
    std::chrono::system_clock::time_point detection_time;
    std::string report_file;
    
    LeakInfo() : total_leak_count(0), total_leak_bytes(0) {}
};

struct NamedAllocationRecord {
    std::string name;
    size_t current_bytes{0};
    size_t peak_bytes{0};
    size_t total_allocated{0};
    size_t total_deallocated{0};
    size_t allocation_events{0};
    size_t deallocation_events{0};
    std::chrono::system_clock::time_point last_allocation{};
    std::chrono::system_clock::time_point last_deallocation{};
    
    bool is_active() const {
        return current_bytes > 0;
    }
};

/**
 * Memory tracking configuration
 */
struct MemoryTrackerConfig {
    bool enabled;
    bool track_stack_traces;
    bool track_file_line;
    bool track_function_names;
    bool track_thread_info;
    bool track_allocation_types;
    size_t max_stack_frames;
    size_t max_allocations;
    std::chrono::milliseconds leak_check_interval;
    std::string leak_report_path;
    bool auto_generate_reports;
    bool log_all_allocations;
    bool log_deallocations;
    size_t log_threshold_size;
    
    MemoryTrackerConfig() : enabled(true), track_stack_traces(true), track_file_line(true),
                           track_function_names(true), track_thread_info(true), track_allocation_types(true),
                           max_stack_frames(32), max_allocations(100000), 
                           leak_check_interval(std::chrono::milliseconds(30000)),
                           auto_generate_reports(true), log_all_allocations(false),
                           log_deallocations(false), log_threshold_size(1024) {}
};

/**
 * Memory tracking system
 */
class MemoryTracker {
public:
    static MemoryTracker& get_instance();
    static MemoryTracker* GetInstance();
    static void Initialize();
    static void Initialize(const MemoryTrackerConfig& config);
    static void Shutdown();
    static bool IsInitialized();
    
    // Configuration
    void set_config(const MemoryTrackerConfig& config);
    MemoryTrackerConfig get_config() const;
    void enable(bool enabled = true);
    void disable();
    bool is_enabled() const;
    
    // Memory tracking
    void* track_allocation(void* address, size_t size, const std::string& file = "", int line = 0,
                          const std::string& function = "", const std::string& type = "unknown",
                          bool is_array = false, size_t array_size = 0);
    
    void track_deallocation(void* address, const std::string& type = "unknown");
    
    // Convenience methods for different allocation types
    void* track_new(void* address, size_t size, const std::string& file = "", int line = 0,
                    const std::string& function = "");
    
    void* track_new_array(void* address, size_t size, size_t count, const std::string& file = "", 
                          int line = 0, const std::string& function = "");
    
    void track_delete(void* address);
    void track_delete_array(void* address);
    
    void* track_malloc(void* address, size_t size, const std::string& file = "", int line = 0,
                       const std::string& function = "");
    
    void track_free(void* address);
    
    void* track_virtual_alloc(void* address, size_t size, const std::string& file = "", int line = 0,
                              const std::string& function = "");
    
    void track_virtual_free(void* address);
    
    void* track_heap_alloc(void* address, size_t size, const std::string& file = "", int line = 0,
                           const std::string& function = "");
    
    void track_heap_free(void* address);

    AllocationHandle track_allocation(const std::string& name, size_t size, MemoryCategory category);
    void release_allocation(AllocationHandle handle);
    bool has_allocation(AllocationHandle handle) const;
    
    // Statistics
    MemoryStats get_stats() const;
    void reset_stats();
    void Reset();
    size_t get_current_allocation_count() const;
    size_t get_current_byte_count() const;
    size_t get_peak_allocation_count() const;
    size_t get_peak_byte_count() const;
    
    // Leak detection
    LeakInfo detect_leaks();
    bool has_leaks() const;
    size_t get_leak_count() const;
    size_t get_leak_byte_count() const;
    bool is_initialized() const;
    
    // Reporting
    void generate_report(const std::string& file_path = "");
    void generate_leak_report(const std::string& file_path = "");
    void generate_statistics_report(const std::string& file_path = "");
    void generate_detailed_report(const std::string& file_path = "");
    
    // Monitoring
    void start_monitoring();
    void stop_monitoring();
    bool is_monitoring() const;
    void set_monitoring_interval(std::chrono::milliseconds interval);
    
    // Callbacks
    void set_allocation_callback(std::function<void(const AllocationInfo&)> callback);
    void set_deallocation_callback(std::function<void(const AllocationInfo&)> callback);
    void set_leak_detected_callback(std::function<void(const LeakInfo&)> callback);
    void set_threshold_exceeded_callback(std::function<void(size_t current, size_t threshold)> callback);
    
    // Utility methods
    std::string get_allocation_info_string(const AllocationInfo& info) const;
    std::string get_stats_string() const;
    std::string get_leak_summary_string() const;
    
    // Memory validation
    bool validate_allocation(void* address) const;
    bool validate_allocation_size(void* address, size_t expected_size) const;
    void validate_all_allocations() const;
    
    // Memory analysis
    std::vector<AllocationInfo> get_allocations_by_size(size_t min_size, size_t max_size = SIZE_MAX) const;
    std::vector<AllocationInfo> get_allocations_by_type(const std::string& type) const;
    std::vector<AllocationInfo> get_allocations_by_file(const std::string& file) const;
    std::vector<AllocationInfo> get_allocations_by_function(const std::string& function) const;
    std::vector<AllocationInfo> get_allocations_by_thread(const std::string& thread_id) const;
    
    // Memory patterns
    struct MemoryPattern {
        size_t size;
        size_t count;
        std::string type;
        std::string file;
        std::string function;
    };
    
    std::vector<MemoryPattern> detect_memory_patterns() const;
    
    // Memory fragmentation analysis
    struct FragmentationInfo {
        size_t total_allocated;
        size_t largest_free_block;
        size_t total_free_blocks;
        double fragmentation_percentage;
    };
    
    FragmentationInfo analyze_fragmentation() const;

    // Named allocation tracking
    void track_named_allocation(const std::string& name, size_t size);
    void track_named_deallocation(const std::string& name, size_t size = 0);
    std::vector<NamedAllocationRecord> get_named_allocations() const;
    std::vector<NamedAllocationRecord> get_active_named_allocations() const;
    size_t get_total_named_bytes() const;

private:
    struct ActiveAllocationInfo {
        AllocationHandle id;
        std::string name;
        MemoryCategory category;
        size_t size;
        std::chrono::system_clock::time_point timestamp;
    };

    static MemoryTracker* instance_;
    static std::mutex instance_mutex_;
    static std::atomic<bool> initialized_;

    MemoryTracker();
    ~MemoryTracker();
    
    // Delete copy semantics
    MemoryTracker(const MemoryTracker&) = delete;
    MemoryTracker& operator=(const MemoryTracker&) = delete;
    
    // Internal methods
    void initialize();
    void cleanup();
    void add_allocation(const AllocationInfo& info);
    void remove_allocation(void* address);
    void update_statistics(const AllocationInfo& info, bool is_allocation);
    void check_leaks();
    void generate_leak_report_internal(const LeakInfo& leaks, const std::string& file_path);
    void generate_statistics_report_internal(const MemoryStats& stats, const std::string& file_path);
    void generate_detailed_report_internal(const std::string& file_path);
    std::string get_stack_trace(size_t max_frames) const;
    std::string get_thread_id() const;
    void log_allocation(const AllocationInfo& info);
    void log_deallocation(const AllocationInfo& info);
    void check_thresholds(size_t current_size);
    void monitoring_thread_func();
    
    // Member variables
    MemoryTrackerConfig config_;
    std::atomic<bool> enabled_;
    std::atomic<bool> monitoring_;
    
    std::unordered_map<void*, AllocationInfo> allocations_;
    std::unordered_map<std::string, std::vector<AllocationInfo>> allocations_by_type_;
    mutable std::mutex allocations_mutex_;
    
    MemoryStats stats_;
    mutable std::mutex stats_mutex_;
    
    LeakInfo current_leaks_;
    mutable std::mutex leaks_mutex_;
    
    // Callbacks
    std::function<void(const AllocationInfo&)> allocation_callback_;
    std::function<void(const AllocationInfo&)> deallocation_callback_;
    std::function<void(const LeakInfo&)> leak_detected_callback_;
    std::function<void(size_t, size_t)> threshold_exceeded_callback_;
    
    // Monitoring
    std::chrono::milliseconds monitoring_interval_;
    std::thread monitoring_thread_;
    std::atomic<bool> stop_monitoring_;
    
    // Error handler
    ErrorHandler* error_handler_;
    
    // Performance tracking
    std::chrono::system_clock::time_point last_leak_check_;
    std::atomic<size_t> allocation_count_since_last_check_;
    std::atomic<size_t> allocation_count_{0};
    std::atomic<size_t> deallocation_count_{0};

    // Named allocation tracking
    std::unordered_map<std::string, NamedAllocationRecord> named_allocations_;
    mutable std::mutex named_allocations_mutex_;
    std::atomic<size_t> total_named_bytes_{0};
    std::unordered_map<AllocationHandle, ActiveAllocationInfo> active_named_allocations_;
    mutable std::mutex active_named_allocations_mutex_;
    std::atomic<AllocationHandle> next_allocation_id_{1};
};

using MemoryTrackingConfig = MemoryTrackerConfig;

/**
 * RAII wrapper for automatic memory tracking
 */
class ScopedMemoryTracker {
public:
    explicit ScopedMemoryTracker(const std::string& context = "");
    ~ScopedMemoryTracker();
    
    // Move semantics
    ScopedMemoryTracker(ScopedMemoryTracker&& other) noexcept;
    ScopedMemoryTracker& operator=(ScopedMemoryTracker&& other) noexcept;
    
    // Delete copy semantics
    ScopedMemoryTracker(const ScopedMemoryTracker&) = delete;
    ScopedMemoryTracker& operator=(const ScopedMemoryTracker&) = delete;
    
    // Methods
    void set_context(const std::string& context);
    std::string get_context() const;
    MemoryStats get_stats_at_start() const;
    MemoryStats get_current_stats() const;
    MemoryStats get_difference() const;
    void generate_report(const std::string& file_path = "");

private:
    std::string context_;
    MemoryStats stats_at_start_;
    bool active_;
};

/**
 * Memory tracking macros
 */
#define MEMORY_TRACK_NEW(address, size) \
    utils::MemoryTracker::get_instance().track_new(address, size, __FILE__, __LINE__, __FUNCTION__)

#define MEMORY_TRACK_NEW_ARRAY(address, size, count) \
    utils::MemoryTracker::get_instance().track_new_array(address, size, count, __FILE__, __LINE__, __FUNCTION__)

#define MEMORY_TRACK_DELETE(address) \
    utils::MemoryTracker::get_instance().track_delete(address)

#define MEMORY_TRACK_DELETE_ARRAY(address) \
    utils::MemoryTracker::get_instance().track_delete_array(address)

#define MEMORY_TRACK_MALLOC(address, size) \
    utils::MemoryTracker::get_instance().track_malloc(address, size, __FILE__, __LINE__, __FUNCTION__)

#define MEMORY_TRACK_FREE(address) \
    utils::MemoryTracker::get_instance().track_free(address)

#define MEMORY_TRACK_VIRTUAL_ALLOC(address, size) \
    utils::MemoryTracker::get_instance().track_virtual_alloc(address, size, __FILE__, __LINE__, __FUNCTION__)

#define MEMORY_TRACK_VIRTUAL_FREE(address) \
    utils::MemoryTracker::get_instance().track_virtual_free(address)

#define MEMORY_TRACK_HEAP_ALLOC(address, size) \
    utils::MemoryTracker::get_instance().track_heap_alloc(address, size, __FILE__, __LINE__, __FUNCTION__)

#define MEMORY_TRACK_HEAP_FREE(address) \
    utils::MemoryTracker::get_instance().track_heap_free(address)

#define MEMORY_SCOPE(context) \
    utils::ScopedMemoryTracker memory_scope_##__LINE__(context)

/**
 * Utility functions
 */
namespace memory_utils {
    
    // Memory allocation wrappers
    void* tracked_new(size_t size);
    void* tracked_new_array(size_t size, size_t count);
    void tracked_delete(void* address);
    void tracked_delete_array(void* address);
    
    void* tracked_malloc(size_t size);
    void tracked_free(void* address);
    
    void* tracked_virtual_alloc(size_t size, DWORD allocation_type = MEM_COMMIT, 
                               DWORD protection = PAGE_READWRITE);
    void tracked_virtual_free(void* address);
    
    void* tracked_heap_alloc(size_t size);
    void tracked_heap_free(void* address);
    
    // Memory validation
    bool is_valid_pointer(void* address);
    bool is_valid_allocation(void* address);
    size_t get_allocation_size(void* address);
    
    // Memory analysis
    size_t get_process_memory_usage();
    size_t get_peak_memory_usage();
    void reset_peak_memory_usage();
    
    // Memory patterns
    std::vector<MemoryTracker::MemoryPattern> detect_common_patterns();
    
    // Memory reporting
    void generate_memory_report(const std::string& file_path = "");
    void generate_memory_summary();
    
} // namespace memory_utils

} // namespace Utils
} // namespace UndownUnlock

#ifndef UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
#define UNDOWNUNLOCK_UTILS_NAMESPACE_ALIAS_DEFINED
namespace utils = UndownUnlock::Utils;
#endif
