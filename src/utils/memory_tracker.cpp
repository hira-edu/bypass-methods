#include "../../include/utils/memory_tracker.h"
#include "../../include/utils/error_handler.h"
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <dbghelp.h>

namespace UndownUnlock::Utils {

// Static member initialization
MemoryTracker* MemoryTracker::instance_ = nullptr;
std::mutex MemoryTracker::instance_mutex_;
std::atomic<bool> MemoryTracker::initialized_{false};

// Static member initialization for other classes
std::vector<MemoryLeak> MemoryLeakDetector::detected_leaks_;
std::mutex MemoryLeakDetector::leaks_mutex_;
std::chrono::system_clock::time_point MemoryLeakDetector::last_detection_;

std::atomic<bool> MemoryUsageMonitor::monitoring_enabled_(false);
std::chrono::system_clock::time_point MemoryUsageMonitor::last_check_;
std::chrono::milliseconds MemoryUsageMonitor::check_interval_(std::chrono::seconds(5));
std::function<void(const MemoryStats&)> MemoryUsageMonitor::callback_;

std::vector<MemoryProfiler::ProfilePoint> MemoryProfiler::profile_points_;
std::mutex MemoryProfiler::profile_mutex_;

// MemoryTracker implementation
MemoryTracker::MemoryTracker() : tracking_enabled_(false), allocation_count_(0), deallocation_count_(0) {
    stats_.start_time = std::chrono::system_clock::now();
    last_leak_check_ = std::chrono::system_clock::now();
}

MemoryTracker::~MemoryTracker() {
    // Generate final report
    if (tracking_enabled_.load()) {
        generate_report("memory_tracker_final_report.txt");
    }
}

MemoryTracker& MemoryTracker::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new MemoryTracker();
    }
    initialized_.store(true, std::memory_order_release);
    return *instance_;
}

void MemoryTracker::Initialize(const MemoryTrackerConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new MemoryTracker();
    }
    instance_->set_config(config);
    initialized_.store(true, std::memory_order_release);
}

void MemoryTracker::Initialize() {
    Initialize(MemoryTrackerConfig());
}

MemoryTracker* MemoryTracker::GetInstance() {
    return &get_instance();
}

bool MemoryTracker::IsInitialized() {
    return initialized_.load(std::memory_order_acquire);
}

void MemoryTracker::Shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        delete instance_;
        instance_ = nullptr;
    }
    initialized_.store(false, std::memory_order_release);
}

void* MemoryTracker::track_allocation(void* address, size_t size, AllocationType type,
                                      const std::string& function, const std::string& file, int line) {
    if (!tracking_enabled_.load() || !config_.enabled) {
        return address;
    }
    
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    
    MemoryAllocation allocation;
    allocation.address = address;
    allocation.size = size;
    allocation.allocation_type = allocation_type_to_string(type);
    allocation.function = function;
    allocation.file = file;
    allocation.line = line;
    allocation.timestamp = std::chrono::system_clock::now();
    allocation.thread_id = GetCurrentThreadId();
    allocation.is_freed = false;
    
    if (config_.track_stack_traces) {
        allocation.stack_trace = get_stack_trace(config_.max_stack_depth);
    }
    
    allocations_[address] = allocation;
    
    if (config_.track_allocation_types) {
        allocations_by_type_[allocation.allocation_type].push_back(allocation);
    }
    
    update_stats(allocation, true);
    allocation_count_.fetch_add(1);
    
    // Check if we need to clean up old allocations
    if (allocations_.size() > config_.max_allocations) {
        cleanup_old_samples();
    }
    
    // Check for leaks periodically
    auto now = std::chrono::system_clock::now();
    if (now - last_leak_check_ > config_.leak_detection_interval) {
        check_for_leaks();
        last_leak_check_ = now;
    }
}

void MemoryTracker::track_deallocation(void* address, AllocationType type) {
    if (!tracking_enabled_.load() || !config_.enabled) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    
    auto it = allocations_.find(address);
    if (it != allocations_.end()) {
        it->second.is_freed = true;
        it->second.timestamp = std::chrono::system_clock::now();
        
        update_stats(it->second, false);
        deallocation_count_.fetch_add(1);
        
        // Remove from type-based tracking
        if (config_.track_allocation_types) {
            auto& type_allocations = allocations_by_type_[it->second.allocation_type];
            type_allocations.erase(
                std::remove_if(type_allocations.begin(), type_allocations.end(),
                              [address](const MemoryAllocation& alloc) {
                                  return alloc.address == address;
                              }),
                type_allocations.end()
            );
        }
    }
}

MemoryStats MemoryTracker::get_stats() const {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    return stats_;
}

std::vector<MemoryLeak> MemoryTracker::detect_leaks() {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    std::vector<MemoryLeak> leaks;
    
    for (const auto& pair : allocations_) {
        const auto& allocation = pair.second;
        if (!allocation.is_freed) {
            MemoryLeak leak;
            leak.allocation = allocation;
            leak.detection_time = std::chrono::system_clock::now();
            leak.leak_type = allocation.allocation_type;
            leak.leak_size = allocation.size;
            leak.leak_count = 1;
            leaks.push_back(leak);
        }
    }
    
    return leaks;
}

void MemoryTracker::Reset() {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    allocations_.clear();
    allocations_by_type_.clear();
    detected_leaks_.clear();
    
    // Reset stats
    stats_ = MemoryStats();
    stats_.start_time = std::chrono::system_clock::now();
    
    allocation_count_.store(0);
    deallocation_count_.store(0);
    
    {
        std::lock_guard<std::mutex> named_lock(named_allocations_mutex_);
        named_allocations_.clear();
    }
    {
        std::lock_guard<std::mutex> handle_lock(active_named_allocations_mutex_);
        active_named_allocations_.clear();
    }
    total_named_bytes_.store(0, std::memory_order_relaxed);
    next_allocation_id_.store(1, std::memory_order_relaxed);
}

void MemoryTracker::set_config(const MemoryTrackerConfig& config) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    config_ = config;
    tracking_enabled_.store(config.enabled);
}

void MemoryTracker::enable_tracking(bool enabled) {
    tracking_enabled_.store(enabled);
    config_.enabled = enabled;
}

bool MemoryTracker::is_initialized() const {
    return initialized_.load(std::memory_order_acquire);
}

std::vector<MemoryAllocation> MemoryTracker::get_allocations_by_type(const std::string& type) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    auto it = allocations_by_type_.find(type);
    if (it != allocations_by_type_.end()) {
        return it->second;
    }
    return std::vector<MemoryAllocation>();
}

std::vector<MemoryAllocation> MemoryTracker::get_allocations_by_function(const std::string& function) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    std::vector<MemoryAllocation> result;
    
    for (const auto& pair : allocations_) {
        if (pair.second.function == function) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

std::vector<MemoryAllocation> MemoryTracker::get_allocations_by_file(const std::string& file) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    std::vector<MemoryAllocation> result;
    
    for (const auto& pair : allocations_) {
        if (pair.second.file == file) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

void MemoryTracker::set_leak_callback(std::function<void(const MemoryLeak&)> callback) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    config_.leak_callback = callback;
}

void MemoryTracker::set_stats_callback(std::function<void(const MemoryStats&)> callback) {
    std::lock_guard<std::mutex> lock(allocations_mutex_);
    config_.stats_callback = callback;
}

void MemoryTracker::generate_report(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open report file: " + filename, ErrorCategory::FILE_IO);
        return;
    }
    
    auto stats = get_stats();
    auto leaks = detect_leaks();
    
    file << "=== Memory Tracker Report ===\n";
    file << "Generated: " << format_timestamp(std::chrono::system_clock::now()) << "\n\n";
    
    file << "=== Statistics ===\n";
    file << format_stats(stats);
    
    file << "\n=== Memory Leaks ===\n";
    if (leaks.empty()) {
        file << "No memory leaks detected.\n";
    } else {
        file << "Found " << leaks.size() << " memory leaks:\n\n";
        for (const auto& leak : leaks) {
            file << format_leak(leak) << "\n";
        }
    }
    
    file << "\n=== Allocations by Type ===\n";
    for (const auto& pair : allocations_by_type_) {
        file << pair.first << ": " << pair.second.size() << " allocations\n";
    }
    
    file.close();
}

void MemoryTracker::print_stats() {
    auto stats = get_stats();
    printf("=== Memory Statistics ===\n");
    printf("%s", format_stats(stats).c_str());
}

void MemoryTracker::print_leaks() {
    auto leaks = detect_leaks();
    printf("=== Memory Leaks ===\n");
    if (leaks.empty()) {
        printf("No memory leaks detected.\n");
    } else {
        printf("Found %zu memory leaks:\n\n", leaks.size());
        for (const auto& leak : leaks) {
            printf("%s\n", format_leak(leak).c_str());
        }
    }
}

std::string MemoryTracker::get_stack_trace(size_t max_depth) {
    // This is a simplified stack trace implementation
    // In a production environment, you'd want to use a more robust solution
    std::ostringstream oss;
    oss << "Stack trace not available in this build";
    return oss.str();
}

std::string MemoryTracker::allocation_type_to_string(AllocationType type) {
    switch (type) {
        case AllocationType::NEW: return "NEW";
        case AllocationType::NEW_ARRAY: return "NEW_ARRAY";
        case AllocationType::MALLOC: return "MALLOC";
        case AllocationType::CALLOC: return "CALLOC";
        case AllocationType::REALLOC: return "REALLOC";
        case AllocationType::VIRTUAL_ALLOC: return "VIRTUAL_ALLOC";
        case AllocationType::HEAP_ALLOC: return "HEAP_ALLOC";
        case AllocationType::WINDOWS_API: return "WINDOWS_API";
        case AllocationType::DIRECTX: return "DIRECTX";
        case AllocationType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

void MemoryTracker::update_stats(const MemoryAllocation& allocation, bool is_allocation) {
    if (is_allocation) {
        stats_.total_allocations.fetch_add(1);
        stats_.current_allocations.fetch_add(1);
        stats_.total_bytes_allocated.fetch_add(allocation.size);
        stats_.current_bytes_allocated.fetch_add(allocation.size);
        stats_.last_allocation_time = allocation.timestamp;
        
        size_t current = stats_.current_bytes_allocated.load();
        size_t peak = stats_.peak_bytes_allocated.load();
        if (current > peak) {
            stats_.peak_bytes_allocated.store(current);
        }
    } else {
        stats_.total_deallocations.fetch_add(1);
        stats_.current_allocations.fetch_sub(1);
        stats_.total_bytes_freed.fetch_add(allocation.size);
        stats_.current_bytes_allocated.fetch_sub(allocation.size);
        stats_.last_deallocation_time = allocation.timestamp;
    }
}

void MemoryTracker::check_for_leaks() {
    auto leaks = detect_leaks();
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    
    for (const auto& leak : leaks) {
        report_leak(leak);
    }
    
    detected_leaks_.insert(detected_leaks_.end(), leaks.begin(), leaks.end());
    stats_.leak_count.store(detected_leaks_.size());
}

void MemoryTracker::report_leak(const MemoryLeak& leak) {
    if (config_.leak_callback) {
        config_.leak_callback(leak);
    }
    
    LOG_WARNING("Memory leak detected: " + leak.leak_type + 
                " (" + std::to_string(leak.leak_size) + " bytes)", ErrorCategory::MEMORY);
}

void MemoryTracker::report_stats(const MemoryStats& stats) {
    if (config_.stats_callback) {
        config_.stats_callback(stats);
    }
}

std::string MemoryTracker::format_allocation(const MemoryAllocation& allocation) {
    std::ostringstream oss;
    oss << "Address: 0x" << std::hex << std::setw(16) << std::setfill('0') 
        << reinterpret_cast<uintptr_t>(allocation.address) << std::dec
        << " Size: " << allocation.size << " bytes"
        << " Type: " << allocation.allocation_type
        << " Function: " << allocation.function
        << " File: " << allocation.file << ":" << allocation.line
        << " Thread: " << allocation.thread_id
        << " Freed: " << (allocation.is_freed ? "Yes" : "No");
    return oss.str();
}

std::string MemoryTracker::format_leak(const MemoryLeak& leak) {
    std::ostringstream oss;
    oss << "Leak Type: " << leak.leak_type
        << " Size: " << leak.leak_size << " bytes"
        << " Count: " << leak.leak_count
        << " Detection Time: " << format_timestamp(leak.detection_time)
        << "\nAllocation: " << format_allocation(leak.allocation);
    return oss.str();
}

std::string MemoryTracker::format_stats(const MemoryStats& stats) {
    std::ostringstream oss;
    oss << "Total Allocations: " << stats.total_allocations.load() << "\n"
        << "Total Deallocations: " << stats.total_deallocations.load() << "\n"
        << "Current Allocations: " << stats.current_allocations.load() << "\n"
        << "Total Bytes Allocated: " << stats.total_bytes_allocated.load() << "\n"
        << "Total Bytes Freed: " << stats.total_bytes_freed.load() << "\n"
        << "Current Bytes Allocated: " << stats.current_bytes_allocated.load() << "\n"
        << "Peak Bytes Allocated: " << stats.peak_bytes_allocated.load() << "\n"
        << "Leak Count: " << stats.leak_count.load() << "\n"
        << "Start Time: " << format_timestamp(stats.start_time) << "\n"
        << "Last Allocation: " << format_timestamp(stats.last_allocation_time) << "\n"
        << "Last Deallocation: " << format_timestamp(stats.last_deallocation_time) << "\n";
    return oss.str();
}

void MemoryTracker::cleanup_old_samples() {
    // Remove old allocations that have been freed
    auto it = allocations_.begin();
    while (it != allocations_.end()) {
        if (it->second.is_freed) {
            it = allocations_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string MemoryTracker::format_timestamp(const std::chrono::system_clock::time_point& timestamp) {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// MemoryLeakDetector implementation
void MemoryLeakDetector::initialize() {
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    detected_leaks_.clear();
    last_detection_ = std::chrono::system_clock::now();
}

void MemoryLeakDetector::shutdown() {
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    detected_leaks_.clear();
}

std::vector<MemoryLeak> MemoryLeakDetector::detect_leaks() {
    return MemoryTracker::get_instance().detect_leaks();
}

void MemoryLeakDetector::report_leaks() {
    auto leaks = detect_leaks();
    if (!leaks.empty()) {
        LOG_WARNING("Memory leak detection found " + std::to_string(leaks.size()) + " leaks", 
                   ErrorCategory::MEMORY);
        for (const auto& leak : leaks) {
            LOG_WARNING("Leak: " + leak.leak_type + " (" + std::to_string(leak.leak_size) + " bytes)", 
                       ErrorCategory::MEMORY);
        }
    }
}

void MemoryLeakDetector::clear_leaks() {
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    detected_leaks_.clear();
}

size_t MemoryLeakDetector::get_leak_count() {
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    return detected_leaks_.size();
}

size_t MemoryLeakDetector::get_total_leak_size() {
    std::lock_guard<std::mutex> lock(leaks_mutex_);
    size_t total_size = 0;
    for (const auto& leak : detected_leaks_) {
        total_size += leak.leak_size;
    }
    return total_size;
}

// MemoryUsageMonitor implementation
void MemoryUsageMonitor::start_monitoring(std::chrono::milliseconds interval) {
    check_interval_ = interval;
    monitoring_enabled_.store(true);
    last_check_ = std::chrono::system_clock::now();
}

void MemoryUsageMonitor::stop_monitoring() {
    monitoring_enabled_.store(false);
}

void MemoryUsageMonitor::set_callback(std::function<void(const MemoryStats&)> callback) {
    callback_ = callback;
}

MemoryStats MemoryUsageMonitor::get_current_usage() {
    return MemoryTracker::get_instance().get_stats();
}

void MemoryUsageMonitor::check_memory_usage() {
    if (!monitoring_enabled_.load()) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    if (now - last_check_ >= check_interval_) {
        auto stats = get_current_usage();
        if (callback_) {
            callback_(stats);
        }
        last_check_ = now;
    }
}

// MemoryProfiler implementation
void MemoryProfiler::add_profile_point(const std::string& name) {
    std::lock_guard<std::mutex> lock(profile_mutex_);
    ProfilePoint point;
    point.name = name;
    point.timestamp = std::chrono::system_clock::now();
    point.stats = MemoryTracker::get_instance().get_stats();
    profile_points_.push_back(point);
}

void MemoryProfiler::clear_profile() {
    std::lock_guard<std::mutex> lock(profile_mutex_);
    profile_points_.clear();
}

std::vector<MemoryProfiler::ProfilePoint> MemoryProfiler::get_profile() {
    std::lock_guard<std::mutex> lock(profile_mutex_);
    return profile_points_;
}

void MemoryProfiler::generate_profile_report(const std::string& filename) {
    auto profile = get_profile();
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open profile report file: " + filename, ErrorCategory::FILE_IO);
        return;
    }
    
    file << "=== Memory Profile Report ===\n";
    file << "Generated: " << MemoryTracker::get_instance().format_timestamp(std::chrono::system_clock::now()) << "\n\n";
    
    for (const auto& point : profile) {
        file << "=== Profile Point: " << point.name << " ===\n";
        file << "Timestamp: " << MemoryTracker::get_instance().format_timestamp(point.timestamp) << "\n";
        file << MemoryTracker::get_instance().format_stats(point.stats) << "\n";
    }
    
    file.close();
}

void MemoryProfiler::print_profile() {
    auto profile = get_profile();
    printf("=== Memory Profile ===\n");
    for (const auto& point : profile) {
        printf("Profile Point: %s\n", point.name.c_str());
        printf("Timestamp: %s\n", MemoryTracker::get_instance().format_timestamp(point.timestamp).c_str());
        printf("%s", MemoryTracker::get_instance().format_stats(point.stats).c_str());
        printf("\n");
    }
}

// MemoryUtils implementation
namespace MemoryUtils {
    size_t get_process_memory_usage() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), 
                                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }
    
    size_t get_peak_memory_usage() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), 
                                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PeakWorkingSetSize;
        }
        return 0;
    }
    
    size_t get_available_memory() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return memInfo.ullAvailPhys;
        }
        return 0;
    }
    
    std::string format_memory_size(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unit_index = 0;
        double size = static_cast<double>(bytes);
        
        while (size >= 1024.0 && unit_index < 4) {
            size /= 1024.0;
            unit_index++;
        }
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
        return oss.str();
    }
    
    bool is_memory_pressure_high() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return memInfo.dwMemoryLoad > 80; // 80% memory usage threshold
        }
        return false;
    }
    
    void optimize_memory_usage() {
        // Force garbage collection and memory cleanup
        SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
        EmptyWorkingSet(GetCurrentProcess());
    }
    
    std::vector<std::string> get_memory_regions() {
        std::vector<std::string> regions;
        // This would require more complex implementation to enumerate memory regions
        // For now, return empty vector
        return regions;
    }
    
    void dump_memory_map(const std::string& filename) {
        // This would require more complex implementation to dump memory map
        // For now, just log that it's not implemented
        LOG_INFO("Memory map dumping not implemented in this build", ErrorCategory::MEMORY);
    }
}

void MemoryTracker::track_named_allocation(const std::string& name, size_t size) {
    if (name.empty() || size == 0) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(named_allocations_mutex_);
    auto& record = named_allocations_[name];
    if (record.name.empty()) {
        record.name = name;
    }
    record.current_bytes += size;
    record.total_allocated += size;
    record.allocation_events++;
    record.last_allocation = now;
    if (record.current_bytes > record.peak_bytes) {
        record.peak_bytes = record.current_bytes;
    }
    total_named_bytes_.fetch_add(size, std::memory_order_relaxed);
}

AllocationHandle MemoryTracker::track_allocation(const std::string& name, size_t size, MemoryCategory category) {
    if (!tracking_enabled_.load() || !config_.enabled) {
        return 0;
    }

    AllocationHandle id = next_allocation_id_.fetch_add(1, std::memory_order_relaxed);
    ActiveAllocationInfo info;
    info.id = id;
    info.name = name.empty() ? ("allocation_" + std::to_string(id)) : name;
    info.category = category;
    info.size = size;
    info.timestamp = std::chrono::system_clock::now();

    {
        std::lock_guard<std::mutex> lock(active_named_allocations_mutex_);
        active_named_allocations_[id] = info;
    }

    track_named_allocation(info.name, size);
    return id;
}

void MemoryTracker::release_allocation(AllocationHandle handle) {
    ActiveAllocationInfo info;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(active_named_allocations_mutex_);
        auto it = active_named_allocations_.find(handle);
        if (it != active_named_allocations_.end()) {
            info = it->second;
            active_named_allocations_.erase(it);
            found = true;
        }
    }

    if (!found) {
        return;
    }

    track_named_deallocation(info.name, info.size);
}

bool MemoryTracker::has_allocation(AllocationHandle handle) const {
    std::lock_guard<std::mutex> lock(active_named_allocations_mutex_);
    return active_named_allocations_.find(handle) != active_named_allocations_.end();
}

void MemoryTracker::track_named_deallocation(const std::string& name, size_t size) {
    std::lock_guard<std::mutex> lock(named_allocations_mutex_);
    auto it = named_allocations_.find(name);
    if (it == named_allocations_.end()) {
        return;
    }

    auto& record = it->second;
    if (size == 0 || size > record.current_bytes) {
        size = record.current_bytes;
    }

    if (size == 0) {
        return;
    }

    record.current_bytes -= size;
    record.total_deallocated += size;
    record.deallocation_events++;
    record.last_deallocation = std::chrono::system_clock::now();

    total_named_bytes_.fetch_sub(size, std::memory_order_relaxed);
}

std::vector<NamedAllocationRecord> MemoryTracker::get_named_allocations() const {
    std::lock_guard<std::mutex> lock(named_allocations_mutex_);
    std::vector<NamedAllocationRecord> records;
    records.reserve(named_allocations_.size());
    for (const auto& entry : named_allocations_) {
        records.push_back(entry.second);
    }
    return records;
}

std::vector<NamedAllocationRecord> MemoryTracker::get_active_named_allocations() const {
    std::lock_guard<std::mutex> lock(named_allocations_mutex_);
    std::vector<NamedAllocationRecord> records;
    records.reserve(named_allocations_.size());
    for (const auto& entry : named_allocations_) {
        if (entry.second.current_bytes > 0) {
            records.push_back(entry.second);
        }
    }
    return records;
}

size_t MemoryTracker::get_total_named_bytes() const {
    return total_named_bytes_.load(std::memory_order_relaxed);
}

} // namespace UndownUnlock::Utils
