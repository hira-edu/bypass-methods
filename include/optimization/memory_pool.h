#pragma once

#include <windows.h>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <algorithm>
#include <cassert>

namespace UndownUnlock {
namespace Utils {
class ErrorHandler;
class PerformanceMonitor;
}
class MemoryTracker;
}

namespace UndownUnlock::Optimization {

using ::UndownUnlock::Utils::ErrorHandler;
using ::UndownUnlock::Utils::PerformanceMonitor;
using ::UndownUnlock::MemoryTracker;

/**
 * Memory pool configuration
 */
struct MemoryPoolConfig {
    size_t initial_pool_size = 1024 * 1024; // 1MB initial pool
    size_t max_pool_size = 100 * 1024 * 1024; // 100MB max pool
    size_t growth_factor = 2; // Double size when growing
    size_t cleanup_threshold = 1000; // Cleanup after 1000 allocations
    std::chrono::milliseconds cleanup_interval = std::chrono::seconds(30);
    bool enable_statistics = true;
    bool enable_compression = false;
    size_t compression_threshold = 1024; // Compress objects larger than 1KB
    
    MemoryPoolConfig() = default;
};

/**
 * Memory block information
 */
struct MemoryBlock {
    void* address;
    size_t size;
    size_t alignment;
    bool is_allocated;
    std::chrono::system_clock::time_point allocation_time;
    std::chrono::system_clock::time_point last_access_time;
    size_t access_count;
    std::string allocation_type;
    
    MemoryBlock() : address(nullptr), size(0), alignment(0), is_allocated(false), access_count(0) {}
};

/**
 * Memory pool statistics
 */
struct MemoryPoolStats {
    std::atomic<size_t> total_allocations;
    std::atomic<size_t> total_deallocations;
    std::atomic<size_t> current_allocations;
    std::atomic<size_t> total_bytes_allocated;
    std::atomic<size_t> total_bytes_deallocated;
    std::atomic<size_t> current_bytes_allocated;
    std::atomic<size_t> peak_bytes_allocated;
    std::atomic<size_t> peak_allocations;
    std::atomic<size_t> pool_hits;
    std::atomic<size_t> pool_misses;
    std::atomic<double> hit_ratio;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_cleanup_time;
    
    MemoryPoolStats()
        : total_allocations(0),
          total_deallocations(0),
          current_allocations(0),
          total_bytes_allocated(0),
          total_bytes_deallocated(0),
          current_bytes_allocated(0),
          peak_bytes_allocated(0),
          peak_allocations(0),
          pool_hits(0),
          pool_misses(0),
          hit_ratio(0.0) {}

    MemoryPoolStats(const MemoryPoolStats& other)
        : total_allocations(other.total_allocations.load()),
          total_deallocations(other.total_deallocations.load()),
          current_allocations(other.current_allocations.load()),
          total_bytes_allocated(other.total_bytes_allocated.load()),
          total_bytes_deallocated(other.total_bytes_deallocated.load()),
          current_bytes_allocated(other.current_bytes_allocated.load()),
          peak_bytes_allocated(other.peak_bytes_allocated.load()),
          peak_allocations(other.peak_allocations.load()),
          pool_hits(other.pool_hits.load()),
          pool_misses(other.pool_misses.load()),
          hit_ratio(other.hit_ratio.load()),
          start_time(other.start_time),
          last_cleanup_time(other.last_cleanup_time) {}

    MemoryPoolStats& operator=(const MemoryPoolStats& other) {
        if (this != &other) {
            total_allocations.store(other.total_allocations.load());
            total_deallocations.store(other.total_deallocations.load());
            current_allocations.store(other.current_allocations.load());
            total_bytes_allocated.store(other.total_bytes_allocated.load());
            total_bytes_deallocated.store(other.total_bytes_deallocated.load());
            current_bytes_allocated.store(other.current_bytes_allocated.load());
            peak_bytes_allocated.store(other.peak_bytes_allocated.load());
            peak_allocations.store(other.peak_allocations.load());
            pool_hits.store(other.pool_hits.load());
            pool_misses.store(other.pool_misses.load());
            hit_ratio.store(other.hit_ratio.load());
            start_time = other.start_time;
            last_cleanup_time = other.last_cleanup_time;
        }
        return *this;
    }
};

/**
 * Memory pool for efficient allocation of frequently used objects
 */
class MemoryPool {
public:
    explicit MemoryPool(const MemoryPoolConfig& config = MemoryPoolConfig());
    ~MemoryPool();
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    
    // Singleton access
    static MemoryPool& get_instance();
    static void initialize(const MemoryPoolConfig& config = MemoryPoolConfig());
    static void shutdown();
    
    // Core allocation methods
    void* allocate(size_t size, size_t alignment = 8, const std::string& type = "unknown");
    void deallocate(void* address);
    void* reallocate(void* address, size_t new_size, size_t alignment = 8);
    
    // Pool management
    void cleanup();
    void defragment();
    void resize(size_t new_size);
    void clear();
    
    // Statistics and monitoring
    MemoryPoolStats get_stats() const;
    void reset_stats();
    void print_stats() const;
    
    // Configuration
    void set_config(const MemoryPoolConfig& config);
    MemoryPoolConfig get_config() const;
    
    // Advanced features
    void enable_compression(bool enable);
    void set_compression_threshold(size_t threshold);
    void enable_statistics(bool enable);
    
    // Utility methods
    bool is_address_from_pool(void* address) const;
    size_t get_block_size(void* address) const;
    std::string get_allocation_type(void* address) const;
    
private:
    // Internal methods
    void initialize_pool();
    void cleanup_pool();
    MemoryBlock* find_free_block(size_t size, size_t alignment);
    MemoryBlock* allocate_new_block(size_t size, size_t alignment);
    void free_block(MemoryBlock* block);
    void update_statistics(const MemoryBlock* block, bool is_allocation);
    void perform_cleanup();
    void perform_defragmentation();
    void compress_block(MemoryBlock* block);
    void decompress_block(MemoryBlock* block);
    size_t calculate_compressed_size(const void* data, size_t size) const;
    void* compress_data(const void* data, size_t size, size_t& compressed_size) const;
    void* decompress_data(const void* compressed_data, size_t compressed_size, size_t original_size) const;
    
    // Member variables
    static MemoryPool* instance_;
    static std::mutex instance_mutex_;
    
    MemoryPoolConfig config_;
    std::vector<MemoryBlock> blocks_;
    std::unordered_map<void*, MemoryBlock*> address_to_block_;
    mutable std::mutex pool_mutex_;
    mutable std::mutex stats_mutex_;
    
    MemoryPoolStats stats_;
    std::chrono::system_clock::time_point last_cleanup_;
    std::atomic<bool> cleanup_running_;
    
    // Performance monitoring
    ErrorHandler* error_handler_;
    PerformanceMonitor* performance_monitor_;
    MemoryTracker* memory_tracker_;
};

/**
 * RAII wrapper for memory pool allocations
 */
template<typename T>
class PoolAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::false_type;
    
    explicit PoolAllocator(const std::string& type = "template") : allocation_type_(type) {}
    
    template<typename U>
    PoolAllocator(const PoolAllocator<U>& other) : allocation_type_(other.allocation_type_) {}
    
    T* allocate(size_type n) {
        size_t size = n * sizeof(T);
        return static_cast<T*>(MemoryPool::get_instance().allocate(size, alignof(T), allocation_type_));
    }
    
    void deallocate(T* p, size_type n) noexcept {
        MemoryPool::get_instance().deallocate(p);
    }
    
    template<typename U, typename... Args>
    void construct(U* p, Args&&... args) {
        ::new(static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }
    
    template<typename U>
    void destroy(U* p) {
        p->~U();
    }
    
    bool operator==(const PoolAllocator& other) const {
        return allocation_type_ == other.allocation_type_;
    }
    
    bool operator!=(const PoolAllocator& other) const {
        return !(*this == other);
    }
    
private:
    std::string allocation_type_;
};

/**
 * Smart pointer using memory pool
 */
template<typename T>
class PoolPtr {
public:
    explicit PoolPtr(const std::string& type = "pool_ptr") 
        : ptr_(nullptr), allocator_(type) {}
    
    explicit PoolPtr(T* raw_ptr, const std::string& type = "pool_ptr")
        : ptr_(raw_ptr), allocator_(type) {}
    
    ~PoolPtr() {
        if (ptr_) {
            ptr_->~T();
            allocator_.deallocate(ptr_, 1);
        }
    }
    
    // Move constructor
    PoolPtr(PoolPtr&& other) noexcept : ptr_(other.ptr_), allocator_(std::move(other.allocator_)) {
        other.ptr_ = nullptr;
    }
    
    // Move assignment
    PoolPtr& operator=(PoolPtr&& other) noexcept {
        if (this != &other) {
            if (ptr_) {
                ptr_->~T();
                allocator_.deallocate(ptr_, 1);
            }
            ptr_ = other.ptr_;
            allocator_ = std::move(other.allocator_);
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    // Access operators
    T* get() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    T* operator->() const { return ptr_; }
    
    // Boolean conversion
    explicit operator bool() const { return ptr_ != nullptr; }
    
    // Reset
    void reset(T* new_ptr = nullptr) {
        if (ptr_) {
            ptr_->~T();
            allocator_.deallocate(ptr_, 1);
        }
        ptr_ = new_ptr;
    }
    
    // Release ownership
    T* release() {
        T* temp = ptr_;
        ptr_ = nullptr;
        return temp;
    }
    
private:
    T* ptr_;
    PoolAllocator<T> allocator_;
    
    // Disable copy
    PoolPtr(const PoolPtr&) = delete;
    PoolPtr& operator=(const PoolPtr&) = delete;
};

/**
 * Memory pool utilities
 */
namespace MemoryPoolUtils {
    
    // Create a pooled object
    template<typename T, typename... Args>
    PoolPtr<T> make_pooled(const std::string& type, Args&&... args) {
        auto allocator = PoolAllocator<T>(type);
        T* ptr = allocator.allocate(1);
        allocator.construct(ptr, std::forward<Args>(args)...);
        return PoolPtr<T>(ptr, type);
    }
    
    // Get pool statistics
    inline MemoryPoolStats get_pool_stats() {
        return MemoryPool::get_instance().get_stats();
    }
    
    // Perform pool cleanup
    inline void cleanup_pool() {
        MemoryPool::get_instance().cleanup();
    }
    
    // Check if address is from pool
    inline bool is_pooled_address(void* address) {
        return MemoryPool::get_instance().is_address_from_pool(address);
    }
    
    // Get allocation type for address
    inline std::string get_allocation_type(void* address) {
        return MemoryPool::get_instance().get_allocation_type(address);
    }
}

} // namespace UndownUnlock::Optimization 
