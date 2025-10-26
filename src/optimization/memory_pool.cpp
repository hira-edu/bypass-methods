#include "../../include/optimization/memory_pool.h"
#include "../../include/utils/error_handler.h"
#include "../../include/utils/performance_monitor.h"
#include "../../include/memory_tracker.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace UndownUnlock::Optimization {

namespace {
MemoryPoolStats SnapshotStats(const MemoryPoolStats& source) {
    MemoryPoolStats snapshot;
    snapshot.total_allocations.store(source.total_allocations.load());
    snapshot.total_deallocations.store(source.total_deallocations.load());
    snapshot.current_allocations.store(source.current_allocations.load());
    snapshot.total_bytes_allocated.store(source.total_bytes_allocated.load());
    snapshot.total_bytes_deallocated.store(source.total_bytes_deallocated.load());
    snapshot.current_bytes_allocated.store(source.current_bytes_allocated.load());
    snapshot.peak_bytes_allocated.store(source.peak_bytes_allocated.load());
    snapshot.peak_allocations.store(source.peak_allocations.load());
    snapshot.pool_hits.store(source.pool_hits.load());
    snapshot.pool_misses.store(source.pool_misses.load());
    snapshot.hit_ratio.store(source.hit_ratio.load());
    snapshot.start_time = source.start_time;
    snapshot.last_cleanup_time = source.last_cleanup_time;
    return snapshot;
}

void ResetStats(MemoryPoolStats& stats, const std::chrono::system_clock::time_point& now) {
    stats.total_allocations.store(0);
    stats.total_deallocations.store(0);
    stats.current_allocations.store(0);
    stats.total_bytes_allocated.store(0);
    stats.total_bytes_deallocated.store(0);
    stats.current_bytes_allocated.store(0);
    stats.peak_bytes_allocated.store(0);
    stats.peak_allocations.store(0);
    stats.pool_hits.store(0);
    stats.pool_misses.store(0);
    stats.hit_ratio.store(0.0);
    stats.start_time = now;
    stats.last_cleanup_time = now;
}
} // namespace

// Static member initialization
MemoryPool* MemoryPool::instance_ = nullptr;
std::mutex MemoryPool::instance_mutex_;

MemoryPool::MemoryPool(const MemoryPoolConfig& config)
    : config_(config), cleanup_running_(false) {
    
    // Initialize utility components
    error_handler_ = utils::ErrorHandler::GetInstance();
    performance_monitor_ = utils::PerformanceMonitor::GetInstance();
    memory_tracker_ = &MemoryTracker::GetInstance();
    ResetStats(stats_, std::chrono::system_clock::now());
    
    // Set error context
    utils::ErrorContext context;
    context.set("component", "MemoryPool");
    context.set("operation", "initialization");
    error_handler_->set_error_context(context);
    
    error_handler_->info(
        "Initializing Memory Pool with config: " + std::to_string(config.initial_pool_size) + " bytes",
        utils::ErrorCategory::MEMORY,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Initialize the pool
    initialize_pool();
    
    // Start performance monitoring
    auto init_operation = performance_monitor_->start_operation("memory_pool_initialization");
    performance_monitor_->end_operation(init_operation);
    
    // Track memory allocation for the pool
    memory_tracker_->TrackAllocation("memory_pool", config.initial_pool_size);
}

MemoryPool::~MemoryPool() {
    error_handler_->info(
        "Shutting down Memory Pool",
        utils::ErrorCategory::MEMORY,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    cleanup_pool();
    clear();
}

MemoryPool& MemoryPool::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new MemoryPool();
    }
    return *instance_;
}

void MemoryPool::initialize(const MemoryPoolConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new MemoryPool(config);
    } else {
        instance_->set_config(config);
    }
}

void MemoryPool::shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        delete instance_;
        instance_ = nullptr;
    }
}

void* MemoryPool::allocate(size_t size, size_t alignment, const std::string& type) {
    if (size == 0) {
        return nullptr;
    }
    
    // Start performance monitoring
    auto alloc_operation = performance_monitor_->start_operation("memory_pool_allocation");
    
    // Set error context
    utils::ErrorContext context;
    context.set("component", "MemoryPool");
    context.set("operation", "allocation");
    context.set("size", std::to_string(size));
    context.set("alignment", std::to_string(alignment));
    context.set("type", type);
    error_handler_->set_error_context(context);
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    try {
        // Find a free block
        MemoryBlock* block = find_free_block(size, alignment);
        if (!block) {
            // Need to allocate a new block
            block = allocate_new_block(size, alignment);
            if (!block) {
                error_handler_->error(
                    "Failed to allocate new memory block of size " + std::to_string(size),
                    utils::ErrorCategory::MEMORY,
                    __FUNCTION__, __FILE__, __LINE__
                );
                performance_monitor_->end_operation(alloc_operation);
                return nullptr;
            }
            stats_.pool_misses.fetch_add(1);
        } else {
            stats_.pool_hits.fetch_add(1);
        }
        
        // Mark block as allocated
        block->is_allocated = true;
        block->allocation_time = std::chrono::system_clock::now();
        block->last_access_time = block->allocation_time;
        block->access_count = 1;
        block->allocation_type = type;
        
        // Update address mapping
        address_to_block_[block->address] = block;
        
        // Update statistics
        update_statistics(block, true);
        
        // Track allocation
        memory_tracker_->TrackAllocation("pool_" + type, size);
        
        error_handler_->debug(
            "Allocated " + std::to_string(size) + " bytes from pool for type: " + type,
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        performance_monitor_->end_operation(alloc_operation);
        return block->address;
        
    } catch (const std::exception& e) {
        error_handler_->error(
            "Exception during memory allocation: " + std::string(e.what()),
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        performance_monitor_->end_operation(alloc_operation);
        return nullptr;
    }
}

void MemoryPool::deallocate(void* address) {
    if (!address) {
        return;
    }
    
    // Start performance monitoring
    auto dealloc_operation = performance_monitor_->start_operation("memory_pool_deallocation");
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    try {
        auto it = address_to_block_.find(address);
        if (it == address_to_block_.end()) {
            error_handler_->warning(
                "Attempting to deallocate address not from pool: " + std::to_string(reinterpret_cast<uintptr_t>(address)),
                utils::ErrorCategory::MEMORY,
                __FUNCTION__, __FILE__, __LINE__
            );
            performance_monitor_->end_operation(dealloc_operation);
            return;
        }
        
        MemoryBlock* block = it->second;
        
        // Update statistics
        update_statistics(block, false);
        
        // Free the block
        free_block(block);
        
        // Remove from address mapping
        address_to_block_.erase(it);
        
        error_handler_->debug(
            "Deallocated " + std::to_string(block->size) + " bytes from pool",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        performance_monitor_->end_operation(dealloc_operation);
        
    } catch (const std::exception& e) {
        error_handler_->error(
            "Exception during memory deallocation: " + std::string(e.what()),
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        performance_monitor_->end_operation(dealloc_operation);
    }
}

void* MemoryPool::reallocate(void* address, size_t new_size, size_t alignment) {
    if (!address) {
        return allocate(new_size, alignment);
    }
    
    if (new_size == 0) {
        deallocate(address);
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto it = address_to_block_.find(address);
    if (it == address_to_block_.end()) {
        error_handler_->warning(
            "Attempting to reallocate address not from pool",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        return nullptr;
    }
    
    MemoryBlock* block = it->second;
    
    // If the new size fits in the current block, just return the same address
    if (new_size <= block->size) {
        block->last_access_time = std::chrono::system_clock::now();
        block->access_count++;
        return address;
    }
    
    // Otherwise, allocate new block and copy data
    void* new_address = allocate(new_size, alignment, block->allocation_type);
    if (new_address) {
        std::memcpy(new_address, address, block->size);
        deallocate(address);
    }
    
    return new_address;
}

void MemoryPool::cleanup() {
    if (cleanup_running_.load()) {
        return;
    }
    
    cleanup_running_.store(true);
    
    auto cleanup_operation = performance_monitor_->start_operation("memory_pool_cleanup");
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    try {
        perform_cleanup();
        last_cleanup_ = std::chrono::system_clock::now();
        
        error_handler_->info(
            "Memory pool cleanup completed",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        performance_monitor_->end_operation(cleanup_operation);
        
    } catch (const std::exception& e) {
        error_handler_->error(
            "Exception during memory pool cleanup: " + std::string(e.what()),
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        performance_monitor_->end_operation(cleanup_operation);
    }
    
    cleanup_running_.store(false);
}

void MemoryPool::defragment() {
    auto defrag_operation = performance_monitor_->start_operation("memory_pool_defragmentation");
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    try {
        perform_defragmentation();
        
        error_handler_->info(
            "Memory pool defragmentation completed",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        
        performance_monitor_->end_operation(defrag_operation);
        
    } catch (const std::exception& e) {
        error_handler_->error(
            "Exception during memory pool defragmentation: " + std::string(e.what()),
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        performance_monitor_->end_operation(defrag_operation);
    }
}

void MemoryPool::resize(size_t new_size) {
    if (new_size <= config_.max_pool_size) {
        config_.initial_pool_size = new_size;
        error_handler_->info(
            "Memory pool resized to " + std::to_string(new_size) + " bytes",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
    } else {
        error_handler_->warning(
            "Requested pool size " + std::to_string(new_size) + " exceeds maximum " + std::to_string(config_.max_pool_size),
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

void MemoryPool::clear() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    // Free all allocated blocks
    for (auto& block : blocks_) {
        if (block.is_allocated) {
            free_block(&block);
        }
    }
    
    blocks_.clear();
    address_to_block_.clear();
    
    error_handler_->info(
        "Memory pool cleared",
        utils::ErrorCategory::MEMORY,
        __FUNCTION__, __FILE__, __LINE__
    );
}

MemoryPoolStats MemoryPool::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    MemoryPoolStats current_stats = SnapshotStats(stats_);
    
    // Calculate hit ratio
    size_t total_requests = current_stats.pool_hits.load() + current_stats.pool_misses.load();
    if (total_requests > 0) {
        current_stats.hit_ratio.store(static_cast<double>(current_stats.pool_hits.load()) / total_requests);
    }
    
    return current_stats;
}

void MemoryPool::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ResetStats(stats_, std::chrono::system_clock::now());
}

void MemoryPool::print_stats() const {
    auto stats = get_stats();
    
    std::stringstream ss;
    ss << "=== Memory Pool Statistics ===" << std::endl;
    ss << "Total Allocations: " << stats.total_allocations.load() << std::endl;
    ss << "Total Deallocations: " << stats.total_deallocations.load() << std::endl;
    ss << "Current Allocations: " << stats.current_allocations.load() << std::endl;
    ss << "Total Bytes Allocated: " << stats.total_bytes_allocated.load() << std::endl;
    ss << "Current Bytes Allocated: " << stats.current_bytes_allocated.load() << std::endl;
    ss << "Peak Bytes Allocated: " << stats.peak_bytes_allocated.load() << std::endl;
    ss << "Pool Hits: " << stats.pool_hits.load() << std::endl;
    ss << "Pool Misses: " << stats.pool_misses.load() << std::endl;
    ss << "Hit Ratio: " << std::fixed << std::setprecision(2) << (stats.hit_ratio.load() * 100.0) << "%" << std::endl;
    
    error_handler_->info(ss.str(), utils::ErrorCategory::MEMORY, __FUNCTION__, __FILE__, __LINE__);
}

void MemoryPool::set_config(const MemoryPoolConfig& config) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    config_ = config;
}

MemoryPoolConfig MemoryPool::get_config() const {
    return config_;
}

void MemoryPool::enable_compression(bool enable) {
    config_.enable_compression = enable;
}

void MemoryPool::set_compression_threshold(size_t threshold) {
    config_.compression_threshold = threshold;
}

void MemoryPool::enable_statistics(bool enable) {
    config_.enable_statistics = enable;
}

bool MemoryPool::is_address_from_pool(void* address) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return address_to_block_.find(address) != address_to_block_.end();
}

size_t MemoryPool::get_block_size(void* address) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto it = address_to_block_.find(address);
    if (it != address_to_block_.end()) {
        return it->second->size;
    }
    return 0;
}

std::string MemoryPool::get_allocation_type(void* address) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto it = address_to_block_.find(address);
    if (it != address_to_block_.end()) {
        return it->second->allocation_type;
    }
    return "unknown";
}

// Private implementation methods

void MemoryPool::initialize_pool() {
    // Allocate initial pool memory
    void* pool_memory = VirtualAlloc(nullptr, config_.initial_pool_size, 
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pool_memory) {
        error_handler_->error(
            "Failed to allocate initial pool memory",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        return;
    }
    
    // Create initial block
    MemoryBlock initial_block;
    initial_block.address = pool_memory;
    initial_block.size = config_.initial_pool_size;
    initial_block.alignment = 8;
    initial_block.is_allocated = false;
    
    blocks_.push_back(initial_block);
    stats_.start_time = std::chrono::system_clock::now();
    last_cleanup_ = std::chrono::system_clock::now();
}

void MemoryPool::cleanup_pool() {
    // Free all pool memory
    for (auto& block : blocks_) {
        if (block.address) {
            VirtualFree(block.address, 0, MEM_RELEASE);
        }
    }
    blocks_.clear();
    address_to_block_.clear();
}

MemoryBlock* MemoryPool::find_free_block(size_t size, size_t alignment) {
    for (auto& block : blocks_) {
        if (!block.is_allocated && block.size >= size) {
            // Check alignment
            uintptr_t addr = reinterpret_cast<uintptr_t>(block.address);
            if ((addr % alignment) == 0) {
                return &block;
            }
        }
    }
    return nullptr;
}

MemoryBlock* MemoryPool::allocate_new_block(size_t size, size_t alignment) {
    // Calculate required size with alignment
    size_t aligned_size = ((size + alignment - 1) / alignment) * alignment;
    
    // Check if we can grow the pool
    size_t current_total = 0;
    for (const auto& block : blocks_) {
        current_total += block.size;
    }
    
    if (current_total + aligned_size > config_.max_pool_size) {
        error_handler_->warning(
            "Cannot allocate new block: would exceed max pool size",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        return nullptr;
    }
    
    // Allocate new memory
    void* new_memory = VirtualAlloc(nullptr, aligned_size, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!new_memory) {
        error_handler_->error(
            "Failed to allocate new memory block",
            utils::ErrorCategory::MEMORY,
            __FUNCTION__, __FILE__, __LINE__
        );
        return nullptr;
    }
    
    // Create new block
    MemoryBlock new_block;
    new_block.address = new_memory;
    new_block.size = aligned_size;
    new_block.alignment = alignment;
    new_block.is_allocated = false;
    
    blocks_.push_back(new_block);
    return &blocks_.back();
}

void MemoryPool::free_block(MemoryBlock* block) {
    if (!block) {
        return;
    }
    
    block->is_allocated = false;
    block->access_count = 0;
    block->allocation_type.clear();
}

void MemoryPool::update_statistics(const MemoryBlock* block, bool is_allocation) {
    if (!config_.enable_statistics) {
        return;
    }
    
    if (is_allocation) {
        stats_.total_allocations.fetch_add(1);
        stats_.current_allocations.fetch_add(1);
        stats_.total_bytes_allocated.fetch_add(block->size);
        stats_.current_bytes_allocated.fetch_add(block->size);
        
        // Update peaks
        size_t current_allocations = stats_.current_allocations.load();
        size_t current_bytes = stats_.current_bytes_allocated.load();
        
        size_t peak_allocations = stats_.peak_allocations.load();
        size_t peak_bytes = stats_.peak_bytes_allocated.load();
        
        if (current_allocations > peak_allocations) {
            stats_.peak_allocations.store(current_allocations);
        }
        if (current_bytes > peak_bytes) {
            stats_.peak_bytes_allocated.store(current_bytes);
        }
    } else {
        stats_.total_deallocations.fetch_add(1);
        stats_.current_allocations.fetch_sub(1);
        stats_.total_bytes_deallocated.fetch_add(block->size);
        stats_.current_bytes_allocated.fetch_sub(block->size);
    }
}

void MemoryPool::perform_cleanup() {
    auto now = std::chrono::system_clock::now();
    
    // Remove old unused blocks
    blocks_.erase(
        std::remove_if(blocks_.begin(), blocks_.end(),
            [&](const MemoryBlock& block) {
                if (!block.is_allocated) {
                    auto time_since_access = now - block.last_access_time;
                    if (time_since_access > config_.cleanup_interval) {
                        VirtualFree(block.address, 0, MEM_RELEASE);
                        return true;
                    }
                }
                return false;
            }),
        blocks_.end()
    );
}

void MemoryPool::perform_defragmentation() {
    // Sort blocks by address to identify gaps
    std::sort(blocks_.begin(), blocks_.end(),
        [](const MemoryBlock& a, const MemoryBlock& b) {
            return a.address < b.address;
        });
    
    // Merge adjacent free blocks
    for (size_t i = 0; i < blocks_.size() - 1; ++i) {
        if (!blocks_[i].is_allocated && !blocks_[i + 1].is_allocated) {
            // Merge blocks
            blocks_[i].size += blocks_[i + 1].size;
            blocks_.erase(blocks_.begin() + i + 1);
            --i; // Recheck this position
        }
    }
}

void MemoryPool::compress_block(MemoryBlock* block) {
    if (!config_.enable_compression || block->size < config_.compression_threshold) {
        return;
    }
    
    // Implementation would use zlib or similar compression library
    // For now, this is a placeholder
    error_handler_->debug(
        "Compression not implemented in this build",
        utils::ErrorCategory::MEMORY,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void MemoryPool::decompress_block(MemoryBlock* block) {
    if (!config_.enable_compression) {
        return;
    }
    
    // Implementation would use zlib or similar compression library
    // For now, this is a placeholder
    error_handler_->debug(
        "Decompression not implemented in this build",
        utils::ErrorCategory::MEMORY,
        __FUNCTION__, __FILE__, __LINE__
    );
}

size_t MemoryPool::calculate_compressed_size(const void* data, size_t size) const {
    // Placeholder implementation
    return size;
}

void* MemoryPool::compress_data(const void* data, size_t size, size_t& compressed_size) const {
    // Placeholder implementation
    compressed_size = size;
    void* compressed = malloc(size);
    if (compressed) {
        std::memcpy(compressed, data, size);
    }
    return compressed;
}

void* MemoryPool::decompress_data(const void* compressed_data, size_t compressed_size, size_t original_size) const {
    // Placeholder implementation
    void* decompressed = malloc(original_size);
    if (decompressed) {
        std::memcpy(decompressed, compressed_data, std::min(compressed_size, original_size));
    }
    return decompressed;
}

} // namespace UndownUnlock::Optimization 
