#include "../../include/optimization/thread_pool.h"
#include "../../include/utils/error_handler.h"
#include "../../include/utils/performance_monitor.h"
#include "../../include/memory_tracker.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

namespace UndownUnlock::Optimization {

namespace {
ThreadPoolStats SnapshotStats(const ThreadPoolStats& source) {
    ThreadPoolStats snapshot;
    snapshot.total_tasks_submitted.store(source.total_tasks_submitted.load());
    snapshot.total_tasks_completed.store(source.total_tasks_completed.load());
    snapshot.total_tasks_failed.store(source.total_tasks_failed.load());
    snapshot.total_tasks_cancelled.store(source.total_tasks_cancelled.load());
    snapshot.current_tasks_queued.store(source.current_tasks_queued.load());
    snapshot.current_tasks_running.store(source.current_tasks_running.load());
    snapshot.current_threads_active.store(source.current_threads_active.load());
    snapshot.current_threads_idle.store(source.current_threads_idle.load());
    snapshot.peak_threads_active.store(source.peak_threads_active.load());
    snapshot.peak_queue_size.store(source.peak_queue_size.load());
    snapshot.average_task_duration_ms.store(source.average_task_duration_ms.load());
    snapshot.throughput_tasks_per_second.store(source.throughput_tasks_per_second.load());
    snapshot.start_time = source.start_time;
    snapshot.last_task_time = source.last_task_time;
    return snapshot;
}

void ResetStats(ThreadPoolStats& stats, const std::chrono::system_clock::time_point& now) {
    stats.total_tasks_submitted.store(0);
    stats.total_tasks_completed.store(0);
    stats.total_tasks_failed.store(0);
    stats.total_tasks_cancelled.store(0);
    stats.current_tasks_queued.store(0);
    stats.current_tasks_running.store(0);
    stats.current_threads_active.store(0);
    stats.current_threads_idle.store(0);
    stats.peak_threads_active.store(0);
    stats.peak_queue_size.store(0);
    stats.average_task_duration_ms.store(0.0);
    stats.throughput_tasks_per_second.store(0.0);
    stats.start_time = now;
    stats.last_task_time = now;
}
} // namespace

// Static member initialization
ThreadPool* ThreadPool::instance_ = nullptr;
std::mutex ThreadPool::instance_mutex_;

ThreadPool::ThreadPool(const ThreadPoolConfig& config)
    : config_(config), stop_flag_(false), pause_flag_(false), 
      active_thread_count_(0), idle_thread_count_(0), task_id_counter_(0) {
    
    // Initialize utility components
    error_handler_ = utils::ErrorHandler::GetInstance();
    performance_monitor_ = utils::PerformanceMonitor::GetInstance();
    memory_tracker_ = &MemoryTracker::GetInstance();
    
    // Set error context
    utils::ErrorContext context;
    context.set("component", "ThreadPool");
    context.set("operation", "initialization");
    error_handler_->set_error_context(context);
    
    error_handler_->info(
        "Initializing Thread Pool with " + std::to_string(config.min_threads) + " to " + std::to_string(config.max_threads) + " threads",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Start performance monitoring
    auto init_operation = performance_monitor_->start_operation("thread_pool_initialization");
    performance_monitor_->end_operation(init_operation);
    
    // Track memory allocation for the pool
    memory_tracker_->TrackAllocation("thread_pool", sizeof(ThreadPool));
    ResetStats(stats_, std::chrono::system_clock::now());
    last_cleanup_ = std::chrono::system_clock::now();
}

ThreadPool::~ThreadPool() {
    error_handler_->info(
        "Shutting down Thread Pool",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    stop();
}

ThreadPool& ThreadPool::get_instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new ThreadPool();
    }
    return *instance_;
}

void ThreadPool::initialize(const ThreadPoolConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new ThreadPool(config);
    } else {
        instance_->set_config(config);
    }
}

void ThreadPool::shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        delete instance_;
        instance_ = nullptr;
    }
}

void ThreadPool::start() {
    if (!worker_threads_.empty()) {
        error_handler_->warning(
            "Thread pool is already running",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        return;
    }
    
    stop_flag_.store(false);
    pause_flag_.store(false);
    
    error_handler_->info(
        "Starting Thread Pool with " + std::to_string(config_.min_threads) + " threads",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Create worker threads
    for (size_t i = 0; i < config_.min_threads; ++i) {
        worker_threads_.emplace_back(&ThreadPool::worker_thread_function, this, i);
    }
    
    active_thread_count_.store(config_.min_threads);
    idle_thread_count_.store(config_.min_threads);
}

void ThreadPool::stop() {
    if (worker_threads_.empty()) {
        return;
    }
    
    error_handler_->info(
        "Stopping Thread Pool",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    // Signal threads to stop
    stop_flag_.store(true);
    condition_.notify_all();
    
    // Wait for all threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    worker_threads_.clear();
    active_thread_count_.store(0);
    idle_thread_count_.store(0);
    
    // Clear task queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!task_queue_.empty()) {
            task_queue_.pop();
        }
        stats_.current_tasks_queued.store(0);
    }
    
    // Clear task registry
    {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        task_registry_.clear();
    }
}

void ThreadPool::pause() {
    pause_flag_.store(true);
    error_handler_->info(
        "Thread Pool paused",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void ThreadPool::resume() {
    pause_flag_.store(false);
    condition_.notify_all();
    error_handler_->info(
        "Thread Pool resumed",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void ThreadPool::resize(size_t new_thread_count) {
    if (new_thread_count < config_.min_threads || new_thread_count > config_.max_threads) {
        error_handler_->warning(
            "Invalid thread count: " + std::to_string(new_thread_count) + 
            " (must be between " + std::to_string(config_.min_threads) + 
            " and " + std::to_string(config_.max_threads) + ")",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        return;
    }
    
    size_t current_count = worker_threads_.size();
    
    if (new_thread_count > current_count) {
        // Add more threads
        for (size_t i = current_count; i < new_thread_count; ++i) {
            worker_threads_.emplace_back(&ThreadPool::worker_thread_function, this, i);
        }
        active_thread_count_.fetch_add(new_thread_count - current_count);
        idle_thread_count_.fetch_add(new_thread_count - current_count);
    } else if (new_thread_count < current_count) {
        // Remove threads (they will exit naturally when stop_flag_ is set)
        // For now, we'll just let them finish naturally
        error_handler_->info(
            "Thread count will be reduced naturally as threads complete their work",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
    
    error_handler_->info(
        "Thread Pool resized to " + std::to_string(new_thread_count) + " threads",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void ThreadPool::cancel_task(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = task_registry_.find(task_id);
    if (it != task_registry_.end()) {
        it->second->status = TaskStatus::CANCELLED;
        stats_.total_tasks_cancelled.fetch_add(1);
        
        error_handler_->info(
            "Task cancelled: " + task_id,
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
}

void ThreadPool::cancel_all_tasks() {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    for (auto& pair : task_registry_) {
        if (pair.second->status == TaskStatus::PENDING) {
            pair.second->status = TaskStatus::CANCELLED;
            stats_.total_tasks_cancelled.fetch_add(1);
        }
    }
    
    error_handler_->info(
        "All pending tasks cancelled",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

bool ThreadPool::is_task_completed(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = task_registry_.find(task_id);
    if (it != task_registry_.end()) {
        return it->second->status == TaskStatus::COMPLETED || 
               it->second->status == TaskStatus::FAILED ||
               it->second->status == TaskStatus::CANCELLED;
    }
    return false;
}

TaskStatus ThreadPool::get_task_status(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = task_registry_.find(task_id);
    if (it != task_registry_.end()) {
        return it->second->status;
    }
    return TaskStatus::PENDING;
}

std::shared_ptr<TaskInfo> ThreadPool::get_task_info(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = task_registry_.find(task_id);
    if (it != task_registry_.end()) {
        return it->second;
    }
    return nullptr;
}

ThreadPoolStats ThreadPool::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    ThreadPoolStats current_stats = SnapshotStats(stats_);
    
    // Calculate throughput
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - current_stats.start_time);
    if (duration.count() > 0) {
        double throughput = static_cast<double>(current_stats.total_tasks_completed.load()) / duration.count();
        current_stats.throughput_tasks_per_second.store(throughput);
    }
    
    return current_stats;
}

void ThreadPool::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ResetStats(stats_, std::chrono::system_clock::now());
}

void ThreadPool::print_stats() const {
    auto stats = get_stats();
    
    std::stringstream ss;
    ss << "=== Thread Pool Statistics ===" << std::endl;
    ss << "Total Tasks Submitted: " << stats.total_tasks_submitted.load() << std::endl;
    ss << "Total Tasks Completed: " << stats.total_tasks_completed.load() << std::endl;
    ss << "Total Tasks Failed: " << stats.total_tasks_failed.load() << std::endl;
    ss << "Total Tasks Cancelled: " << stats.total_tasks_cancelled.load() << std::endl;
    ss << "Current Tasks Queued: " << stats.current_tasks_queued.load() << std::endl;
    ss << "Current Tasks Running: " << stats.current_tasks_running.load() << std::endl;
    ss << "Current Threads Active: " << stats.current_threads_active.load() << std::endl;
    ss << "Current Threads Idle: " << stats.current_threads_idle.load() << std::endl;
    ss << "Peak Threads Active: " << stats.peak_threads_active.load() << std::endl;
    ss << "Peak Queue Size: " << stats.peak_queue_size.load() << std::endl;
    ss << "Average Task Duration: " << std::fixed << std::setprecision(2) << stats.average_task_duration_ms.load() << "ms" << std::endl;
    ss << "Throughput: " << std::fixed << std::setprecision(2) << stats.throughput_tasks_per_second.load() << " tasks/sec" << std::endl;
    
    error_handler_->info(ss.str(), utils::ErrorCategory::SYSTEM, __FUNCTION__, __FILE__, __LINE__);
}

void ThreadPool::set_config(const ThreadPoolConfig& config) {
    config_ = config;
}

ThreadPoolConfig ThreadPool::get_config() const {
    return config_;
}

size_t ThreadPool::get_thread_count() const {
    return worker_threads_.size();
}

size_t ThreadPool::get_queue_size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return task_queue_.size();
}

bool ThreadPool::is_running() const {
    return !worker_threads_.empty() && !stop_flag_.load();
}

bool ThreadPool::is_paused() const {
    return pause_flag_.load();
}

// Private implementation methods

void ThreadPool::worker_thread_function(size_t thread_id) {
    // Set thread name for debugging
    std::string thread_name = config_.thread_name_prefix + "_" + std::to_string(thread_id);
    
    // Set error context
    utils::ErrorContext context;
    context.set("component", "ThreadPool");
    context.set("operation", "worker_thread");
    context.set("thread_id", std::to_string(thread_id));
    context.set("thread_name", thread_name);
    error_handler_->set_error_context(context);
    
    error_handler_->debug(
        "Worker thread started: " + thread_name,
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
    
    while (!stop_flag_.load()) {
        PrioritizedTask task(nullptr, TaskPriority::NORMAL, "", "");
        bool has_task = false;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for task or stop signal
            condition_.wait(lock, [this] {
                return stop_flag_.load() || (!task_queue_.empty() && !pause_flag_.load());
            });
            
            if (stop_flag_.load()) {
                break;
            }
            
            if (!task_queue_.empty() && !pause_flag_.load()) {
                task = std::move(const_cast<PrioritizedTask&>(task_queue_.top()));
                task_queue_.pop();
                has_task = true;
                
                stats_.current_tasks_queued.fetch_sub(1);
                stats_.current_tasks_running.fetch_add(1);
                active_thread_count_.fetch_add(1);
                idle_thread_count_.fetch_sub(1);
                
                if (active_thread_count_.load() > stats_.peak_threads_active.load()) {
                    stats_.peak_threads_active.store(active_thread_count_.load());
                }
            }
        }
        
        if (has_task) {
            // Register task
            {
                std::lock_guard<std::mutex> lock(registry_mutex_);
                task_registry_[task.task_id] = task.task_info;
            }
            
            // Process the task
            process_task(task);
            
            // Update statistics
            active_thread_count_.fetch_sub(1);
            idle_thread_count_.fetch_add(1);
            stats_.current_tasks_running.fetch_sub(1);
        }
    }
    
    error_handler_->debug(
        "Worker thread stopped: " + thread_name,
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

void ThreadPool::process_task(PrioritizedTask& task) {
    // Set error context
    utils::ErrorContext context;
    context.set("component", "ThreadPool");
    context.set("operation", "process_task");
    context.set("task_id", task.task_id);
    context.set("task_name", task.task_name);
    error_handler_->set_error_context(context);
    
    // Start performance monitoring
    auto task_operation = performance_monitor_->start_operation("thread_pool_task_execution");
    
    // Update task info
    task.task_info->status = TaskStatus::RUNNING;
    task.task_info->start_time = std::chrono::system_clock::now();
    task.task_info->worker_thread_id = std::this_thread::get_id();
    
    log_task_event(task.task_id, "started", "Task execution began");
    
    try {
        // Execute the task
        task.task();
        
        // Task completed successfully
        task.task_info->status = TaskStatus::COMPLETED;
        task.task_info->end_time = std::chrono::system_clock::now();
        task.task_info->duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            task.task_info->end_time - task.task_info->start_time
        );
        
        stats_.total_tasks_completed.fetch_add(1);
        update_statistics(*task.task_info, true);
        
        log_task_event(task.task_id, "completed", "Task executed successfully");
        
        error_handler_->debug(
            "Task completed: " + task.task_id + " in " + std::to_string(task.task_info->duration.count()) + "ms",
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
        
    } catch (const std::exception& e) {
        // Task failed
        task.task_info->status = TaskStatus::FAILED;
        task.task_info->end_time = std::chrono::system_clock::now();
        task.task_info->duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            task.task_info->end_time - task.task_info->start_time
        );
        task.task_info->error_message = e.what();
        
        stats_.total_tasks_failed.fetch_add(1);
        update_statistics(*task.task_info, true);
        
        log_task_event(task.task_id, "failed", "Task failed with exception: " + std::string(e.what()));
        
        error_handler_->error(
            "Task failed: " + task.task_id + " - " + std::string(e.what()),
            utils::ErrorCategory::SYSTEM,
            __FUNCTION__, __FILE__, __LINE__
        );
    }
    
    performance_monitor_->end_operation(task_operation);
    
    // Clean up completed tasks periodically
    auto now = std::chrono::system_clock::now();
    if (now - last_cleanup_ > std::chrono::seconds(30)) {
        cleanup_completed_tasks();
        last_cleanup_ = now;
    }
}

void ThreadPool::update_statistics(const TaskInfo& task_info, bool is_completion) {
    if (!config_.enable_statistics) {
        return;
    }
    
    if (is_completion) {
        // Update average task duration
        double current_avg = stats_.average_task_duration_ms.load();
        size_t completed_count = stats_.total_tasks_completed.load();
        
        if (completed_count > 0) {
            double new_avg = (current_avg * (completed_count - 1) + task_info.duration.count()) / completed_count;
            stats_.average_task_duration_ms.store(new_avg);
        }
        
        stats_.last_task_time = std::chrono::system_clock::now();
    }
}

void ThreadPool::cleanup_completed_tasks() {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    auto it = task_registry_.begin();
    while (it != task_registry_.end()) {
        if (it->second->status == TaskStatus::COMPLETED || 
            it->second->status == TaskStatus::FAILED ||
            it->second->status == TaskStatus::CANCELLED) {
            it = task_registry_.erase(it);
        } else {
            ++it;
        }
    }
}

void ThreadPool::adjust_thread_count() {
    // This would implement dynamic thread scaling based on queue size and system load
    // For now, it's a placeholder
    error_handler_->debug(
        "Thread count adjustment not implemented in this build",
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

std::string ThreadPool::generate_task_id() {
    static std::atomic<size_t> counter{0};
    size_t id = counter.fetch_add(1);
    return "task_" + std::to_string(id) + "_" + std::to_string(task_id_counter_.fetch_add(1));
}

void ThreadPool::log_task_event(const std::string& task_id, const std::string& event, const std::string& details) {
    error_handler_->debug(
        "Task event: " + task_id + " - " + event + (details.empty() ? "" : " - " + details),
        utils::ErrorCategory::SYSTEM,
        __FUNCTION__, __FILE__, __LINE__
    );
}

} // namespace UndownUnlock::Optimization 
