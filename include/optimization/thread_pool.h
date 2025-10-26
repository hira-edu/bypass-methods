#pragma once

#include <windows.h>
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <future>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <string>
#include <chrono>
#include <unordered_map>

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
 * Task priority levels
 */
enum class TaskPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

/**
 * Task status
 */
enum class TaskStatus {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    FAILED = 3,
    CANCELLED = 4
};

/**
 * Thread pool configuration
 */
struct ThreadPoolConfig {
    size_t min_threads = 2;
    size_t max_threads = 16;
    size_t idle_timeout_ms = 30000; // 30 seconds
    size_t max_queue_size = 1000;
    bool enable_work_stealing = true;
    bool enable_task_prioritization = true;
    bool enable_statistics = true;
    std::string thread_name_prefix = "ThreadPool";
    
    ThreadPoolConfig() = default;
};

/**
 * Task information
 */
struct TaskInfo {
    std::string id;
    std::string name;
    std::string description;
    TaskPriority priority;
    TaskStatus status;
    std::chrono::system_clock::time_point created_time;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::milliseconds duration;
    std::string error_message;
    size_t retry_count;
    size_t max_retries;
    std::thread::id worker_thread_id;
    
    TaskInfo() : priority(TaskPriority::NORMAL), status(TaskStatus::PENDING),
                 retry_count(0), max_retries(0) {}
};

/**
 * Thread pool statistics
 */
struct ThreadPoolStats {
    std::atomic<size_t> total_tasks_submitted;
    std::atomic<size_t> total_tasks_completed;
    std::atomic<size_t> total_tasks_failed;
    std::atomic<size_t> total_tasks_cancelled;
    std::atomic<size_t> current_tasks_queued;
    std::atomic<size_t> current_tasks_running;
    std::atomic<size_t> current_threads_active;
    std::atomic<size_t> current_threads_idle;
    std::atomic<size_t> peak_threads_active;
    std::atomic<size_t> peak_queue_size;
    std::atomic<double> average_task_duration_ms;
    std::atomic<double> throughput_tasks_per_second;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_task_time;
    
    ThreadPoolStats()
        : total_tasks_submitted(0),
          total_tasks_completed(0),
          total_tasks_failed(0),
          total_tasks_cancelled(0),
          current_tasks_queued(0),
          current_tasks_running(0),
          current_threads_active(0),
          current_threads_idle(0),
          peak_threads_active(0),
          peak_queue_size(0),
          average_task_duration_ms(0.0),
          throughput_tasks_per_second(0.0) {}

    ThreadPoolStats(const ThreadPoolStats& other)
        : total_tasks_submitted(other.total_tasks_submitted.load()),
          total_tasks_completed(other.total_tasks_completed.load()),
          total_tasks_failed(other.total_tasks_failed.load()),
          total_tasks_cancelled(other.total_tasks_cancelled.load()),
          current_tasks_queued(other.current_tasks_queued.load()),
          current_tasks_running(other.current_tasks_running.load()),
          current_threads_active(other.current_threads_active.load()),
          current_threads_idle(other.current_threads_idle.load()),
          peak_threads_active(other.peak_threads_active.load()),
          peak_queue_size(other.peak_queue_size.load()),
          average_task_duration_ms(other.average_task_duration_ms.load()),
          throughput_tasks_per_second(other.throughput_tasks_per_second.load()),
          start_time(other.start_time),
          last_task_time(other.last_task_time) {}

    ThreadPoolStats& operator=(const ThreadPoolStats& other) {
        if (this != &other) {
            total_tasks_submitted.store(other.total_tasks_submitted.load());
            total_tasks_completed.store(other.total_tasks_completed.load());
            total_tasks_failed.store(other.total_tasks_failed.load());
            total_tasks_cancelled.store(other.total_tasks_cancelled.load());
            current_tasks_queued.store(other.current_tasks_queued.load());
            current_tasks_running.store(other.current_tasks_running.load());
            current_threads_active.store(other.current_threads_active.load());
            current_threads_idle.store(other.current_threads_idle.load());
            peak_threads_active.store(other.peak_threads_active.load());
            peak_queue_size.store(other.peak_queue_size.load());
            average_task_duration_ms.store(other.average_task_duration_ms.load());
            throughput_tasks_per_second.store(other.throughput_tasks_per_second.load());
            start_time = other.start_time;
            last_task_time = other.last_task_time;
        }
        return *this;
    }
};

/**
 * Task wrapper with priority
 */
struct PrioritizedTask {
    std::function<void()> task;
    TaskPriority priority;
    std::chrono::system_clock::time_point submission_time;
    std::string task_id;
    std::string task_name;
    std::promise<void> promise;
    std::shared_ptr<TaskInfo> task_info;
    
    PrioritizedTask(std::function<void()> t, TaskPriority p, const std::string& id, const std::string& name)
        : task(std::move(t)), priority(p), submission_time(std::chrono::system_clock::now()),
          task_id(id), task_name(name), task_info(std::make_shared<TaskInfo>()) {
        task_info->id = id;
        task_info->name = name;
        task_info->priority = p;
        task_info->created_time = submission_time;
    }
    
    bool operator<(const PrioritizedTask& other) const {
        return static_cast<int>(priority) < static_cast<int>(other.priority);
    }
};

class TaskBuilder;

/**
 * Thread pool for efficient task execution
 */
class ThreadPool {
public:
    explicit ThreadPool(const ThreadPoolConfig& config = ThreadPoolConfig());
    ~ThreadPool();
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    
    // Singleton access
    static ThreadPool& get_instance();
    static void initialize(const ThreadPoolConfig& config = ThreadPoolConfig());
    static void shutdown();
    
    // Task submission methods
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    template<typename F, typename... Args>
    auto submit_priority(TaskPriority priority, F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    template<typename F, typename... Args>
    auto submit_with_id(const std::string& task_id, const std::string& task_name, F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    // Task management
    void cancel_task(const std::string& task_id);
    void cancel_all_tasks();
    bool is_task_completed(const std::string& task_id) const;
    TaskStatus get_task_status(const std::string& task_id) const;
    std::shared_ptr<TaskInfo> get_task_info(const std::string& task_id) const;
    
    // Thread pool management
    void start();
    void stop();
    void pause();
    void resume();
    void resize(size_t new_thread_count);
    
    // Statistics and monitoring
    ThreadPoolStats get_stats() const;
    void reset_stats();
    void print_stats() const;
    
    // Configuration
    void set_config(const ThreadPoolConfig& config);
    ThreadPoolConfig get_config() const;
    
    // Utility methods
    size_t get_thread_count() const;
    size_t get_queue_size() const;
    bool is_running() const;
    bool is_paused() const;
    
private:
    friend class TaskBuilder;
    // Internal methods
    void worker_thread_function(size_t thread_id);
    void process_task(PrioritizedTask& task);
    void update_statistics(const TaskInfo& task_info, bool is_completion);
    void cleanup_completed_tasks();
    void adjust_thread_count();
    std::string generate_task_id();
    void log_task_event(const std::string& task_id, const std::string& event, const std::string& details = "");
    
    // Member variables
    static ThreadPool* instance_;
    static std::mutex instance_mutex_;
    
    ThreadPoolConfig config_;
    std::vector<std::thread> worker_threads_;
    std::priority_queue<PrioritizedTask> task_queue_;
    std::unordered_map<std::string, std::shared_ptr<TaskInfo>> task_registry_;
    
    mutable std::mutex queue_mutex_;
    mutable std::mutex registry_mutex_;
    mutable std::mutex stats_mutex_;
    
    std::condition_variable condition_;
    std::atomic<bool> stop_flag_;
    std::atomic<bool> pause_flag_;
    std::atomic<size_t> active_thread_count_;
    std::atomic<size_t> idle_thread_count_;
    
    ThreadPoolStats stats_;
    std::chrono::system_clock::time_point last_cleanup_;
    std::atomic<size_t> task_id_counter_;
    
    // Performance monitoring
    ErrorHandler* error_handler_;
    PerformanceMonitor* performance_monitor_;
    MemoryTracker* memory_tracker_;
};

/**
 * Task builder for fluent API
 */
class TaskBuilder {
public:
    explicit TaskBuilder(ThreadPool& pool) : pool_(pool), priority_(TaskPriority::NORMAL) {}
    
    TaskBuilder& with_priority(TaskPriority priority) {
        priority_ = priority;
        return *this;
    }
    
    TaskBuilder& with_id(const std::string& id) {
        task_id_ = id;
        return *this;
    }
    
    TaskBuilder& with_name(const std::string& name) {
        task_name_ = name;
        return *this;
    }
    
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        if (task_id_.empty()) {
            task_id_ = pool_.generate_task_id();
        }
        if (task_name_.empty()) {
            task_name_ = "Task_" + task_id_;
        }
        
        return pool_.submit_with_id(task_id_, task_name_, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
private:
    ThreadPool& pool_;
    TaskPriority priority_;
    std::string task_id_;
    std::string task_name_;
};

/**
 * Thread pool utilities
 */
namespace ThreadPoolUtils {
    
    // Get thread pool instance
    inline ThreadPool& get_pool() {
        return ThreadPool::get_instance();
    }
    
    // Submit a simple task
    template<typename F, typename... Args>
    auto submit_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        return get_pool().submit(std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    // Submit a high priority task
    template<typename F, typename... Args>
    auto submit_urgent_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        return get_pool().submit_priority(TaskPriority::HIGH, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    // Submit a background task
    template<typename F, typename... Args>
    auto submit_background_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
        return get_pool().submit_priority(TaskPriority::LOW, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    // Create a task builder
    inline TaskBuilder create_task() {
        return TaskBuilder(get_pool());
    }
    
    // Get pool statistics
    inline ThreadPoolStats get_pool_stats() {
        return get_pool().get_stats();
    }
    
    // Wait for all tasks to complete
    inline void wait_for_all() {
        // This would need to be implemented in the ThreadPool class
        // For now, just wait a bit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Check if pool is busy
    inline bool is_pool_busy() {
        auto stats = get_pool_stats();
        return stats.current_tasks_queued.load() > 0 || stats.current_tasks_running.load() > 0;
    }
}

// Template implementation for task submission
template<typename F, typename... Args>
auto ThreadPool::submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    return submit_priority(TaskPriority::NORMAL, std::forward<F>(f), std::forward<Args>(args)...);
}

template<typename F, typename... Args>
auto ThreadPool::submit_priority(TaskPriority priority, F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using ReturnType = typename std::result_of<F(Args...)>::type;
    
    auto task_id = generate_task_id();
    auto task_name = "Task_" + task_id;
    
    auto task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    std::future<ReturnType> future = task->get_future();
    
    PrioritizedTask prioritized_task(
        [task]() { (*task)(); },
        priority,
        task_id,
        task_name
    );
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        if (task_queue_.size() >= config_.max_queue_size) {
            error_handler_->warning(
                "Task queue is full, dropping task: " + task_id,
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            return std::future<ReturnType>();
        }
        
        task_queue_.push(std::move(prioritized_task));
        stats_.current_tasks_queued.fetch_add(1);
        stats_.total_tasks_submitted.fetch_add(1);
        
        if (stats_.current_tasks_queued.load() > stats_.peak_queue_size.load()) {
            stats_.peak_queue_size.store(stats_.current_tasks_queued.load());
        }
    }
    
    condition_.notify_one();
    return future;
}

template<typename F, typename... Args>
auto ThreadPool::submit_with_id(const std::string& task_id, const std::string& task_name, F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using ReturnType = typename std::result_of<F(Args...)>::type;
    
    auto task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    std::future<ReturnType> future = task->get_future();
    
    PrioritizedTask prioritized_task(
        [task]() { (*task)(); },
        TaskPriority::NORMAL,
        task_id,
        task_name
    );
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        if (task_queue_.size() >= config_.max_queue_size) {
            error_handler_->warning(
                "Task queue is full, dropping task: " + task_id,
                utils::ErrorCategory::SYSTEM,
                __FUNCTION__, __FILE__, __LINE__
            );
            return std::future<ReturnType>();
        }
        
        task_queue_.push(std::move(prioritized_task));
        stats_.current_tasks_queued.fetch_add(1);
        stats_.total_tasks_submitted.fetch_add(1);
        
        if (stats_.current_tasks_queued.load() > stats_.peak_queue_size.load()) {
            stats_.peak_queue_size.store(stats_.current_tasks_queued.load());
        }
    }
    
    condition_.notify_one();
    return future;
}

} // namespace UndownUnlock::Optimization 
