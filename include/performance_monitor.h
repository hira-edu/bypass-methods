#pragma once

#include "utils/performance_monitor.h"

#include <chrono>
#include <string>
#include <unordered_map>
#include <utility>

namespace UndownUnlock {

/**
 * Lightweight compatibility wrapper around utils::PerformanceMonitor to
 * mirror the legacy API that the hooking/tests expect.
 */
class PerformanceMonitor {
public:
    class Timer {
    public:
        Timer(const std::string& metric_name, const std::string& label);
        Timer(Timer&&) noexcept = default;
        Timer& operator=(Timer&&) noexcept = default;
        Timer(const Timer&) = delete;
        Timer& operator=(const Timer&) = delete;

        void Stop();
        double GetElapsedTime() const;

    private:
        std::string metric_name_;
        std::string label_;
        std::chrono::high_resolution_clock::time_point start_time_;
        std::chrono::high_resolution_clock::time_point end_time_;
        bool stopped_;
    };

    explicit PerformanceMonitor(std::string category = "");

    Timer StartTimer(const std::string& operation, const std::string& label = "") const;
    void RecordOperation(const std::string& operation, double duration_ms) const;
    void RecordOperation(const std::string& operation, const Timer& timer) const;

    static Utils::PerformanceMonitor& GetInstance();
    static void Initialize();
    static void Shutdown();
    static bool IsInitialized();
    static void Reset();
    static Utils::TimerStats GetTimerStats(const std::string& name);
    static std::unordered_map<std::string, Utils::TimerStats> GetAllStats();

private:
    std::string prefix_;

    std::string make_metric_name(const std::string& operation) const;
};

// ===== Inline implementations =====

inline PerformanceMonitor::PerformanceMonitor(std::string category)
    : prefix_(std::move(category)) {}

inline std::string PerformanceMonitor::make_metric_name(const std::string& operation) const {
    if (prefix_.empty()) {
        return operation;
    }
    if (operation.empty()) {
        return prefix_;
    }
    return prefix_ + "::" + operation;
}

inline PerformanceMonitor::Timer PerformanceMonitor::StartTimer(
    const std::string& operation, const std::string& label) const {
    return Timer(make_metric_name(operation), label);
}

inline void PerformanceMonitor::RecordOperation(
    const std::string& operation, double duration_ms) const {
    Utils::PerformanceMonitor::get_instance().record_timing_sample(
        make_metric_name(operation), duration_ms, prefix_);
}

inline void PerformanceMonitor::RecordOperation(
    const std::string& operation, const Timer& timer) const {
    RecordOperation(operation, timer.GetElapsedTime());
}

inline Utils::PerformanceMonitor& PerformanceMonitor::GetInstance() {
    return Utils::PerformanceMonitor::get_instance();
}

inline void PerformanceMonitor::Initialize() {
    Utils::PerformanceMonitor::Initialize();
}

inline void PerformanceMonitor::Shutdown() {
    Utils::PerformanceMonitor::Shutdown();
}

inline bool PerformanceMonitor::IsInitialized() {
    return Utils::PerformanceMonitor::get_instance().is_initialized();
}

inline void PerformanceMonitor::Reset() {
    Utils::PerformanceMonitor::GetInstance()->Reset();
}

inline Utils::TimerStats PerformanceMonitor::GetTimerStats(const std::string& name) {
    return Utils::PerformanceMonitor::get_instance().GetTimerStats(name);
}

inline std::unordered_map<std::string, Utils::TimerStats> PerformanceMonitor::GetAllStats() {
    return Utils::PerformanceMonitor::get_instance().GetAllStats();
}

inline PerformanceMonitor::Timer::Timer(const std::string& metric_name, const std::string& label)
    : metric_name_(metric_name),
      label_(label),
      start_time_(std::chrono::high_resolution_clock::now()),
      end_time_(start_time_),
      stopped_(false) {}

inline void PerformanceMonitor::Timer::Stop() {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    end_time_ = std::chrono::high_resolution_clock::now();
}

inline double PerformanceMonitor::Timer::GetElapsedTime() const {
    auto end = stopped_ ? end_time_ : std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start_time_).count();
}

} // namespace UndownUnlock
