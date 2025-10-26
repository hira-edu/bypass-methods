#pragma once

#include "utils/memory_tracker.h"

#include <string>
#include <utility>
#include <vector>

namespace UndownUnlock {

/**
 * Compatibility wrapper around utils::MemoryTracker that mirrors the legacy API
 * used throughout the hooking layer and unit tests.
 */
class MemoryTracker {
public:
    using AllocationRecord = Utils::NamedAllocationRecord;

    class AllocationGuard {
    public:
        AllocationGuard();
        AllocationGuard(Utils::MemoryTracker* tracker, std::string name, size_t size, bool auto_release);
        AllocationGuard(AllocationGuard&& other) noexcept;
        AllocationGuard& operator=(AllocationGuard&& other) noexcept;
        AllocationGuard(const AllocationGuard&) = delete;
        AllocationGuard& operator=(const AllocationGuard&) = delete;
        ~AllocationGuard();

        void Release();

    private:
        void cleanup();

        Utils::MemoryTracker* tracker_;
        std::string name_;
        size_t size_;
        bool auto_release_;
        bool released_;
    };

    explicit MemoryTracker(std::string category = "");

    AllocationGuard TrackAllocation(const std::string& resource, size_t size) const;
    void TrackDeallocation(const std::string& resource, size_t size = 0) const;

    static MemoryTracker& GetInstance();
    static void Initialize();
    static void Shutdown();
    static bool IsInitialized();
    static void Reset();
    static std::vector<AllocationRecord> GetAllocations();
    static std::vector<AllocationRecord> GetLeaks();
    static size_t GetTotalAllocated();

private:
    std::string prefix_;

    std::string make_allocation_name(const std::string& resource) const;
    static bool IsGlobalInstance(const MemoryTracker* instance);
};

// ===== Inline implementations =====

inline MemoryTracker::MemoryTracker(std::string category)
    : prefix_(std::move(category)) {}

inline std::string MemoryTracker::make_allocation_name(const std::string& resource) const {
    if (prefix_.empty()) {
        return resource;
    }
    if (resource.empty()) {
        return prefix_;
    }
    return prefix_ + "::" + resource;
}

inline bool MemoryTracker::IsGlobalInstance(const MemoryTracker* instance) {
    return instance == &GetInstance();
}

inline MemoryTracker::AllocationGuard MemoryTracker::TrackAllocation(
    const std::string& resource, size_t size) const {
    auto& tracker = Utils::MemoryTracker::get_instance();
    auto name = make_allocation_name(resource);
    tracker.track_named_allocation(name, size);
    bool auto_release = IsGlobalInstance(this);
    return AllocationGuard(&tracker, std::move(name), size, auto_release);
}

inline void MemoryTracker::TrackDeallocation(
    const std::string& resource, size_t size) const {
    Utils::MemoryTracker::get_instance().track_named_deallocation(
        make_allocation_name(resource), size);
}

inline MemoryTracker& MemoryTracker::GetInstance() {
    static MemoryTracker global_tracker("GlobalMemoryTracker");
    return global_tracker;
}

inline void MemoryTracker::Initialize() {
    Utils::MemoryTracker::Initialize();
}

inline void MemoryTracker::Shutdown() {
    Utils::MemoryTracker::Shutdown();
}

inline bool MemoryTracker::IsInitialized() {
    return Utils::MemoryTracker::IsInitialized();
}

inline void MemoryTracker::Reset() {
    Utils::MemoryTracker::GetInstance()->Reset();
}

inline std::vector<MemoryTracker::AllocationRecord> MemoryTracker::GetAllocations() {
    return Utils::MemoryTracker::get_instance().get_named_allocations();
}

inline std::vector<MemoryTracker::AllocationRecord> MemoryTracker::GetLeaks() {
    return Utils::MemoryTracker::get_instance().get_active_named_allocations();
}

inline size_t MemoryTracker::GetTotalAllocated() {
    return Utils::MemoryTracker::get_instance().get_total_named_bytes();
}

inline MemoryTracker::AllocationGuard::AllocationGuard()
    : tracker_(nullptr),
      size_(0),
      auto_release_(false),
      released_(true) {}

inline MemoryTracker::AllocationGuard::AllocationGuard(
    Utils::MemoryTracker* tracker, std::string name, size_t size, bool auto_release)
    : tracker_(tracker),
      name_(std::move(name)),
      size_(size),
      auto_release_(auto_release),
      released_(false) {}

inline MemoryTracker::AllocationGuard::AllocationGuard(AllocationGuard&& other) noexcept
    : tracker_(other.tracker_),
      name_(std::move(other.name_)),
      size_(other.size_),
      auto_release_(other.auto_release_),
      released_(other.released_) {
    other.tracker_ = nullptr;
    other.released_ = true;
}

inline MemoryTracker::AllocationGuard& MemoryTracker::AllocationGuard::operator=(
    AllocationGuard&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    cleanup();
    tracker_ = other.tracker_;
    name_ = std::move(other.name_);
    size_ = other.size_;
    auto_release_ = other.auto_release_;
    released_ = other.released_;
    other.tracker_ = nullptr;
    other.released_ = true;
    return *this;
}

inline MemoryTracker::AllocationGuard::~AllocationGuard() {
    cleanup();
}

inline void MemoryTracker::AllocationGuard::Release() {
    released_ = true;
}

inline void MemoryTracker::AllocationGuard::cleanup() {
    if (tracker_ && auto_release_ && !released_) {
        tracker_->track_named_deallocation(name_, size_);
    }
    tracker_ = nullptr;
    released_ = true;
}

} // namespace UndownUnlock
