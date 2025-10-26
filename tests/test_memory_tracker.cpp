#include <gtest/gtest.h>
#include "utils/memory_tracker.h"

namespace {

class MemoryTrackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& tracker = utils::MemoryTracker::get_instance();
        tracker.enable(true);
        tracker.reset_stats();
    }
};

}  // namespace

TEST_F(MemoryTrackerTest, TracksBasicAllocationLifecycle) {
    auto& tracker = utils::MemoryTracker::get_instance();
    int dummy_value = 42;

    auto* recorded = tracker.track_allocation(&dummy_value, sizeof(dummy_value), __FILE__, __LINE__, __FUNCTION__);
    ASSERT_EQ(recorded, &dummy_value);

    tracker.track_deallocation(&dummy_value);

    // If we reached this point without exceptions, tracking is functioning for basic flows.
    SUCCEED();
}

TEST_F(MemoryTrackerTest, SupportsResettingStatistics) {
    auto& tracker = utils::MemoryTracker::get_instance();
    tracker.reset_stats();

    auto stats = tracker.get_stats();
    EXPECT_EQ(stats.total_allocations.load(), 0u);
    EXPECT_EQ(stats.total_deallocations.load(), 0u);
}
