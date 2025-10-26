#include <gtest/gtest.h>
#include <string>
#include "utils/performance_monitor.h"

TEST(PerformanceMonitorTest, RecordsCounterSamples) {
    auto& monitor = utils::PerformanceMonitor::get_instance();
    monitor.enable(true);

    monitor.record_counter("unittest_counter", 1.0);
    monitor.record_counter("unittest_counter", 2.0);

    auto stats = monitor.get_metric_stats("unittest_counter");
    EXPECT_GE(stats.sample_count, 2u);
    EXPECT_LE(stats.min_value, stats.max_value);
}

TEST(PerformanceMonitorTest, ProvidesMetricSummaryString) {
    auto& monitor = utils::PerformanceMonitor::get_instance();
    monitor.record_gauge("unittest_gauge", 5.0);

    auto summary = monitor.get_metric_summary_string();
    EXPECT_FALSE(summary.empty());
}
