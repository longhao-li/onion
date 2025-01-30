#include "onion/scheduler.hpp"

#include <doctest/doctest.h>

#include <set>

using namespace onion;

TEST_CASE("[Scheduler] Dispatch with worker ID") {
    Scheduler scheduler;
    std::mutex mutex;
    std::set<std::size_t> idSet;

    const auto taskWithWorkerId = [&](std::size_t id) noexcept -> Task<> {
        std::lock_guard<std::mutex> lock{mutex};
        CHECK(idSet.find(id) == idSet.end());
        CHECK(idSet.insert(id).second);
        if (idSet.size() == scheduler.size())
            scheduler.stop();
        co_return;
    };

    scheduler.dispatch(taskWithWorkerId);
    scheduler.start();

    CHECK(idSet.size() == scheduler.size());
    for (std::size_t i = 0; i < scheduler.size(); ++i)
        CHECK(idSet.find(i) != idSet.end());
}
