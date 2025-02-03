#include "onion/io_context.hpp"

#include <doctest/doctest.h>

#include <mutex>
#include <set>

using namespace onion;

TEST_CASE("[IoContext] Dispatch with worker ID") {
    IoContext ctx;

    std::mutex mutex;
    std::set<std::size_t> idSet;

    const auto taskWithWorkerId = [&](std::size_t id) noexcept -> Task<> {
        std::lock_guard<std::mutex> lock{mutex};
        CHECK(idSet.find(id) == idSet.end());
        CHECK(idSet.insert(id).second);
        if (idSet.size() == ctx.size())
            ctx.stop();
        co_return;
    };

    ctx.dispatch(taskWithWorkerId);
    ctx.start();

    CHECK(idSet.size() == ctx.size());
    for (std::size_t i = 0; i < ctx.size(); ++i)
        CHECK(idSet.find(i) != idSet.end());
}
