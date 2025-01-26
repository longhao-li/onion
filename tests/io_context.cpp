#include "onion/io_context.hpp"

#include <doctest/doctest.h>

#include <chrono>
#include <mutex>
#include <set>
#include <tuple>

using namespace onion;
using namespace std::chrono_literals;

TEST_CASE("[task] coroutine context switch") {
    io_context ctx;

    const int value = 42;

    auto task3 = []() -> task<> { co_return; };

    auto task2 = [&]() -> task<const int &> {
        co_await task3();
        co_return value;
    };

    auto task1 = [&]() -> task<std::string> {
        const int &v = co_await task2();
        CHECK(v == 42);
        co_return "Hello, World!";
    };

    auto task0 = [&]() -> task<> {
        std::string str = co_await task1();
        CHECK(str == "Hello, World!");

        int v = co_await task2();
        CHECK(v == 42);

        str = co_await task1();
        CHECK(str == "Hello, World!");

        ctx.stop();
    };

    ctx.schedule(task0());
    ctx.run();
}

TEST_CASE("[task] manually control") {
    auto manual_task = []() -> task<int> { co_return 42; };

    auto task = manual_task();
    CHECK(task);
    CHECK(!task.done());

    task.coroutine().resume();
    CHECK(task.done());
    CHECK(std::move(task.promise()).result() == 42);
}

TEST_CASE("[task] manual exception control") {
    int dummy = 42;

    auto int_exception_task = []() -> task<int> {
        throw std::runtime_error("Manual exception");
        co_return 42;
    };

    auto int_ref_exception_task = [&]() -> task<int &> {
        throw std::runtime_error("Manual exception");
        co_return dummy;
    };

    auto void_exception_task = []() -> task<> {
        throw std::runtime_error("Manual exception");
        co_return;
    };

    auto int_task = int_exception_task();
    CHECK(int_task);
    CHECK(!int_task.done());

    int_task.coroutine().resume();
    CHECK(int_task.done());
    CHECK_THROWS_AS(std::ignore = std::move(int_task.promise()).result(), std::runtime_error);

    auto int_ref_task = int_ref_exception_task();
    CHECK(int_ref_task);
    CHECK(!int_ref_task.done());

    int_ref_task.coroutine().resume();
    CHECK(int_ref_task.done());
    CHECK_THROWS_AS(std::ignore = int_ref_task.promise().result(), std::runtime_error);

    auto void_task = void_exception_task();
    CHECK(void_task);
    CHECK(!void_task.done());

    void_task.coroutine().resume();
    CHECK(void_task.done());
    CHECK_THROWS_AS(void_task.promise().result(), std::runtime_error);
}

TEST_CASE("[task] yielding") {
    io_context ctx;

    auto task = [&]() -> onion::task<> {
        for (std::size_t i = 0; i < 2000; ++i)
            co_await yield();

        ctx.stop();
        co_return;
    };

    ctx.schedule(task());
    ctx.run();
}

TEST_CASE("[task] sleeping") {
    io_context ctx;

    auto task = [&]() -> onion::task<> {
        for (std::size_t i = 0; i < 3; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(200ms);
            auto end = std::chrono::high_resolution_clock::now();

            CHECK(end - start >= 200ms);
        }

        {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(1s);
            auto end = std::chrono::high_resolution_clock::now();

            CHECK(end - start >= 1s);
        }

        for (std::size_t i = 0; i < 3; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(-1s);
            auto end = std::chrono::high_resolution_clock::now();

            CHECK(end - start >= 0s);
        }

        ctx.stop();
    };

    ctx.schedule(task());
    ctx.run();
}

TEST_CASE("[io_context_pool] dispatch with context ID") {
    io_context_pool       pool;
    std::mutex            mutex;
    std::set<std::size_t> id_set;

    const auto task_with_context_id = [&](std::size_t id) -> task<> {
        std::lock_guard<std::mutex> lock{mutex};
        CHECK(id_set.find(id) == id_set.end());
        CHECK(id_set.insert(id).second);
        if (id_set.size() == pool.size())
            pool.stop();
        co_return;
    };

    pool.dispatch(task_with_context_id);
    pool.run();

    CHECK(id_set.size() == pool.size());
    for (std::size_t i = 0; i < pool.size(); ++i)
        CHECK(id_set.find(i) != id_set.end());
}
