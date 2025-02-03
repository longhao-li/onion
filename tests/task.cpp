#include "onion/io_context.hpp"

#include <doctest/doctest.h>

#include <chrono>
#include <tuple>

using namespace onion;
using namespace std::chrono_literals;

TEST_CASE("[Task] Coroutine context switch") {
    IoContext ctx{0};
    const int value = 42;

    auto task3 = []() -> Task<> { co_return; };

    auto task2 = [&]() -> Task<const int &> {
        co_await task3();
        co_return value;
    };

    auto task1 = [&]() -> Task<std::string> {
        const int &v = co_await task2();
        CHECK(v == 42);
        co_return "Hello, World!";
    };

    auto task0 = [&]() -> Task<> {
        std::string str = co_await task1();
        CHECK(str == "Hello, World!");

        int v = co_await task2();
        CHECK(v == 42);

        str = co_await task1();
        CHECK(str == "Hello, World!");

        ctx.stop();
    };

    ctx.schedule(task0());
    ctx.start();
}

TEST_CASE("[Task] Manually control") {
    auto manualTask = []() -> Task<int> { co_return 42; };

    auto task = manualTask();
    CHECK(task);
    CHECK(!task.completed());

    task.coroutine().resume();
    CHECK(task.completed());
    CHECK(task.promise().result() == 42);
}

TEST_CASE("[Task] Manual exception control") {
    int dummy = 42;

    auto manualIntExceptionTask = []() -> Task<int> {
        throw std::runtime_error("Manual exception");
        co_return 42;
    };

    auto manualIntRefExceptionTask = [&]() -> Task<int &> {
        throw std::runtime_error("Manual exception");
        co_return dummy;
    };

    auto manualVoidExceptionTask = []() -> Task<> {
        throw std::runtime_error("Manual exception");
        co_return;
    };

    auto intTask = manualIntExceptionTask();
    CHECK(intTask);
    CHECK(!intTask.completed());

    intTask.coroutine().resume();
    CHECK(intTask.completed());
    CHECK_THROWS_AS(std::ignore = intTask.promise().result(), std::runtime_error);

    auto intRefTask = manualIntRefExceptionTask();
    CHECK(intRefTask);
    CHECK(!intRefTask.completed());

    intRefTask.coroutine().resume();
    CHECK(intRefTask.completed());
    CHECK_THROWS_AS(std::ignore = intRefTask.promise().result(), std::runtime_error);

    auto voidTask = manualVoidExceptionTask();
    CHECK(voidTask);
    CHECK(!voidTask.completed());

    voidTask.coroutine().resume();
    CHECK(voidTask.completed());
    CHECK_THROWS_AS(voidTask.promise().result(), std::runtime_error);
}

TEST_CASE("[Task] Yielding") {
    IoContext ctx{1};

    auto task = [&]() -> Task<> {
        for (std::size_t i = 0; i < 2000; ++i)
            co_await yield();

        ctx.stop();
        co_return;
    };

    ctx.schedule(task());
    ctx.start();
}

TEST_CASE("[Task] Sleeping") {
    IoContext ctx{1};

    auto task = [&]() -> Task<> {
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
    ctx.start();
}
