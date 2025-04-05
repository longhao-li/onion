#include "onion/io_context.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <mutex>
#include <set>
#include <tuple>

using namespace onion;
using namespace std::chrono_literals;

// A dirty hack to use google test in coroutines.
#define assert_true(statement)             [&] { ASSERT_TRUE(statement); }()
#define assert_false(statement)            [&] { ASSERT_FALSE(statement); }()
#define assert_eq(val1, val2)              [&] { ASSERT_EQ(val1, val2); }()
#define assert_ne(val1, val2)              [&] { ASSERT_NE(val1, val2); }()
#define assert_ge(val1, val2)              [&] { ASSERT_GE(val1, val2); }()
#define assert_throw(statement, exception) [&] { ASSERT_THROW(statement, exception); }()

TEST(task, coroutine_context_switch) {
    io_context ctx;

    const int value = 42;

    auto task3 = []() -> task<> { co_return; };

    auto task2 = [&]() -> task<const int &> {
        co_await task3();
        co_return value;
    };

    auto task1 = [&]() -> task<std::string> {
        const int &v = co_await task2();
        // A dirty hack to use google test in coroutines.
        assert_eq(v, 42);
        co_return "Hello, World!";
    };

    auto task0 = [&]() -> task<> {
        std::string str = co_await task1();
        assert_eq(str, "Hello, World!");

        int v = co_await task2();
        assert_eq(v, 42);

        str = co_await task1();
        assert_eq(str, "Hello, World!");

        ctx.stop();
    };

    ctx.schedule(task0());
    ctx.run();
}

TEST(task, manually_control) {
    auto manual_task = []() -> task<int> { co_return 42; };

    auto task = manual_task();
    assert_true(task);
    assert_false(task.done());

    task.coroutine().resume();
    assert_true(task.done());
    assert_eq(std::move(task.promise()).result(), 42);
}

TEST(task, manual_exception_control) {
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
    assert_true(int_task);
    assert_false(int_task.done());

    int_task.coroutine().resume();
    assert_true(int_task.done());
    assert_throw(std::ignore = std::move(int_task.promise()).result(), std::runtime_error);

    auto int_ref_task = int_ref_exception_task();
    assert_true(int_ref_task);
    assert_false(int_ref_task.done());

    int_ref_task.coroutine().resume();
    assert_true(int_ref_task.done());
    assert_throw(std::ignore = int_ref_task.promise().result(), std::runtime_error);

    auto void_task = void_exception_task();
    assert_true(void_task);
    assert_false(void_task.done());

    void_task.coroutine().resume();
    assert_true(void_task.done());
    assert_throw(void_task.promise().result(), std::runtime_error);
}

TEST(task, yielding) {
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

TEST(task, sleeping) {
    io_context ctx;

    auto task = [&]() -> onion::task<> {
        for (std::size_t i = 0; i < 3; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(200ms);
            auto end = std::chrono::high_resolution_clock::now();
            assert_ge(end - start, 200ms);
        }

        {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(1s);
            auto end = std::chrono::high_resolution_clock::now();
            assert_ge(end - start, 1s);
        }

        for (std::size_t i = 0; i < 3; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            co_await sleep(-1s);
            auto end = std::chrono::high_resolution_clock::now();
            assert_ge(end - start, 0ms);
        }

        ctx.stop();
    };

    ctx.schedule(task());
    ctx.run();
}

TEST(io_context_pool, dispatch_with_context_id) {
    io_context_pool       pool;
    std::mutex            mutex;
    std::set<std::size_t> id_set;

    const auto task_with_context_id = [&](std::size_t id) -> task<> {
        std::lock_guard<std::mutex> lock{mutex};
        assert_eq(id_set.find(id), id_set.end());
        assert_true(id_set.insert(id).second);
        if (id_set.size() == pool.size())
            pool.stop();
        co_return;
    };

    pool.dispatch(task_with_context_id);
    pool.run();

    assert_eq(id_set.size(), pool.size());
    for (std::size_t i = 0; i < pool.size(); ++i)
        assert_ne(id_set.find(i), id_set.end());
}
