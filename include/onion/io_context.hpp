#pragma once

#include "export.hpp"
#include "task.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <WinSock2.h>
#    include <Windows.h>
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
#    include <liburing.h>
#    include <sys/eventfd.h>
#endif

#include <atomic>
#include <mutex>
#include <queue>
#include <span>
#include <system_error>

namespace onion {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \struct overlapped_t
/// \brief
///   Overlapped structure for Windows overlapped I/O operations.
struct overlapped_t : OVERLAPPED {
    promise_base *promise;
    std::int32_t  error;
    std::uint32_t bytes;
};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
/// \struct overlapped_t
/// \brief
///   Overlapped structure for Linux io_uring overlapped I/O operations.
struct overlapped_t {
    promise_base *promise;
    int           result;
};
#endif

/// \class io_context
/// \brief
///   Context for asynchronous I/O operations.
class io_context {
public:
    /// \brief
    ///   Create a new \c io_context object and initialize the IO multiplexer. IOCP is used for Windows and io_uring is
    ///   used for Linux.
    /// \throws std::system_error
    ///   Thrown if failed to create IO multiplexer.
    ONION_API io_context();

    /// \brief
    ///   \c io_context is not copyable.
    io_context(const io_context &other) = delete;

    /// \brief
    ///   \c io_context is not movable.
    io_context(io_context &&other) = delete;

    /// \brief
    ///   Destroy this \c io_context object. This \c io_context must be stopped before destruction.
    ONION_API ~io_context() noexcept;

    /// \brief
    ///   \c io_context is not copyable.
    auto operator=(const io_context &other) = delete;

    /// \brief
    ///   \c io_context is not movable.
    auto operator=(io_context &&other) = delete;

    /// \brief
    ///   Checks if this \c io_context is running.
    /// \retval true
    ///   This \c io_context is running.
    /// \retval false
    ///   This \c io_context is not running.
    [[nodiscard]] auto is_running() const noexcept -> bool {
        return this->m_running.load(std::memory_order_relaxed);
    }

    /// \brief
    ///   Start this \c io_context to process IO events. This method will block current thread until the \c io_context
    ///   is stopped.
    ONION_API auto run() noexcept -> std::error_code;

    /// \brief
    ///   Request this \c io_context to stop. This method only sends a stop request to this \c io_context and returns
    ///   immediately. This method is concurrent safe.
    auto stop() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        PostQueuedCompletionStatus(m_iocp, 0, 1, nullptr);
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        eventfd_write(m_wakeup, std::numeric_limits<std::uint32_t>::max());
#endif
    }

    /// \brief
    ///   Wake up this \c io_context immediately. This method is concurrent safe.
    auto wakeup() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        PostQueuedCompletionStatus(m_iocp, 0, 0, nullptr);
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        eventfd_write(m_wakeup, 1);
#endif
    }

    /// \brief
    ///   Schedule a task in this \c io_context. This method is concurrent safe.
    /// \tparam T
    ///   Type of the result of the task.
    /// \param coroutine
    ///   The task to be scheduled. Ownership of the task will be transferred to this \c io_context. The scheduled task
    ///   must be the stack bottom of the coroutine call stack.
    template <typename T>
    auto schedule(task<T> coroutine) noexcept -> void {
        auto handle = coroutine.detach();
        { // Push the task into external task queue.
            std::lock_guard<std::mutex> lock(this->m_mutex);
            this->m_external.push_back(&handle.promise());
            this->m_has_external.store(true, std::memory_order_relaxed);
        }
    }

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   For internal usage. Get native IOCP handle.
    /// \return HANDLE
    ///   Native IOCP handle of this \c io_context.
    [[nodiscard]] auto iocp() const noexcept -> HANDLE {
        return m_iocp;
    }
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   For internal usage. Get IO uring instance for this \c io_context.
    /// \return
    ///   Pointer to the IO uring instance for this \c io_context.
    [[nodiscard]] auto uring() const noexcept -> io_uring * {
        return &m_uring;
    }
#endif

    /// \brief
    ///   Get \c io_context for current thread.
    /// \return
    ///   Pointer to \c io_context for current thread. The return value is \c nullptr if current thread is not a \c
    ///   io_context thread.
    [[nodiscard]] ONION_API static auto current() noexcept -> io_context *;

private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \struct timeout_event
    /// \brief
    ///   A struct that stores timeout events.
    struct timeout_event {
        std::int64_t  when;
        promise_base *promise;

        auto operator<(const timeout_event &other) const noexcept -> bool {
            return when > other.when;
        }
    };

    /// \brief
    ///   For internal usage. Schedule a task in this \c io_context with a timeout. This method is not concurrent safe.
    /// \param[in] promise
    ///   Promise of the task to be scheduled.
    /// \param timeout
    ///   Timeout in milliseconds.
    auto schedule(promise_base *promise, std::uint32_t timeout) noexcept -> void {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);

        std::int64_t expire = now.QuadPart + timeout * this->m_frequency;
        this->m_timeouts.push({expire, promise});
    }
#endif

    friend class schedule_awaitable;
    friend class sleep_awaitable;
    friend class yield_awaitable;

private:
    /// \brief
    ///   A flag that indicates whether this \c io_context is running.
    std::atomic_bool m_running;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Performance counter frequency per millisecond.
    std::int64_t m_frequency;

    /// \brief
    ///   IOCP handle for Windows asynchronous I/O operations.
    HANDLE m_iocp;

    /// \brief
    ///   Priority queue that is used to handle timeout events.
    std::priority_queue<timeout_event> m_timeouts;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   IO uring instance for Linux asynchronous I/O operations.
    mutable io_uring m_uring;

    /// \brief
    ///   Event file descriptor that is used to wake up io_uring.
    int m_wakeup;
#endif

    /// \brief
    ///   Local task queue for this \c io_context.
    std::vector<promise_base *> m_tasks;

    /// \brief
    ///   Mutex for external tasks.
    std::mutex m_mutex;

    /// \brief
    ///   A flag that indicates whether this \c io_context has external tasks.
    std::atomic_bool m_has_external;

    /// \brief
    ///   External tasks for this \c io_context.
    std::vector<promise_base *> m_external;
};

/// \class io_context_pool
/// \brief
///   Thread pool for \c io_context. Static thread pool will be used.
class io_context_pool {
public:
    /// \brief
    ///   Create a new \c io_context_pool. Number of \c io_contexts will be determined by number of hardware threads.
    ONION_API io_context_pool();

    /// \brief
    ///   Create a new \c io_context_pool with the specified number of \c io_contexts.
    /// \param size
    ///   Number of \c io_contexts to be created. Number of of \c io_contexts will be determined by number of hardware
    ///   threads if \p size is 0.
    ONION_API explicit io_context_pool(std::uint32_t size);

    /// \brief
    ///   \c io_context_pool is not copyable.
    io_context_pool(const io_context_pool &other) = delete;

    /// \brief
    ///   \c io_context_pool is not movable.
    io_context_pool(io_context_pool &&other) = delete;

    /// \brief
    ///   Destroy this pool and the owned \c io_contexts. This pool must be stopped before destroying.
    ONION_API ~io_context_pool() noexcept;

    /// \brief
    ///   \c io_context_pool is not copyable.
    auto operator=(const io_context_pool &other) = delete;

    /// \brief
    ///   \c io_context_pool is not movable.
    auto operator=(io_context_pool &&other) = delete;

    /// \brief
    ///   Checks if this \c io_context_pool is running.
    /// \retval true
    ///   This \c io_context_pool is running.
    /// \retval false
    ///   This \c io_context_pool is not running.
    [[nodiscard]] auto is_running() const noexcept -> bool {
        return this->m_running.load(std::memory_order_relaxed);
    }

    /// \brief
    ///   Get number of \c io_contexts in this pool.
    /// \return
    ///   Number of \c io_contexts in this pool.
    [[nodiscard]] auto size() const noexcept -> std::size_t {
        return this->m_size;
    }

    /// \brief
    ///   Get all \c io_context in this pool.
    /// \return
    ///   All \c io_context in this pool.
    [[nodiscard]] auto contexts() noexcept -> std::span<io_context> {
        return {this->m_pool, this->m_size};
    }

    /// \brief
    ///   Start all \c io_contexts in this pool. This method will block current thread until all contexts are stopped.
    ONION_API auto run() noexcept -> void;

    /// \brief
    ///   Request all \c io_contexts in this pool to stop. This method only sends a stop request to all contexts and
    ///   returns immediately. This method is concurrent safe.
    auto stop() noexcept -> void {
        for (auto &ctx : this->contexts())
            ctx.stop();
    }

    /// \brief
    ///   Schedule a task in one of \c io_contexts in this pool. The context is choosen via round-robin. This method is
    ///   concurrent safe.
    /// \tparam T
    ///   Return type of the task to be scheduled.
    /// \param coroutine
    ///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine call stack.
    template <typename T>
    auto schedule(task<T> coroutine) noexcept -> void {
        std::size_t next = this->m_next.fetch_add(1, std::memory_order_relaxed);
        io_context &ctx  = this->m_pool[next % this->m_size];
        ctx.schedule(std::move(coroutine));
        ctx.wakeup();
    }

    /// \brief
    ///   Dispatch tasks into all contexts in this \c io_context_pool. This method is concurrent safe.
    /// \tparam Func
    ///   Type of the function that is used to generate tasks. This function should take the context ID as parameter and
    ///   return a task.
    /// \param func
    ///   Function that generates tasks. This function should take the context ID as parameter. It is guaranteed that
    ///   the context ID starts from 0 and ends at \c size() - 1. The function should not throw any exception.
    template <typename Func>
        requires(std::is_invocable_v<Func, std::size_t>)
    auto dispatch(Func &&func) noexcept -> void {
        for (std::size_t i = 0; i < this->m_size; ++i) {
            io_context &ctx = this->m_pool[i];
            ctx.schedule(func(i));
            ctx.wakeup();
        }
    }

    /// \brief
    ///   Dispatch tasks into all contexts in this \c io_context_pool. This method is concurrent safe.
    /// \tparam Func
    ///   Type of the function that is used to generate tasks. This function should take \p args as parameters and
    ///   return a task.
    /// \tparam Args
    ///   Types of the arguments that are passed to the function.
    /// \param func
    ///   Function that generates tasks. This function should take \p args as parameters.
    /// \param[in] args
    ///   Arguments that are passed to the function. Arguments are always used as lvalue references.
    template <typename Func, typename... Args>
        requires(std::is_invocable_v<Func, Args &...>)
    auto dispatch(Func &&func, Args &&...args) noexcept -> void {
        for (auto &ctx : this->contexts()) {
            ctx.schedule(func(std::forward<Args>(args)...));
            ctx.wakeup();
        }
    }

private:
    /// \brief
    ///   Running flag for this \c io_context_pool.
    std::atomic_bool m_running;

    /// \brief
    ///   Index to the next \c io_context to schedule a task.
    std::atomic_size_t m_next;

    /// \brief
    ///   \c io_context pool.
    io_context *m_pool;

    /// \brief
    ///   Number of \c io_contexts in this pool.
    std::size_t m_size;
};

/// \class schedule_awaitable
/// \brief
///   Awaitable object for scheduling a task to be executed in current \c io_context.
class schedule_awaitable {
public:
    /// \brief
    ///   Create a new \c schedule_awaitable object to schedule another coroutine.
    /// \tparam T
    ///   Type of the result of the task.
    /// \param coroutine
    ///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine call stack.
    template <typename T>
    explicit schedule_awaitable(task<T> coroutine) noexcept : m_promise{&coroutine.detach().promise()} {}

    /// \brief
    ///   C++20 coroutine API method. Prepare for scheduling and suspending current coroutine.
    /// \return
    ///   This method always returns \c true.
    auto await_ready() noexcept -> bool {
        io_context *ctx = io_context::current();
        ctx->m_tasks.push_back(this->m_promise);
        ctx->wakeup();
        return true;
    }

    /// \brief
    ///   Prepare for suspending current coroutine. Do nothing.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \return
    ///   This method always returns \c false.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T>) const noexcept -> bool {
        return false;
    }

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get the async operation result. Do nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
    /// \brief
    ///   Pointer to the promise of the task to be scheduled.
    promise_base *m_promise;
};

/// \brief
///   Schedule the specified task in current \c io_context. This method could only be used in \c io_context threads.
/// \tparam T
///   Type of the result of the task. Usually this type should be \c void.
/// \param coroutine
///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine call
///   stack.
/// \return
///   An awaitable object to schedule another coroutine.
template <typename T>
auto schedule(task<T> coroutine) noexcept -> schedule_awaitable {
    return schedule_awaitable{std::move(coroutine)};
}

/// \class yield_awaitable
/// \brief
///   Awaitable object for yielding current coroutine so that the \c io_context can schedule another coroutine
///   immediately.
class yield_awaitable {
public:
    /// \brief
    ///   Create a new \c YieldAwaitable object to yield current coroutine.
    constexpr yield_awaitable() noexcept : m_ovlp{} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This method always returns \c false.
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for yielding and suspending current coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        this->m_ovlp.promise = &coroutine.promise();
        HANDLE iocp          = io_context::current()->iocp();
        PostQueuedCompletionStatus(iocp, 0, 0, &this->m_ovlp);
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        this->m_ovlp.promise = &coroutine.promise();

        io_uring     *ring = io_context::current()->uring();
        io_uring_sqe *sqe  = io_uring_get_sqe(ring);
        while (sqe == nullptr) [[unlikely]] {
            io_uring_submit(ring);
            sqe = io_uring_get_sqe(ring);
        }

        io_uring_prep_nop(sqe);
        io_uring_sqe_set_flags(sqe, 0);
        io_uring_sqe_set_data(sqe, &this->m_ovlp);
#endif
    }

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get the async operation result. Do nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
    /// \brief
    ///   Overlapped structure for asynchronous IO operations.
    overlapped_t m_ovlp;
};

/// \brief
///   Yield current coroutine so that the scheduler can schedule another coroutine immediately.
/// \return
///   An awaitable object to yield current coroutine.
constexpr auto yield() noexcept -> yield_awaitable {
    return {};
}

/// \class sleep_awaitable
/// \brief
///   Awaitable object for suspending current coroutine for a while.
class sleep_awaitable {
public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Create a new \c sleep_awaitable object to suspend current coroutine for a while.
    /// \tparam Rep
    ///   Representation for \c std::chrono::duration. See C++ reference for more details.
    /// \tparam Period
    ///   Period for \c std::chrono::duration. See C++ reference for more details.
    /// \param duration
    ///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend current coroutine.
    template <typename Rep, typename Period>
    constexpr sleep_awaitable(std::chrono::duration<Rep, Period> duration) noexcept {
        using std::chrono::duration_cast;
        using std::chrono::milliseconds;

        auto count = duration_cast<milliseconds>(duration).count();
        if (count > 0) [[likely]]
            this->m_timeout = static_cast<std::uint32_t>(count);
    }
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Create a new \c sleep_awaitable object to suspend current coroutine for a while.
    /// \tparam Rep
    ///   Representation for \c std::chrono::duration. See C++ reference for more details.
    /// \tparam Period
    ///   Period for \c std::chrono::duration. See C++ reference for more details.
    /// \param duration
    ///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend current coroutine.
    template <typename Rep, typename Period>
    constexpr sleep_awaitable(std::chrono::duration<Rep, Period> duration) noexcept {
        using std::chrono::duration_cast;
        using std::chrono::nanoseconds;

        auto count = duration_cast<nanoseconds>(duration).count();
        if (count > 0) {
            m_timeout.tv_sec  = count / 1000000000LL;
            m_timeout.tv_nsec = count % 1000000000LL;
        }
    }
#endif

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This method always returns \c false.
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async sleep operation and suspend this coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   Timeout is negative or zero, this coroutine should not be suspended.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_timeout == 0)
            return false;

        io_context::current()->schedule(&coroutine.promise(), this->m_timeout);
        return true;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        this->m_ovlp.promise = &coroutine.promise();

        io_uring     *ring = io_context::current()->uring();
        io_uring_sqe *sqe  = io_uring_get_sqe(ring);
        while (sqe == nullptr) [[unlikely]] {
            io_uring_submit(ring);
            sqe = io_uring_get_sqe(ring);
        }

        io_uring_prep_timeout(sqe, &this->m_timeout, std::numeric_limits<unsigned>::max(), 0);
        io_uring_sqe_set_flags(sqe, 0);
        io_uring_sqe_set_data(sqe, &this->m_ovlp);

        return true;
#endif
    }

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get result of this sleep operation. Do nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Timeout in milliseconds.
    std::uint32_t m_timeout = 0;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Overlapped structure for io_uring overlapped IO operations.
    overlapped_t m_ovlp{};

    /// \brief
    ///   io_uring timeout struct.
    __kernel_timespec m_timeout{};
#endif
};

/// \brief
///   Suspend current coroutine for a while.
/// \tparam Rep
///   Representation for \c std::chrono::duration. See C++ reference for more details.
/// \tparam Period
///   Period for \c std::chrono::duration. See C++ reference for more details.
/// \param duration
///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend current coroutine.
/// \return
///   An awaitable object to suspend current coroutine for a while.
template <typename Rep, typename Period>
constexpr auto sleep(std::chrono::duration<Rep, Period> duration) noexcept -> sleep_awaitable {
    return {duration};
}

} // namespace onion
