#pragma once

#include "task.hpp"

#include <atomic>
#include <mutex>
#include <queue>

namespace onion {
namespace detail {

/// \class IoContextWorkerTaskQueue
/// \brief
///   For internal usage. Work-stealing queue for tasks in worker.
class IoContextWorkerTaskQueue {
public:
    /// \brief
    ///   Initialize this work-stealing queue with the specified size.
    /// \param capacity
    ///   Expected maximum number of tasks that could be stored in this queue. This value will
    ///   always be rounded up to the block size.
    ONION_API explicit IoContextWorkerTaskQueue(std::size_t capacity) noexcept;

    /// \brief
    ///   \c IoContextWorkerTaskQueue is not copyable.
    IoContextWorkerTaskQueue(const IoContextWorkerTaskQueue &) = delete;

    /// \brief
    ///   Move constructor of \c IoContextWorkerTaskQueue.
    /// \param[inout] other
    ///   The \c IoContextWorkerTaskQueue object to be moved. The moved \c IoContextWorkerTaskQueue
    ///   object will be in a valid but undefined state.
    IoContextWorkerTaskQueue(IoContextWorkerTaskQueue &&other) noexcept
        : m_mask{other.m_mask},
          m_ownerIndex{other.m_ownerIndex.load(std::memory_order_relaxed)},
          m_thiefIndex{other.m_thiefIndex.load(std::memory_order_relaxed)},
          m_blocks{other.m_blocks} {
        other.m_blocks = nullptr;
    }

    /// \brief
    ///   Destroy this work-stealing queue and release memory.
    ONION_API ~IoContextWorkerTaskQueue() noexcept;

    /// \brief
    ///   \c IoContextWorkerTaskQueue is not copyable.
    auto operator=(const IoContextWorkerTaskQueue &other) = delete;

    /// \brief
    ///   \c IoContextWorkerTaskQueue is not move-assignable.
    auto operator=(IoContextWorkerTaskQueue &&other) = delete;

    /// \brief
    ///  Get the approximate size in use of the queue.
    /// \return
    ///   The approximate size in use of the queue.
    [[nodiscard]]
    ONION_API auto approximateSize() const noexcept -> std::size_t;

    /// \brief
    ///   Try to push a task into the queue.
    /// \param[in] value
    ///   Pointer to the promise of the task to be pushed into the queue.
    /// \retval true
    ///   The task is successfully pushed into the queue.
    /// \retval false
    ///   The queue is full and the task is not pushed into the queue.
    ONION_API auto tryPush(PromiseBase *value) noexcept -> bool;

    /// \brief
    ///   Try to pop a task from this task queue. This method could only be called in the owner
    ///   thread.
    /// \return
    ///   Pointer to the promise of the task popped from the queue. Otherwise, return \c nullptr.
    [[nodiscard]]
    ONION_API auto tryPop() noexcept -> PromiseBase *;

    /// \brief
    ///   Try to steal a task from this task queue. This method could only be called in the thief
    ///   thread.
    /// \return
    ///   Pointer to the promise of the task stolen from the queue. Otherwise, return \c nullptr.
    [[nodiscard]]
    ONION_API auto trySteal() noexcept -> PromiseBase *;

private:
    /// \brief
    ///   Try to move the push index to the next block.
    /// \retval true
    ///   The push index is successfully moved to the next block.
    /// \retval false
    ///   The push index is not moved to the next block because the next block is not available.
    auto advancePushIndex() noexcept -> bool;

    /// \brief
    ///   Try to move the pop index to the previous block.
    /// \retval true
    ///   The pop index is successfully moved to the previous block.
    /// \retval false
    ///   The pop index is not moved to the previous block because the previous block is not
    ///   available.
    auto advancePopIndex() noexcept -> bool;

    /// \brief
    ///   Try to move the steal index to the next block.
    /// \param current
    ///   Current thief block index.
    /// \retval true
    ///   The steal index is successfully moved to the next block.
    /// \retval false
    ///   The steal index is not moved to the next block because the next block is not available.
    auto advanceStealIndex(std::size_t current) noexcept -> bool;

private:
    std::size_t m_mask;
    std::atomic_size_t m_ownerIndex;
    std::atomic_size_t m_thiefIndex;
    void *m_blocks;
};

} // namespace detail

/// \class IoContext
/// \brief
///   The context for asynchronous I/O operations. Static thread pool is used for I/O operations.
class IoContext;

/// \class ScheduleAwaitable
/// \brief
///   Awaitable object for scheduling a task to be executed in current worker.
class [[nodiscard]] ScheduleAwaitable;

/// \class YieldAwaitable
/// \brief
///   Awaitable object for yielding current coroutine so that the worker can schedule another
///   coroutine immediately.
class [[nodiscard]] YieldAwaitable;

/// \class SleepAwaitable
/// \brief
///   Awaitable object for suspending current coroutine for a while.
class [[nodiscard]] SleepAwaitable;

namespace detail {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \struct Overlapped
/// \brief
///   Overlapped structure for Windows overlapped IO operations.
struct Overlapped {
    std::uintptr_t internal;
    std::uintptr_t internalHigh;
    union {
        struct {
            std::uint32_t offset;
            std::uint32_t offsetHigh;
        } dummyStructName;
        void *pointer;
    } dummyUnionName;
    void *event;

    std::uint32_t error;
    std::uint32_t bytes;
    PromiseBase *promise;
};
#elif defined(__linux) || defined(__linux__)
/// \struct Overlapped
/// \brief
///   Overlapped structure for \c io_uring operations.
struct Overlapped {
    std::int32_t result;
    PromiseBase *promise;
};
#endif

/// \class IoContextWorker
/// \brief
///   Worker class for \c IoContext.
class IoContextWorker {
public:
    /// \brief
    ///   Create a new worker for the given IO context and initialize the IO multiplexer. \c IOCP
    ///   will be used for Windows, \c io_uring will be used for Linux and \c kqueue will be used
    ///   for BSD.
    /// \param[in] context
    ///   Owner context of this worker.
    /// \throws std::system_error
    ///   Thrown if failed to create IO multiplexer.
    ONION_API explicit IoContextWorker(IoContext &context);

    /// \brief
    ///   \c IoContextWorker is not copyable.
    IoContextWorker(const IoContextWorker &other) = delete;

    /// \brief
    ///   Move constructor of \c IoContextWorker. This is implemented so that \c IoContextWorker
    ///   objects could be managed in \c std::vector. This constructor should not be used directly.
    /// \param[inout] other
    ///   The worker to move from. The moved worker will be in a valid but undefined state.
    ONION_API IoContextWorker(IoContextWorker &&other) noexcept;

    /// \brief
    ///   Destroy this worker and release resources. This worker must be stopped before destruction.
    ONION_API ~IoContextWorker() noexcept;

    /// \brief
    ///   \c IoContextWorker is not copyable.
    auto operator=(const IoContextWorker &other) = delete;

    /// \brief
    ///   \c IoContextWorker is not move-assignable.
    auto operator=(IoContextWorker &&other) = delete;

    /// \brief
    ///   Get the owner \c IoContext of this worker.
    /// \return
    ///   Reference to the owner \c IoContext of this worker.
    [[nodiscard]]
    auto context() const noexcept -> IoContext & {
        return *m_context;
    }

    /// \brief
    ///   Checks if this worker is running.
    /// \retval true
    ///   This worker is running.
    /// \retval false
    ///   This worker is not running.
    [[nodiscard]]
    auto isRunning() const noexcept -> bool {
        return m_isRunning.load(std::memory_order_relaxed);
    }

    /// \brief
    ///   Start this worker to process IO events. This method will block current thread until the
    ///   worker is stopped.
    ///
    ///   It is OK to call this method for multiple-times in different threads at the same time, but
    ///   only one of them will start the worker.
    ONION_API auto start() noexcept -> void;

    /// \brief
    ///   Request this worker to stop. This method only sends a stop request to this worker and
    ///   returns immediately. This method is concurrent safe.
    ONION_API auto stop() noexcept -> void;

    /// \brief
    ///   Schedule a task in this worker. This method is concurrent safe.
    /// \tparam T
    ///   Type of the result of the task.
    /// \param task
    ///   The task to be scheduled. Ownership of the task will be transferred to this worker. The
    ///   scheduled task must be the stack bottom of the coroutine call stack.
    template <typename T>
    auto schedule(Task<T> task) noexcept -> void {
        auto coroutine = task.detach();

        { // Push the task into the task queue.
            std::lock_guard<std::mutex> lock{m_localTasksMutex};
            m_localTasks.push_back(&coroutine.promise());
            m_hasLocalTask.store(true, std::memory_order_relaxed);
        }

        // Handle the scheduled task as soon as possible.
        wakeUp();
    }

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   For internal usage. Get IOCP of this worker.
    /// \return
    ///   IOCP handle of this worker.
    [[nodiscard]]
    auto ioCompletionPort() const noexcept -> void * {
        return m_iocp;
    }
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   For internal usage. Get pointer to struct \c io_uring of this worker.
    /// \return
    ///   Pointer to \c io_uring of this worker.
    [[nodiscard]]
    auto uring() const noexcept -> void * {
        return m_uring;
    }
#endif

    /// \brief
    ///   Get worker for current thread.
    /// \return
    ///   Pointer to worker for current thread. The return value is \c nullptr if current thread
    ///   is not a worker thread.
    [[nodiscard]]
    ONION_API static auto current() noexcept -> IoContextWorker *;

private:
    /// \brief
    ///   For internal usage. Schedule a task in this worker. This method is not concurrent safe.
    /// \param[in] promise
    ///   Promise of the task to be scheduled.
    auto schedule(PromiseBase &promise) noexcept -> void {
        if (!m_taskQueue.tryPush(&promise)) [[unlikely]] {
            std::lock_guard<std::mutex> lock{m_localTasksMutex};
            m_localTasks.push_back(&promise);
            m_hasLocalTask.store(true, std::memory_order_relaxed);
        }
    }

    /// \brief
    ///   Wake up the IO multiplexer of this worker. This method is concurrent safe.
    ONION_API auto wakeUp() noexcept -> void;

    friend class ::onion::ScheduleAwaitable;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   For internal usage. For Win32 only. Schedule a task in this worker with timeout. The
    ///   scheduled task will be executed after the timeout. This method is not concurrent safe and
    ///   could only be called in owner thread.
    /// \param[in] promise
    ///   Pointer to the promise of the task to be scheduled.
    /// \param timeout
    ///   Timeout in milliseconds.
    ONION_API auto schedule(PromiseBase &promise, std::uint32_t timeout) noexcept -> void;

    friend class ::onion::SleepAwaitable;
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \struct TimeoutEvent
    /// \brief
    ///   IOCP does not support timer events. This is used to simulate timer for Windows.
    struct TimeoutEvent {
        std::int64_t expire;
        PromiseBase *promise;

        /// \brief
        ///   \c TimeoutEvent objects are managed in \c std::priority_queue and earlier expire time
        ///   should be popped first.
        auto operator<(const TimeoutEvent &other) const noexcept -> bool {
            return expire > other.expire;
        }
    };
#endif

private:
    /// \brief
    ///   A flag that indicates whether this worker is running.
    std::atomic_bool m_isRunning;

    /// \brief
    ///   Owner \c IoContext of this worker.
    IoContext *m_context;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   IO completion port for this worker.
    void *m_iocp;

    /// \brief
    ///   Frequency of the performance counter per millisecond.
    std::int64_t m_frequency;

    /// \brief
    ///   Timeout event queue for this worker.
    std::priority_queue<TimeoutEvent> m_timeouts;
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   Pointer to \c io_uring for this worker.
    void *m_uring;

    /// \brief
    ///   Wake up eventfd for this worker.
    int m_wakeUp;
#endif

    /// \brief
    ///   Task queue for this worker.
    detail::IoContextWorkerTaskQueue m_taskQueue;

    /// \brief
    ///   Mutex for local tasks.
    std::mutex m_localTasksMutex;

    /// \brief
    ///   Local tasks for this worker.
    std::vector<PromiseBase *> m_localTasks;

    /// \brief
    ///   A flag that indicates whether this worker has local tasks.
    std::atomic_bool m_hasLocalTask;
};

} // namespace detail

/// \class IoContext
/// \brief
///   The context for asynchronous I/O operations. Static thread pool is used for I/O operations.
class IoContext {
public:
    /// \brief
    ///   Create a new \c IoContext with workers. Number of workers will be equal to the
    ///   number of hardware threads.
    /// \throws std::system_error
    ///   Thrown if any worker failed to initialize IO multiplexer.
    ONION_API IoContext();

    /// \brief
    ///   Create a new \c IoContext with specified number of workers.
    /// \param count
    ///   Expected number of workers to be created. Number of workers will be determined by the
    ///   number of hardware threads if this value is 0.
    /// \throws std::system_error
    ///   Thrown if any worker failed to initialize IO multiplexer.
    ONION_API explicit IoContext(std::size_t count);

    /// \brief
    ///   \c IoContext is not copyable.
    IoContext(const IoContext &other) = delete;

    /// \brief
    ///   \c IoContext is not movable.
    IoContext(IoContext &&other) = delete;

    /// \brief
    ///   Destroy this \c IoContext. All workers must be stopped before destroying.
    ONION_API ~IoContext() noexcept;

    /// \brief
    ///   \c IoContext is not copyable.
    auto operator=(const IoContext &other) = delete;

    /// \brief
    ///   \c IoContext is not movable.
    auto operator=(IoContext &&other) = delete;

    /// \brief
    ///   Get number of workers in this \c IoContext.
    /// \return
    ///   Number of workers in this \c IoContext.
    [[nodiscard]]
    auto size() const noexcept -> std::size_t {
        return m_workers.size();
    }

    /// \brief
    ///   Start all workers in this \c IoContext. This method will block current thread until all
    ///   workers are stopped.
    ///
    ///   It is OK to call this method for multiple-times in different threads at the same time, but
    ///   only one of them will start the workers.
    ONION_API auto start() noexcept -> void;

    /// \brief
    ///   Request all workers in this \c IoContext to stop. This method only sends a stop request to
    ///   all workers and returns immediately. This method is concurrent safe.
    auto stop() noexcept -> void {
        for (auto &worker : m_workers)
            worker.stop();
    }

    /// \brief
    ///   Dispatch tasks into all workers in this \c IoContext. This method is concurrent safe.
    /// \tparam Func
    ///   Type of the function that is used to generate tasks. This function should take the worker
    ///   ID as parameter and return a task.
    /// \param func
    ///   Function that generates tasks. This function should take the worker ID as parameter. It is
    ///   guaranteed that the worker ID starts from 0 and ends at \c size() - 1. The function should
    ///   not throw any exception.
    template <typename Func>
        requires(std::is_invocable_v<Func, std::size_t>)
    auto dispatch(Func &&func) noexcept -> void {
        for (std::size_t i = 0; i < m_workers.size(); ++i)
            m_workers[i].schedule(func(i));
    }

    /// \brief
    ///   Dispatch tasks into all workers in this \c IoContext. This method is concurrent safe.
    /// \tparam Func
    ///   Type of the function that is used to generate tasks. This function should take \p args as
    ///   parameters and return a task.
    /// \tparam Args
    ///   Types of the arguments that are passed to the function.
    /// \param func
    ///   Function that generates tasks. This function should take \p args as parameters.
    /// \param[in] args
    ///   Arguments that are passed to the function. Arguments are always used as lvalue references.
    template <typename Func, typename... Args>
        requires(std::is_invocable_v<Func, Args &...>)
    auto dispatch(Func &&func, Args &&...args) noexcept -> void {
        for (auto &m_worker : m_workers)
            m_worker.schedule(func(std::forward<Args>(args)...));
    }

    /// \brief
    ///   Schedule a task in this \c IoContext. The workers are choosen via round-robin. This method
    ///   is concurrent safe.
    /// \tparam T
    ///   Return type of the task to be scheduled.
    /// \param task
    ///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine
    ///   call stack.
    template <typename T>
    auto schedule(Task<T> task) noexcept -> void {
        std::size_t next = m_next.fetch_add(1, std::memory_order_relaxed) % m_workers.size();
        m_workers[next].schedule(std::move(task));
    }

    friend class ::onion::detail::IoContextWorker;

private:
    /// \brief
    ///   Running flag for this worker.
    std::atomic_bool m_isRunning;

    /// \brief
    ///   Index to the next worker to schedule a task.
    std::atomic_size_t m_next;

    /// \brief
    ///   Workers for this IO context.
    std::vector<detail::IoContextWorker> m_workers;
};

} // namespace onion

namespace onion {

/// \class ScheduleAwaitable
/// \brief
///   Awaitable object for scheduling a task to be executed in current worker.
class [[nodiscard]] ScheduleAwaitable {
public:
    /// \brief
    ///   Create a new \c ScheduleAwaitable object to schedule another coroutine.
    /// \tparam T
    ///   Type of the result of the task.
    /// \param task
    ///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine
    ///   call stack.
    template <typename T>
    explicit ScheduleAwaitable(Task<T> task) noexcept : m_promise{&task.detach().promise()} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This method always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for scheduling and suspending current coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \return
    ///   This method always returns \c false.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T>) noexcept -> bool {
        auto *worker = detail::IoContextWorker::current();
        worker->schedule(*m_promise);
        worker->wakeUp();
        return false;
    }

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get the async operation result. Do
    ///   nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
    /// \brief
    ///   Pointer to the promise of the task to be scheduled.
    detail::PromiseBase *m_promise;
};

/// \brief
///   Schedule the specified task in current worker. This method could only be used in worker
///   threads.
/// \tparam T
///   Type of the result of the task. Usually this type should be \c void.
/// \param task
///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine call
///   stack.
/// \return
///   An awaitable object to schedule another coroutine.
template <typename T>
auto schedule(Task<T> task) noexcept -> ScheduleAwaitable {
    return ScheduleAwaitable{std::move(task)};
}

/// \class YieldAwaitable
/// \brief
///   Awaitable object for yielding current coroutine so that the worker can schedule another
///   coroutine immediately.
class [[nodiscard]] YieldAwaitable {
public:
    /// \brief
    ///   Create a new \c YieldAwaitable object to yield current coroutine.
    constexpr YieldAwaitable() noexcept : m_ovlp{} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This method always returns \c false.
    [[nodiscard]]
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
        this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   For internal usage. Yield current coroutine so that the scheduler can schedule another
    ///   coroutine immediately.
    /// \param[in] promise
    ///   Promise of the coroutine to be yielded.
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> void;

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get the async operation result. Do
    ///   nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
    /// \brief
    ///   Overlapped structure for asynchronous IO operations.
    detail::Overlapped m_ovlp;
};

/// \brief
///   Yield current coroutine so that the scheduler can schedule another coroutine immediately.
/// \return
///   An awaitable object to yield current coroutine.
constexpr auto yield() noexcept -> YieldAwaitable {
    return {};
}

/// \class SleepAwaitable
/// \brief
///   Awaitable object for suspending current coroutine for a while.
class [[nodiscard]] SleepAwaitable {
public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Create a new \c SleepAwaitable object to suspend current coroutine for a while.
    /// \tparam Rep
    ///   Representation for \c std::chrono::duration. See C++ reference for more details.
    /// \tparam Period
    ///   Period for \c std::chrono::duration. See C++ reference for more details.
    /// \param duration
    ///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend
    ///   current coroutine.
    template <typename Rep, typename Period>
    constexpr SleepAwaitable(std::chrono::duration<Rep, Period> duration) noexcept : m_timeout{} {
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        auto count        = milliseconds.count();
        if (count > 0) [[likely]]
            m_timeout = static_cast<std::uint32_t>(count);
    }
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   Create a new \c SleepAwaitable object to suspend current coroutine for a while.
    /// \tparam Rep
    ///   Representation for \c std::chrono::duration. See C++ reference for more details.
    /// \tparam Period
    ///   Period for \c std::chrono::duration. See C++ reference for more details.
    /// \param duration
    ///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend
    ///   current coroutine.
    template <typename Rep, typename Period>
    constexpr SleepAwaitable(std::chrono::duration<Rep, Period> duration) noexcept
        : m_ovlp{},
          m_timeout{} {
        auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
        auto count       = nanoseconds.count();

        if (count > 0) [[likely]] {
            m_timeout.tv_sec  = count / 1'000'000'000;
            m_timeout.tv_nsec = count % 1'000'000'000;
        }
    }
#endif

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
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
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   For internal usage. Actual prepare for async timeout event.
    /// \param[in] promise
    ///   Promise of the coroutine to be suspended.
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   C++20 coroutine API. Resume current coroutine and get result of this sleep operation. Do
    ///   nothing.
    static constexpr auto await_resume() noexcept -> void {}

private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Timeout in milliseconds.
    std::uint32_t m_timeout;
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   Overlapped structure for \c io_uring operations.
    detail::Overlapped m_ovlp;

    /// \brief
    ///   Timeout struct used for \c io_uring.
    struct {
        std::int64_t tv_sec;
        std::int64_t tv_nsec;
    } m_timeout;
#endif
};

/// \brief
///   Suspend current coroutine for a while.
/// \tparam Rep
///   Representation for \c std::chrono::duration. See C++ reference for more details.
/// \tparam Period
///   Period for \c std::chrono::duration. See C++ reference for more details.
/// \param duration
///   Time to suspend current coroutine. Passing nevative or zero duration will not suspend current
///   coroutine.
/// \return
///   An awaitable object to suspend current coroutine for a while.
template <typename Rep, typename Period>
constexpr auto sleep(std::chrono::duration<Rep, Period> duration) noexcept -> SleepAwaitable {
    return {duration};
}

} // namespace onion
