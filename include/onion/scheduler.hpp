#pragma once

#include "task.hpp"

#include <atomic>
#include <queue>
#include <random>
#include <span>
#include <vector>

namespace onion::detail {

/// \class SchedulerTaskQueue
/// \brief
///   For internal usage. Work-stealing queue for tasks in scheduler.
class SchedulerTaskQueue {
public:
    /// \brief
    ///   Initialize this work-stealing queue with the specified size.
    /// \param capacity
    ///   Expected maximum number of tasks that could be stored in this queue. This value will
    ///   always be rounded up to the block size.
    ONION_API explicit SchedulerTaskQueue(std::size_t capacity) noexcept;

    /// \brief
    ///   Copy constructor of \c SchedulerTaskQueue. Copying \c SchedulerTaskQueue is not concurrent
    ///   safe.
    /// \param other
    ///   The \c SchedulerTaskQueue to copy from.
    ONION_API SchedulerTaskQueue(const SchedulerTaskQueue &other) noexcept;

    /// \brief
    ///   Move constructor of \c SchedulerTaskQueue. Moving \c SchedulerTaskQueue is not concurrent
    ///   safe.
    /// \param[inout] other
    ///   The \c SchedulerTaskQueue to move from. The moved \c SchedulerTaskQueue will be in a valid
    ///   but undefined state.
    ONION_API SchedulerTaskQueue(SchedulerTaskQueue &&other) noexcept;

    /// \brief
    ///   Destroy this work-stealing queue and release memory.
    ONION_API ~SchedulerTaskQueue() noexcept;

    /// \brief
    ///   Copy assignment operator of \c SchedulerTaskQueue. Copying \c SchedulerTaskQueue is not
    ///   concurrent safe.
    ///
    ///   Self-assignment is allowed but not recommended.
    /// \param other
    ///   The \c SchedulerTaskQueue to copy from.
    /// \return
    ///   Reference to this \c SchedulerTaskQueue.
    ONION_API auto operator=(const SchedulerTaskQueue &other) noexcept -> SchedulerTaskQueue &;

    /// \brief
    ///   Move assignment operator of \c SchedulerTaskQueue. Moving \c SchedulerTaskQueue is not
    ///   concurrent safe.
    ///
    ///   Self-assignment is allowed but not recommended.
    /// \param[inout] other
    ///   The \c SchedulerTaskQueue to move from. The moved \c SchedulerTaskQueue will be in a valid
    ///   but undefined state.
    /// \return
    ///   Reference to this \c SchedulerTaskQueue.
    ONION_API auto operator=(SchedulerTaskQueue &&other) noexcept -> SchedulerTaskQueue &;

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
    /// \class TaskBlock
    /// \brief
    ///   Block of tasks in the work-stealing queue.
    class TaskBlock;

    std::size_t m_mask;
    std::atomic_size_t m_ownerIndex;
    std::atomic_size_t m_thiefIndex;
    std::vector<TaskBlock> m_blocks;
};

} // namespace onion::detail

namespace onion {

/// \class Scheduler
/// \brief
///   Scheduler for asynchronous tasks. Static thread pool is used.
class Scheduler;

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
#endif

/// \class SchedulerWorker
/// \brief
///   Worker for \c Scheduler. Workers are dispatched by \c Scheduler one per thread to execute
///   tasks.
class SchedulerWorker {
public:
    /// \brief
    ///   Create a new worker for the given scheduler and initialize the IO multiplexer. \c IOCP
    ///   will be used for Windows, \c io_uring will be used for Linux and \c kqueue will be used
    ///   for BSD.
    /// \param[in] scheduler
    ///   Owner scheduler of this worker.
    /// \param index
    ///   Index of this worker in the owner scheduler.
    /// \throws std::system_error
    ///   Thrown if failed to create IO multiplexer.
    ONION_API SchedulerWorker(Scheduler &scheduler, std::size_t index);

    /// \brief
    ///   \c SchedulerWorker is not copyable.
    SchedulerWorker(const SchedulerWorker &other) = delete;

    /// \brief
    ///   Move constructor of \c SchedulerWorker. This is implemented so that \c SchedulerWorker
    ///   objects could be managed in \c std::vector. This constructor should not be used directly.
    /// \param[inout] other
    ///   The worker to move from. The moved worker will be in a valid but undefined state.
    ONION_API SchedulerWorker(SchedulerWorker &&other) noexcept;

    /// \brief
    ///   Destroy this worker. The worker must be stopped before destroying.
    ONION_API ~SchedulerWorker() noexcept;

    /// \brief
    ///   \c SchedulerWorker is not copyable.
    auto operator=(const SchedulerWorker &other) = delete;

    /// \brief
    ///   \c SchedulerWorker is not move-assignable.
    auto operator=(SchedulerWorker &&other) = delete;

    /// \brief
    ///   Start this worker to process IO events. This method will block current thread until the
    ///   worker is stopped.
    ///
    ///   You are not supposed to call this method in multiple threads. \c std::terminate will be
    ///   called if hazard is detected.
    ONION_API auto start() noexcept -> void;

    /// \brief
    ///   Request this worker to stop. This method only sends a stop request to this worker and
    ///   returns immediately. This method is concurrent safe.
    ONION_API auto stop() noexcept -> void;

    /// \brief
    ///   Schedule a task in this worker. This method is not concurrent safe and could only be
    ///   called in owner thread.
    /// \tparam T
    ///   Type of the result of the task.
    /// \param task
    ///   The task to be scheduled. Ownership of the task will be transferred to this worker. The
    ///   scheduled task must be the stack bottom of the coroutine call stack.
    template <typename T>
    auto schedule(Task<T> task) noexcept -> void {
        auto coroutine = task.detach();
        this->schedule(static_cast<PromiseBase &>(coroutine.promise()));
    }

    /// \brief
    ///   For internal usage. Schedule a task in this worker. This method is not concurrent safe and
    ///   could only be called in owner thread.
    /// \param[in] promise
    ///   Promise of the task to be scheduled.
    auto schedule(PromiseBase &promise) noexcept -> void {
        if (!m_taskQueue.tryPush(&promise)) [[unlikely]]
            m_localTasks.push_back(&promise);
    }

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   For internal usage. Get IOCP of this worker.
    /// \return
    ///   IOCP handle of this worker.
    auto ioMultiplexer() const noexcept -> void * {
        return m_iocp;
    }
#endif

    /// \brief
    ///   Get worker for current thread.
    /// \return
    ///   Reference to the worker for current thread. The return value is \c nullptr if current
    ///   thread is not a worker thread.
    [[nodiscard]]
    ONION_API static auto threadWorker() noexcept -> SchedulerWorker *;

private:
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

    /// \brief
    ///   For internal usage. For Win32 only. Schedule a task in this worker with timeout. The
    ///   scheduled task will be executed after the timeout. This method is not concurrent safe and
    ///   could only be called in owner thread.
    /// \param[in] promise
    ///   Pointer to the promise of the task to be scheduled.
    /// \param timeout
    ///   Timeout in milliseconds.
    auto schedule(PromiseBase &promise, std::uint32_t timeout) noexcept -> void;

    friend class SleepAwaitable;
#endif

    /// \brief
    ///   A flag that indicates whether this worker is running.
    std::atomic_bool m_isRunning;

    /// \brief
    ///   A flag that indicates whether this worker should stop.
    std::atomic_bool m_shouldStop;

    /// \brief
    ///   Owner scheduler of this worker. Not null.
    Scheduler *m_scheduler;

    /// \brief
    ///   Index of this worker in the scheduler. This is used for randomly choosing a worker to
    ///   steal tasks. It is guaranteed that indices starts from 0 and are continuous.
    std::size_t m_index;

    /// \brief
    ///   Random number generator used to random select a worker for task stealing.
    std::minstd_rand m_random;

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
#endif

    /// \brief
    ///   Task queue for this worker.
    SchedulerTaskQueue m_taskQueue;

    /// \brief
    ///   Overflow task queue for this worker. This queue could only be used by the owner worker.
    std::vector<PromiseBase *> m_localTasks;
};

} // namespace detail

/// \class Scheduler
/// \brief
///   Scheduler for asynchronous tasks. Static thread pool is used.
class Scheduler {
public:
    /// \brief
    ///   Create a new \c Scheduler with workers. Number of workers will be equal to the number of
    ///   hardware threads.
    /// \throws std::system_error
    ///   Thrown if any worker failed to initialize IO multiplexer.
    ONION_API Scheduler();

    /// \brief
    ///   Create a new \c Scheduler with specified number of workers.
    /// \param count
    ///   Expected number of workers to be created. Number of workers will be determined by the
    ///   number of hardware threads if this value is 0.
    /// \throws std::system_error
    ///   Thrown if any worker failed to initialize IO multiplexer.
    ONION_API explicit Scheduler(std::size_t count);

    /// \brief
    ///   \c Scheduler is not copyable.
    Scheduler(const Scheduler &other) = delete;

    /// \brief
    ///   \c Scheduler is not movable.
    Scheduler(Scheduler &&other) = delete;

    /// \brief
    ///   Destroy this \c Scheduler. All workers must be stopped before destroying.
    ONION_API ~Scheduler() noexcept;

    /// \brief
    ///   \c Scheduler is not copyable.
    auto operator=(const Scheduler &other) = delete;

    /// \brief
    ///   \c Scheduler is not movable.
    auto operator=(Scheduler &&other) = delete;

    /// \brief
    ///   Get number of workers in this \c Scheduler.
    /// \return
    ///   Number of workers in this \c Scheduler.
    [[nodiscard]]
    auto size() const noexcept -> std::size_t {
        return m_workers.size();
    }

    /// \brief
    ///   Get all workers in this \c Scheduler.
    /// \return
    ///   Span of all workers in this \c Scheduler.
    [[nodiscard]]
    auto workers() noexcept -> std::span<detail::SchedulerWorker> {
        return m_workers;
    }

    /// \brief
    ///   Start all workers in this \c Scheduler. This method will block current thread until all
    ///   workers are stopped.
    ///
    ///   You are not supposed to call this method for multiple times. \c std::terminate will be
    ///   called if hazard is detected.
    ONION_API auto start() noexcept -> void;

    /// \brief
    ///   Request all workers in this \c Scheduler to stop. This method only sends a stop request to
    ///   all workers and returns immediately. This method is concurrent safe.
    ONION_API auto stop() noexcept -> void;

    /// \brief
    ///   Dispatch tasks into all workers in this \c Scheduler. This method is not concurrent safe
    ///   and should not be called when workers are running.
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
        // This method is not concurrent safe. Terminate if data hazard happens.
        if (m_isRunning.load(std::memory_order_relaxed)) [[unlikely]]
            std::terminate();

        for (std::size_t i = 0; i < m_workers.size(); ++i)
            m_workers[i].schedule(func(i));
    }

    /// \brief
    ///   Dispatch tasks into all workers in this \c Scheduler. This method is not concurrent safe
    ///   and should not be called when workers are running.
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
        // This method is not concurrent safe. Terminate if data hazard happens.
        if (m_isRunning.load(std::memory_order_relaxed)) [[unlikely]]
            std::terminate();

        for (auto &worker : m_workers)
            worker.schedule(func(args...));
    }

    /// \brief
    ///   Random select a worker to schedule a task. This method is not concurrent safe and should
    ///   not be called when workers are running. Program will terminate if workers are running.
    /// \tparam T
    ///   Return type of the task to be scheduled.
    /// \param task
    ///   The task to be scheduled. The scheduled task should be the stack bottom of the coroutine
    ///   call stack.
    template <typename T>
    auto schedule(Task<T> task) noexcept -> void {
        // This method is not concurrent safe. Terminate if data hazard happens.
        if (m_isRunning.load(std::memory_order_relaxed)) [[unlikely]]
            std::terminate();

        auto distribution = std::uniform_int_distribution<std::size_t>(0, m_workers.size() - 1);
        auto index        = distribution(m_random);

        m_workers[index].schedule<T>(std::move(task));
    }

private:
    /// \brief
    ///   Running flag for this scheduler.
    std::atomic_bool m_isRunning;

    /// \brief
    ///   Random number generator used to random select a worker for task scheduling.
    std::minstd_rand m_random;

    /// \brief
    ///   Worker list for this scheduler.
    std::vector<detail::SchedulerWorker> m_workers;
};

} // namespace onion
