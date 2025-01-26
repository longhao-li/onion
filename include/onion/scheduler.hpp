#pragma once

#include "task.hpp"

#include <atomic>
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
