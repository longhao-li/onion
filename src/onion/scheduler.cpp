#include "onion/scheduler.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <thread>

using namespace onion;
using namespace onion::detail;

/// \brief
///   For internal usage. Pause the current thread for a short while in spin-waiting.
static auto spinPause() noexcept -> void {
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#    if defined(__clang__) || defined(__GNUC__)
    __builtin_ia32_pause();
#    elif defined(_MSC_VER)
    _mm_pause();
#    else
    __asm__ volatile("pause" ::: "memory");
#    endif
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    __asm__ volatile("yield" ::: "memory");
#else
    std::this_thread::yield();
#endif
}

/// \class SchedulerTaskQueue::TaskBlock
/// \brief
///   Block of tasks in the work-stealing queue.
class SchedulerTaskQueue::TaskBlock {
public:
    /// \enum Status
    /// \brief
    ///   Status of block operations.
    enum class Status {
        Success,
        Done,
        Empty,
        Full,
        Conflict,
    };

public:
    /// \brief
    ///   Initialize this task block.
    TaskBlock() noexcept : m_head{}, m_tail{}, m_stealHead{}, m_stealTail{}, m_tasks{} {
        m_stealTail.store(m_tasks.size(), std::memory_order_relaxed);
    }

    /// \brief
    ///   Copy constructor of \c TaskBlock. Copying \c TaskBlock is not concurrent safe.
    /// \param other
    ///   The \c TaskBlock to copy from.
    TaskBlock(const TaskBlock &other) noexcept
        : m_head{other.m_head.load(std::memory_order_relaxed)},
          m_tail{other.m_tail.load(std::memory_order_relaxed)},
          m_stealHead{other.m_stealHead.load(std::memory_order_relaxed)},
          m_stealTail{other.m_stealTail.load(std::memory_order_relaxed)} {
        std::ranges::copy(other.m_tasks, m_tasks.begin());
    }

    /// \brief
    ///   Move constructor of \c TaskBlock. Moving \c TaskBlock is not concurrent safe.
    ///
    ///   This move constructor is actually the same as the copy constructor.
    /// \param[inout] other
    ///   The \c TaskBlock to move from.
    TaskBlock(TaskBlock &&other) noexcept : TaskBlock{other} {}

    /// \brief
    ///   Destroy this task block. \c TaskBlock is trivially destructible.
    ~TaskBlock() noexcept = default;

    /// \brief
    ///   Copy assignment operator of \c TaskBlock. Copying \c TaskBlock is not concurrent safe.
    ///
    ///   Self-assignment is allowed but not recommended.
    /// \param other
    ///   The \c TaskBlock to copy from.
    /// \return
    ///   Reference to this \c TaskBlock.
    auto operator=(const TaskBlock &other) noexcept -> TaskBlock & {
        if (this == &other) [[unlikely]]
            return *this;

        std::size_t head      = other.m_head.load(std::memory_order_relaxed);
        std::size_t tail      = other.m_tail.load(std::memory_order_relaxed);
        std::size_t stealHead = other.m_stealHead.load(std::memory_order_relaxed);
        std::size_t stealTail = other.m_stealTail.load(std::memory_order_relaxed);

        m_head.store(head, std::memory_order_relaxed);
        m_tail.store(tail, std::memory_order_relaxed);
        m_stealHead.store(stealHead, std::memory_order_relaxed);
        m_stealTail.store(stealTail, std::memory_order_relaxed);

        std::ranges::copy(other.m_tasks, m_tasks.begin());

        return *this;
    }

    /// \brief
    ///   Move assignment operator of \c TaskBlock. Moving \c TaskBlock is not concurrent safe.
    ///
    ///   This move assignment operator is actually the same as the copy assignment operator.
    /// \param[inout] other
    ///   The \c TaskBlock to move from.
    /// \return
    ///   Reference to this \c TaskBlock.
    auto operator=(TaskBlock &&other) noexcept -> TaskBlock & {
        return this->operator=(other);
    }

    /// \brief
    ///   Get the size of this task block.
    /// \return
    ///   The size of this task block.
    [[nodiscard]]
    static constexpr auto size() noexcept -> std::size_t {
        return 64;
    }

    /// \brief
    ///   Checks if this block is available for pushing tasks by owner thread.
    /// \retval true
    ///   This block is available for pushing tasks.
    /// \retval false
    ///   This block is currently being used by thief thread and is not available for pushing tasks.
    [[nodiscard]]
    auto isWritable() const noexcept -> bool {
        return m_stealTail.load(std::memory_order_relaxed) == m_tasks.size();
    }

    /// \brief
    ///   Checks if this block is available for stealing tasks by thief thread.
    /// \retval true
    ///   This block is available for stealing tasks.
    /// \retval false
    ///   This block is currently being used by owner thread and is not available for stealing
    ///   tasks.
    [[nodiscard]]
    auto isStealable() const noexcept -> bool {
        return m_stealTail.load(std::memory_order_relaxed) != m_tasks.size();
    }

    /// \brief
    ///   Try to append a task to this block.
    /// \param[in] value
    ///   Pointer to promise of the task to be appended into this block.
    auto tryPush(PromiseBase *value) noexcept -> Status {
        std::size_t back = m_tail.load(std::memory_order_relaxed);
        if (back >= m_tasks.size()) [[unlikely]]
            return Status::Full;

        m_tasks[back] = value;
        m_tail.store(back + 1, std::memory_order_release);

        return Status::Success;
    }

    /// \brief
    ///   Try to push a sequence of tasks into this block.
    /// \tparam Iterator
    ///   Type of the first iterator to acquire tasks from.
    /// \tparam Sentinel
    ///   Type of the sentinel iterator to stop acquiring tasks.
    /// \param first
    ///   The first iterator to acquire tasks from.
    /// \param last
    ///   The sentinel iterator to stop acquiring tasks.
    /// \return
    ///   Iterator to the first element that is not pushed into this block.
    template <typename Iterator, typename Sentinel>
    auto tryPush(Iterator first, Sentinel last) noexcept -> Iterator {
        std::size_t back = m_tail.load(std::memory_order_relaxed);
        for (; first != last && back < m_tasks.size(); ++first, ++back)
            m_tasks[back] = *first;

        m_tail.store(back, std::memory_order_release);
        return first;
    }

    /// \brief
    ///   Try to pop a task from this block. This method could only be called by the owner thread of
    ///   this block.
    /// \return
    ///   A status code that indicates the result of this operation and the pointer to the promise
    ///   of the task if succeeded.
    /// \retval Status::Success
    ///   The task is successfully popped.
    /// \retval Status::Done
    ///   This block is done and no more task could be popped.
    /// \retval Status::Empty
    ///   This block is empty and no task could be popped.
    [[nodiscard]]
    auto tryPop() noexcept -> std::pair<Status, PromiseBase *> {
        // This block should be taken over before reusing.
        std::size_t front = m_head.load(std::memory_order_relaxed);
        if (front == m_tasks.size()) [[unlikely]]
            return {Status::Done, nullptr};

        // This block is empty.
        std::size_t back = m_tail.load(std::memory_order_relaxed);
        if (front == back) [[unlikely]]
            return {Status::Empty, nullptr};

        PromiseBase *value = m_tasks[back - 1];
        m_tail.store(back - 1, std::memory_order_release);

        return {Status::Success, value};
    }

    /// \brief
    ///   Try to steal a task from this block. This method could only be called by the thief thread
    ///   of this block.
    /// \return
    ///   A status code that indicates the result of this operation and the pointer to the promise
    ///   of the task if succeeded.
    /// \retval Status::Success
    ///   The task is successfully stolen and \p value is set to the pointer to promise of the task.
    /// \retval Status::Done
    ///   This block is done and no more task could be stolen.
    /// \retval Status::Empty
    ///   This block is empty and no task could be stolen.
    /// \retval Status::Conflict
    ///   Another thief is stealing a task from this block.
    [[nodiscard]]
    auto trySteal() noexcept -> std::pair<Status, PromiseBase *> {
        // No more task could be stolen.
        std::size_t pos = m_stealTail.load(std::memory_order_relaxed);
        if (pos == m_tasks.size()) [[unlikely]]
            return {Status::Done, nullptr};

        // This block is empty.
        std::size_t back = m_tail.load(std::memory_order_acquire);
        if (pos == back) [[unlikely]]
            return {Status::Empty, nullptr};

        // Conflict with other threads.
        if (!m_stealTail.compare_exchange_strong(pos, pos + 1, std::memory_order_relaxed))
            return {Status::Conflict, nullptr};

        PromiseBase *value = m_tasks[pos];
        m_stealHead.fetch_add(1, std::memory_order_release);

        return {Status::Success, value};
    }

    /// \brief
    ///   Take over the rest of the block. This method could only be called by the owner thread of
    ///   this block.
    /// \return
    ///   A pair of indices that indicates the range of tasks that are taken over.
    [[nodiscard]]
    auto takeOver() noexcept -> std::pair<std::size_t, std::size_t> {
        // Marks that there is nothing to steal. Take over the rest of the block.
        std::size_t pos = m_stealTail.exchange(m_tasks.size(), std::memory_order_relaxed);

        // This block has already been taken over.
        if (pos == m_tasks.size()) [[unlikely]] {
            return {
                m_head.load(std::memory_order_relaxed),
                m_tail.load(std::memory_order_relaxed),
            };
        }

        // The rest of the block.
        m_head.store(pos, std::memory_order_relaxed);
        return {
            pos,
            m_tail.load(std::memory_order_relaxed),
        };
    }

    /// \brief
    ///   Wait for everything in this block to be stolen and then reset this block.
    auto reclaim() noexcept -> void {
        std::size_t stealEnd = m_tail.load(std::memory_order_relaxed);
        while (m_stealHead.load(std::memory_order_acquire) != stealEnd)
            spinPause();

        m_head.store(0, std::memory_order_relaxed);
        m_tail.store(0, std::memory_order_relaxed);
        m_stealHead.store(0, std::memory_order_relaxed);
        m_stealTail.store(m_tasks.size(), std::memory_order_relaxed);
    }

    /// \brief
    ///   Marks that the rest of this block could be stolen. This method could only be called in the
    ///   owner thread of this block.
    auto grant() noexcept -> void {
        std::size_t head = m_head.exchange(m_tasks.size(), std::memory_order_relaxed);
        m_stealTail.store(head, std::memory_order_relaxed);
    }

private:
    std::atomic_size_t m_head;
    std::atomic_size_t m_tail;
    std::atomic_size_t m_stealHead;
    std::atomic_size_t m_stealTail;
    std::array<PromiseBase *, 64> m_tasks;
};

SchedulerTaskQueue::SchedulerTaskQueue(std::size_t capacity) noexcept
    : m_mask{},
      m_ownerIndex{1},
      m_thiefIndex{0},
      m_blocks{} {
    // Round up with block size.
    capacity = (capacity + TaskBlock::size() - 1) & ~(TaskBlock::size() - 1);
    capacity = std::max(capacity / TaskBlock::size(), std::size_t{2});

    m_blocks.resize(capacity);
    m_mask = capacity - 1;

    m_blocks[m_ownerIndex.load(std::memory_order_relaxed)].reclaim();
}

SchedulerTaskQueue::SchedulerTaskQueue(const SchedulerTaskQueue &other) noexcept
    : m_mask{other.m_mask},
      m_ownerIndex{other.m_ownerIndex.load(std::memory_order_relaxed)},
      m_thiefIndex{other.m_thiefIndex.load(std::memory_order_relaxed)},
      m_blocks{other.m_blocks} {}

SchedulerTaskQueue::SchedulerTaskQueue(SchedulerTaskQueue &&other) noexcept
    : m_mask{other.m_mask},
      m_ownerIndex{other.m_ownerIndex.load(std::memory_order_relaxed)},
      m_thiefIndex{other.m_thiefIndex.load(std::memory_order_relaxed)},
      m_blocks{std::move(other.m_blocks)} {}

SchedulerTaskQueue::~SchedulerTaskQueue() noexcept = default;

auto SchedulerTaskQueue::operator=(const SchedulerTaskQueue &other) noexcept
    -> SchedulerTaskQueue & {
    if (this == &other) [[unlikely]]
        return *this;

    std::size_t ownerIndex = other.m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t thiefIndex = other.m_thiefIndex.load(std::memory_order_relaxed);

    m_mask = other.m_mask;
    m_ownerIndex.store(ownerIndex, std::memory_order_relaxed);
    m_thiefIndex.store(thiefIndex, std::memory_order_relaxed);
    m_blocks = other.m_blocks;

    return *this;
}

auto SchedulerTaskQueue::operator=(SchedulerTaskQueue &&other) noexcept -> SchedulerTaskQueue & {
    if (this == &other) [[unlikely]]
        return *this;

    std::size_t ownerIndex = other.m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t thiefIndex = other.m_thiefIndex.load(std::memory_order_relaxed);

    m_mask = other.m_mask;
    m_ownerIndex.store(ownerIndex, std::memory_order_relaxed);
    m_thiefIndex.store(thiefIndex, std::memory_order_relaxed);
    m_blocks = std::move(other.m_blocks);

    return *this;
}

auto SchedulerTaskQueue::tryPush(PromiseBase *value) noexcept -> bool {
    do {
        std::size_t index = m_ownerIndex.load(std::memory_order_relaxed);
        TaskBlock &block  = m_blocks[index & m_mask];

        if (block.tryPush(value) == TaskBlock::Status::Success)
            return true;
    } while (advancePushIndex());
    return false;
}

auto SchedulerTaskQueue::tryPop() noexcept -> PromiseBase * {
    do {
        std::size_t index = m_ownerIndex.load(std::memory_order_relaxed);
        TaskBlock &block  = m_blocks[index & m_mask];

        auto [status, value] = block.tryPop();
        if (status == TaskBlock::Status::Success)
            return value;

        if (status == TaskBlock::Status::Done)
            return nullptr;
    } while (advancePopIndex());
    return nullptr;
}

auto SchedulerTaskQueue::trySteal() noexcept -> PromiseBase * {
    std::size_t thief = 0;
    do {
        thief = m_thiefIndex.load(std::memory_order_relaxed);

        TaskBlock &block = m_blocks[thief & m_mask];
        auto result      = block.trySteal();
        while (result.first != TaskBlock::Status::Done) {
            if (result.first == TaskBlock::Status::Success)
                return result.second;

            if (result.first == TaskBlock::Status::Empty)
                return nullptr;

            // Conflict with other threads. Try to steal again.
            result = block.trySteal();
        }
    } while (advanceStealIndex(thief));
    return nullptr;
}

auto SchedulerTaskQueue::advancePushIndex() noexcept -> bool {
    std::size_t owner = m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t next  = owner + 1;
    std::size_t thief = m_thiefIndex.load(std::memory_order_relaxed);

    // Wrap around occured.
    if (next - thief >= m_blocks.size())
        return false;

    // Try to acquire next block for writing.
    TaskBlock &nextBlock = m_blocks[next & m_mask];
    if (!nextBlock.isWritable())
        return false;

    // Release current block.
    TaskBlock &currentBlock = m_blocks[owner & m_mask];
    currentBlock.grant();
    m_ownerIndex.store(next, std::memory_order_relaxed);

    // Acquire next block. This must be placed after releasing current block to avoid dead lock.
    nextBlock.reclaim();

    return true;
}

auto SchedulerTaskQueue::advancePopIndex() noexcept -> bool {
    std::size_t owner = m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t prev  = owner - 1;

    TaskBlock &prevBlock = m_blocks[prev & m_mask];
    auto result          = prevBlock.takeOver();

    if (result.first != result.second) {
        std::size_t thief = m_thiefIndex.load(std::memory_order_relaxed);
        if (thief == prev) {
            prev += m_blocks.size();
            thief += m_blocks.size() - 1;
            m_thiefIndex.store(thief, std::memory_order_relaxed);
        }

        m_ownerIndex.store(prev, std::memory_order_relaxed);
        return true;
    }

    return false;
}

auto SchedulerTaskQueue::advanceStealIndex(std::size_t current) noexcept -> bool {
    std::size_t next     = current + 1;
    TaskBlock &nextBlock = m_blocks[next & m_mask];

    if (nextBlock.isStealable()) {
        m_thiefIndex.compare_exchange_strong(current, next, std::memory_order_relaxed);
        return true;
    }

    return m_thiefIndex.load(std::memory_order_relaxed) != current;
}
