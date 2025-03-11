#include "onion/io_context.hpp"

#include <sys/utsname.h>

#include <array>
#include <cstdlib>
#include <system_error>
#include <thread>

using namespace onion;
using namespace onion::detail;

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#    define spinPause() __asm__ volatile("pause")
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#    define spinPause() __asm__ volatile("yield")
#else
#    define spinPause() std::this_thread::yield()
#endif

/// \brief
///   Create an unsigned int that represents a version number.
/// \param major
///   Major linux kernel version number.
/// \param minor
///   Minor linux kernel version number.
/// \param patch
///   Patch linux kernel version number.
[[nodiscard]]
static auto makeVersion(std::uint8_t major, std::uint8_t minor, std::uint8_t patch) noexcept
    -> std::uint32_t {
    return (static_cast<std::uint32_t>(major) << 16) | (static_cast<std::uint32_t>(minor) << 8) |
           patch;
}

/// \brief
///   Get current linux kernel version. This is used to check if certain \c io_uring features are
///   supported.
/// \return
///   An unsigned integer that represents current linux kernel version. This is created via function
///   \c makeVersion.
[[nodiscard]]
static auto kernelVersion() noexcept -> std::uint32_t {
    std::uint8_t versions[3]{};

    struct utsname name;
    if (::uname(&name) != 0)
        return 0;

    std::string_view s = name.release;
    std::uint8_t *v    = versions;

    for (char c : s) {
        if (c >= '0' && c <= '9')
            *v = *v * 10 + static_cast<std::uint8_t>(c) - '0';
        else if (c == '.')
            ++v;
        else
            break;

        if (v >= versions + std::size(versions)) [[unlikely]]
            break;
    }

    return makeVersion(versions[0], versions[1], versions[2]);
}

/// \brief
///   Get available \c io_uring setup flags according to current kernel version.
/// \return
///   Available \c io_uring setup flags.
[[nodiscard]]
static auto ioUringSetupFlags() noexcept -> std::uint32_t {
    std::uint32_t flags   = IORING_SETUP_CLAMP;
    std::uint32_t version = kernelVersion();

    if (version >= makeVersion(5, 18, 0))
        flags |= IORING_SETUP_SUBMIT_ALL;

    if (version >= makeVersion(5, 19, 0)) {
        flags |= IORING_SETUP_COOP_TASKRUN;
        flags |= IORING_SETUP_TASKRUN_FLAG;
    }

    if (version >= makeVersion(5, 12, 0)) {
        flags &= (~IORING_SETUP_COOP_TASKRUN);
        flags &= (~IORING_SETUP_TASKRUN_FLAG);
        flags |= IORING_SETUP_SQPOLL;
    }

    return flags;
}

/// \brief
///   Get available \c io_uring feature flags according to current kernel version.
/// \return
///   Available \c io_uring feature flags.
[[nodiscard]]
static auto ioUringSetupFeatures() noexcept -> std::uint32_t {
    std::uint32_t features = 0;
    std::uint32_t version  = kernelVersion();

    if (version >= makeVersion(5, 4, 0))
        features |= IORING_FEAT_SINGLE_MMAP;

    if (version >= makeVersion(5, 5, 0))
        features |= IORING_FEAT_NODROP;

    if (version >= makeVersion(5, 6, 0))
        features |= IORING_FEAT_RW_CUR_POS;

    if (version >= makeVersion(5, 7, 0))
        features |= IORING_FEAT_FAST_POLL;

    // Enabled with IORING_SETUP_SQPOLL.
    if (version >= makeVersion(5, 12, 0)) {
        features |= IORING_FEAT_SQPOLL_NONFIXED;
        features |= IORING_FEAT_NATIVE_WORKERS;
    }

    return features;
}

namespace {

/// \brief
///   Maximum number of tasks in a \c TaskBlock.
inline constexpr std::size_t TaskBlockCapacity = 128;

/// \class TaskBlock
/// \brief
///   Block of tasks in the work-stealing queue.
class TaskBlock {
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
    TaskBlock() noexcept : m_head{}, m_tail{}, m_stealCount{}, m_stealTail{}, m_tasks{} {
        m_stealTail.store(m_tasks.size(), std::memory_order_relaxed);
    }

    /// \brief
    ///   \c TaskBlock is not copyable.
    TaskBlock(const TaskBlock &other) = delete;

    /// \brief
    ///   \c TaskBlock is not movable.
    TaskBlock(TaskBlock &&other) = delete;

    /// \brief
    ///   Destroy this task block. \c TaskBlock is trivially destructible.
    ~TaskBlock() noexcept = default;

    /// \brief
    ///   \c TaskBlock is not copyable.
    auto operator=(const TaskBlock &other) = delete;

    /// \brief
    ///   \c TaskBlock is not movable.
    auto operator=(TaskBlock &&other) = delete;

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
        m_stealCount.fetch_add(1, std::memory_order_release);

        return {Status::Success, value};
    }

    /// \brief
    ///   Take over the rest of the block. This method could only be called by the owner thread of
    ///   this block.
    /// \return
    ///   A pair of indices that indicates the range of tasks that are taken over.
    [[nodiscard]]
    auto takeover() noexcept -> std::pair<std::size_t, std::size_t> {
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
        while (m_stealCount.load(std::memory_order_acquire) != stealEnd)
            spinPause();

        m_head.store(0, std::memory_order_relaxed);
        m_tail.store(0, std::memory_order_relaxed);
        m_stealCount.store(0, std::memory_order_relaxed);
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
    alignas(64) std::atomic_size_t m_head;
    alignas(64) std::atomic_size_t m_tail;
    alignas(64) std::atomic_size_t m_stealCount;
    alignas(64) std::atomic_size_t m_stealTail;
    alignas(64) std::array<PromiseBase *, TaskBlockCapacity> m_tasks;
};

} // namespace

IoContextWorkerTaskQueue::IoContextWorkerTaskQueue(std::size_t capacity) noexcept
    : m_ownerIndex{1},
      m_thiefIndex{0},
      m_mask{},
      m_blocks{nullptr} {
    // Round up with block size.
    capacity = (capacity + TaskBlockCapacity - 1) & ~(TaskBlockCapacity - 1);
    capacity = std::max(capacity / TaskBlockCapacity, std::size_t{2});

    m_mask       = capacity - 1;
    auto *blocks = new (std::nothrow) TaskBlock[capacity];

    // We assume that the memory allocation will never fail. Explicit terminate to avoid undefined
    // behavior.
    if (blocks == nullptr) [[unlikely]]
        std::terminate();

    blocks[m_ownerIndex.load(std::memory_order_relaxed)].reclaim();
    m_blocks = blocks;
}

IoContextWorkerTaskQueue::~IoContextWorkerTaskQueue() noexcept {
    if (m_blocks != nullptr) {
        auto *blocks = static_cast<TaskBlock *>(m_blocks);
        delete[] blocks;
    }
}

auto IoContextWorkerTaskQueue::shouldSteal(std::size_t random) const noexcept -> bool {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);
    return blocks[random & m_mask].isStealable();
}

auto IoContextWorkerTaskQueue::tryPush(PromiseBase *value) noexcept -> bool {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);
    do {
        std::size_t index = m_ownerIndex.load(std::memory_order_relaxed);
        TaskBlock &block  = blocks[index & m_mask];

        if (block.tryPush(value) == TaskBlock::Status::Success)
            return true;
    } while (advancePushIndex());
    return false;
}

auto IoContextWorkerTaskQueue::tryPop() noexcept -> PromiseBase * {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);
    do {
        std::size_t index = m_ownerIndex.load(std::memory_order_relaxed);
        TaskBlock &block  = blocks[index & m_mask];

        auto [status, value] = block.tryPop();
        if (status == TaskBlock::Status::Success)
            return value;

        if (status == TaskBlock::Status::Done)
            return nullptr;
    } while (advancePopIndex());
    return nullptr;
}

auto IoContextWorkerTaskQueue::trySteal() noexcept -> PromiseBase * {
    auto *blocks      = static_cast<TaskBlock *>(m_blocks);
    std::size_t thief = 0;
    do {
        thief = m_thiefIndex.load(std::memory_order_relaxed);

        TaskBlock &block = blocks[thief & m_mask];
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

auto IoContextWorkerTaskQueue::advancePushIndex() noexcept -> bool {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);

    std::size_t owner = m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t next  = owner + 1;
    std::size_t thief = m_thiefIndex.load(std::memory_order_relaxed);

    // Wrap around occured.
    if (next - thief > m_mask)
        return false;

    // Try to acquire next block for writing.
    TaskBlock &nextBlock = blocks[next & m_mask];
    if (!nextBlock.isWritable())
        return false;

    // Release current block.
    TaskBlock &currentBlock = blocks[owner & m_mask];
    currentBlock.grant();
    m_ownerIndex.store(next, std::memory_order_relaxed);

    // Acquire next block. This must be placed after releasing current block to avoid dead lock.
    nextBlock.reclaim();

    return true;
}

auto IoContextWorkerTaskQueue::advancePopIndex() noexcept -> bool {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);

    std::size_t owner = m_ownerIndex.load(std::memory_order_relaxed);
    std::size_t prev  = owner - 1;

    TaskBlock &prevBlock = blocks[prev & m_mask];
    auto result          = prevBlock.takeover();

    if (result.first != result.second) {
        std::size_t thief = m_thiefIndex.load(std::memory_order_relaxed);
        if (thief == prev) {
            prev += m_mask + 1;
            thief += m_mask;
            m_thiefIndex.store(thief, std::memory_order_relaxed);
        }

        m_ownerIndex.store(prev, std::memory_order_relaxed);
        return true;
    }

    return false;
}

auto IoContextWorkerTaskQueue::advanceStealIndex(std::size_t current) noexcept -> bool {
    auto *blocks = static_cast<TaskBlock *>(m_blocks);

    std::size_t next     = current + 1;
    TaskBlock &nextBlock = blocks[next & m_mask];

    if (nextBlock.isStealable()) {
        m_thiefIndex.compare_exchange_strong(current, next, std::memory_order_relaxed);
        return true;
    }

    return m_thiefIndex.load(std::memory_order_relaxed) != current;
}

/// \brief
///   Worker for each thread.
static thread_local IoContextWorker *threadWorker;

IoContextWorker::IoContextWorker(IoContext &context)
    : m_isRunning{false},
      m_context{&context},
      m_maxStealRetry{std::max<std::size_t>(context.size() / 4, 1)},
      m_randomEngine{std::random_device{}()},
      m_randomDistribution{},
      m_uring{static_cast<io_uring *>(std::malloc(sizeof(io_uring)))},
      m_wakeUp{-1},
      m_taskQueue{16384},
      m_localTasksMutex{},
      m_localTasks{},
      m_hasLocalTask{false} {
    // We assumes that the memory allocation will never fail. Explicit terminate to avoid undefined
    // behavior.
    if (m_uring == nullptr) [[unlikely]]
        std::terminate();

    io_uring_params params{
        .sq_entries     = 0,
        .cq_entries     = 0,
        .flags          = ioUringSetupFlags(),
        .sq_thread_cpu  = 0,
        .sq_thread_idle = 0,
        .features       = ioUringSetupFeatures(),
        .wq_fd          = 0,
        .resv           = {},
        .sq_off         = {},
        .cq_off         = {},
    };

    int result = io_uring_queue_init_params(32768, m_uring, &params);
    if (result != 0) [[unlikely]] {
        std::free(m_uring);
        throw std::system_error{-result, std::system_category(), "Failed to create io_uring"};
    }

    // Create event file descriptor.
    m_wakeUp = eventfd(0, EFD_CLOEXEC);
    if (m_wakeUp < 0) [[unlikely]] {
        int error = errno;
        io_uring_queue_exit(m_uring);
        std::free(m_uring);
        throw std::system_error{error, std::system_category(), "Failed to create eventfd"};
    }
}

IoContextWorker::IoContextWorker(IoContextWorker &&other) noexcept
    : m_isRunning{other.m_isRunning.load(std::memory_order_relaxed)},
      m_context{other.m_context},
      m_maxStealRetry{other.m_maxStealRetry},
      m_randomEngine{std::move(other.m_randomEngine)},
      m_randomDistribution{other.m_randomDistribution},
      m_uring{other.m_uring},
      m_wakeUp{other.m_wakeUp},
      m_taskQueue{std::move(other.m_taskQueue)},
      m_localTasksMutex{},
      m_localTasks{std::move(other.m_localTasks)},
      m_hasLocalTask{other.m_hasLocalTask.load(std::memory_order_relaxed)} {
    other.m_uring  = nullptr;
    other.m_wakeUp = -1;
}

IoContextWorker::~IoContextWorker() noexcept {
    if (m_uring != nullptr) {
        io_uring_queue_exit(m_uring);
        std::free(m_uring);
        ::close(m_wakeUp);
    }
}

auto IoContextWorker::start() noexcept -> void {
    // This method could only be called once at the same time.
    if (m_isRunning.exchange(true, std::memory_order_relaxed)) [[unlikely]]
        return;

    // Set thread worker.
    threadWorker = this;

    // Update random distribution.
    m_randomDistribution = std::uniform_int_distribution<std::size_t>{0, m_context->size() - 1};

    // Stop flag.
    bool shouldStop = false;

    // Local tasks.
    std::vector<PromiseBase *> localTasks;
    localTasks.reserve(64);

    // Execute a task.
    const auto runTask = [](PromiseBase *promise) noexcept -> void {
        std::coroutine_handle<> stack = promise->stackBottom();
        promise->coroutine().resume();
        if (stack.done())
            stack.destroy();
    };

    // Steal works from another worker and execute.
    const auto stealTasks = [this, runTask]() noexcept -> void {
        auto &workers = m_context->m_workers;

        // Do not steal tasks if there is only one worker.
        if (workers.size() == 1)
            return;

        // Steal from the worker that has the most tasks.
        IoContextWorker *worker = nullptr;
        for (std::size_t i = 0; i < m_maxStealRetry; ++i) {
            std::size_t index = m_randomDistribution(m_randomEngine);
            auto &victim      = workers[index];

            // Do not steal from self.
            if (&victim == this)
                return;

            if (victim.m_taskQueue.shouldSteal(m_randomEngine())) {
                worker = &victim;
                break;
            }
        }

        if (worker == nullptr)
            return;

        PromiseBase *promise = worker->m_taskQueue.trySteal();
        while (promise != nullptr) {
            runTask(promise);
            promise = worker->m_taskQueue.trySteal();
        }
    };

    // Try to handle local tasks.
    const auto handleTasks = [this, runTask, stealTasks, &localTasks]() noexcept -> void {
        bool shouldSteal = true;

        PromiseBase *promise = m_taskQueue.tryPop();
        if (promise != nullptr)
            shouldSteal = false;

        while (promise != nullptr) {
            runTask(promise);
            promise = m_taskQueue.tryPop();
        }

        if (m_hasLocalTask.load(std::memory_order_relaxed)) {
            shouldSteal = false;

            { // Take over local tasks.
                std::lock_guard<std::mutex> lock{m_localTasksMutex};
                localTasks.swap(m_localTasks);
                m_hasLocalTask.store(false, std::memory_order_relaxed);
            }

            for (PromiseBase *task : localTasks)
                runTask(task);

            localTasks.clear();
        }

        if (shouldSteal)
            stealTasks();
    };

    io_uring_cqe *cqe = nullptr;
    __kernel_timespec timeout{};
    eventfd_t wakeUpBuffer = 0;

    // Prepare for wake up event. Older versions of linux kernel does not support multishot read. We
    // would manually simulate it.
    const auto prepareWakeup = [this, &wakeUpBuffer]() -> void {
        io_uring_sqe *sqe = io_uring_get_sqe(m_uring);
        while (sqe == nullptr) [[unlikely]] {
            // Terminate if failed to prepare or wake up event. Avoid undefined behavior.
            if (io_uring_submit(m_uring)) [[unlikely]]
                std::terminate();

            sqe = io_uring_get_sqe(m_uring);
        }

        io_uring_prep_read(sqe, m_wakeUp, &wakeUpBuffer, sizeof(wakeUpBuffer), 0);
        io_uring_sqe_set_data(sqe, nullptr);

        // Terminate if failed to prepare or wake up event. Avoid undefined behavior.
        if (io_uring_submit(m_uring) < 0) [[unlikely]]
            std::terminate();
    };

    // Handle tasks once before entering the event loop.
    prepareWakeup();
    handleTasks();
    while (!shouldStop) [[likely]] {
        // Wait for at most 1 second.
        timeout.tv_sec  = 1;
        timeout.tv_nsec = 0;

        int result = io_uring_wait_cqe_timeout(m_uring, &cqe, &timeout);
        while (result == 0) {
            auto *ovlp = static_cast<Overlapped *>(io_uring_cqe_get_data(cqe));

            if (ovlp != nullptr) [[likely]] {
                ovlp->result = cqe->res;
                this->schedule(*ovlp->promise);
            } else {
                if (wakeUpBuffer >= IoContextStopKey) [[unlikely]]
                    shouldStop = true;
                else if (wakeUpBuffer > 0)
                    prepareWakeup();
            }

            io_uring_cq_advance(m_uring, 1);
            result = io_uring_peek_cqe(m_uring, &cqe);
        }

        // Handle tasks.
        handleTasks();
    }

    // Unset thread worker.
    threadWorker = nullptr;

    // Clear running flag so that this worker could be reused.
    m_isRunning.store(false, std::memory_order_relaxed);
}

auto IoContextWorker::current() noexcept -> IoContextWorker * {
    return threadWorker;
}

IoContext::IoContext() : m_isRunning{false}, m_next{0}, m_workers{} {
    std::size_t count = std::max(std::thread::hardware_concurrency(), std::uint32_t{1});
    for (std::size_t i = 0; i < count; ++i)
        m_workers.emplace_back(*this);
}

IoContext::IoContext(std::size_t count) : m_isRunning{false}, m_next{0}, m_workers{} {
    if (count == 0)
        count = std::max(std::thread::hardware_concurrency(), std::uint32_t{1});

    for (std::size_t i = 0; i < count; ++i)
        m_workers.emplace_back(*this);
}

IoContext::~IoContext() noexcept = default;

auto IoContext::start() noexcept -> void {
    if (m_isRunning.exchange(true, std::memory_order_relaxed)) [[unlikely]]
        return;

    std::vector<std::thread> threads;
    threads.reserve(m_workers.size());

    for (auto &worker : m_workers)
        threads.emplace_back(&IoContextWorker::start, &worker);

    for (auto &thread : threads)
        thread.join();

    m_isRunning.store(false, std::memory_order_relaxed);
}
