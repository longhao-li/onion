#include "onion/io_context.hpp"

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
#    include <sys/utsname.h>
#endif

#include <thread>

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
/// \brief
///   Create an unsigned int that represents a version number.
/// \param major
///   Major linux kernel version number.
/// \param minor
///   Minor linux kernel version number.
/// \param patch
///   Patch linux kernel version number.
[[nodiscard]] static auto make_version(std::uint8_t major, std::uint8_t minor, std::uint8_t patch) noexcept
    -> std::uint32_t {
    return (static_cast<std::uint32_t>(major) << 16) | (static_cast<std::uint32_t>(minor) << 8) | patch;
}

/// \brief
///   Get current linux kernel version. This is used to check if certain \c io_uring features are
///   supported.
/// \return
///   An unsigned integer that represents current linux kernel version. This is created via function
///   \c make_version.
[[nodiscard]] static auto kernel_version() noexcept -> std::uint32_t {
    std::uint8_t versions[3]{};

    struct utsname name;
    if (::uname(&name) != 0)
        return 0;

    std::string_view s = name.release;
    std::uint8_t    *v = versions;

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

    return make_version(versions[0], versions[1], versions[2]);
}

/// \brief
///   Get available \c io_uring setup flags according to current kernel version.
/// \return
///   Available \c io_uring setup flags.
[[nodiscard]] static auto io_uring_setup_flags() noexcept -> std::uint32_t {
    std::uint32_t flags   = IORING_SETUP_CLAMP;
    std::uint32_t version = kernel_version();

    if (version >= make_version(5, 18, 0))
        flags |= IORING_SETUP_SUBMIT_ALL;

    if (version >= make_version(5, 19, 0)) {
        flags |= IORING_SETUP_COOP_TASKRUN;
        flags |= IORING_SETUP_TASKRUN_FLAG;
    }

    return flags;
}

/// \brief
///   Get available \c io_uring feature flags according to current kernel version.
/// \return
///   Available \c io_uring feature flags.
[[nodiscard]] static auto io_uring_setup_features() noexcept -> std::uint32_t {
    std::uint32_t features = 0;
    std::uint32_t version  = kernel_version();

    if (version >= make_version(5, 4, 0))
        features |= IORING_FEAT_SINGLE_MMAP;

    if (version >= make_version(5, 5, 0))
        features |= IORING_FEAT_NODROP;

    if (version >= make_version(5, 6, 0))
        features |= IORING_FEAT_RW_CUR_POS;

    if (version >= make_version(5, 7, 0))
        features |= IORING_FEAT_FAST_POLL;

    if (version >= make_version(5, 12, 0))
        features |= IORING_FEAT_NATIVE_WORKERS;

    return features;
}
#endif

/// \brief
///   \c io_context for each thread.
static thread_local onion::io_context *current_io_context;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
onion::io_context::io_context()
    : m_running{false},
      m_frequency{0},
      m_iocp{nullptr},
      m_timeouts{},
      m_tasks{},
      m_mutex{},
      m_external{} {
    { // Start up Windows socket library.
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) [[unlikely]]
            throw std::system_error{WSAGetLastError(), std::system_category(),
                                    "Failed to start up Windows socket library"};
    }

    // Create IOCP for Windows.
    this->m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (this->m_iocp == nullptr) [[unlikely]] {
        int error = static_cast<int>(GetLastError());
        WSACleanup();
        throw std::system_error{error, std::system_category(), "Failed to create IOCP"};
    }

    // Get performance counter frequency.
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    this->m_frequency = frequency.QuadPart / 1000;

    // Reserve some memory for tasks and external handles.
    this->m_tasks.reserve(128);
    this->m_external.reserve(128);
}
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
onion::io_context::io_context() : m_running{false}, m_uring{}, m_wakeup{-1}, m_tasks{}, m_mutex{}, m_external{} {
    // Create event file descriptor for wake up.
    this->m_wakeup = eventfd(0, EFD_CLOEXEC);
    if (this->m_wakeup == -1) [[unlikely]]
        throw std::system_error{errno, std::system_category(), "Failed to create eventfd"};

    // Create io_uring.
    io_uring_params params{};
    params.flags    = io_uring_setup_flags();
    params.features = io_uring_setup_features();

    int result = io_uring_queue_init_params(32768, &this->m_uring, &params);
    if (result != 0) [[unlikely]] {
        close(this->m_wakeup);
        throw std::system_error{-result, std::system_category(), "Failed to create io_uring"};
    }

    // Reserve some memory for tasks and external handles.
    this->m_tasks.reserve(128);
    this->m_external.reserve(128);
}
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
onion::io_context::~io_context() noexcept {
    // io_context must be stopped before destruction.
    if (this->is_running()) [[unlikely]]
        std::terminate();

    CloseHandle(this->m_iocp);
    WSACleanup();
}
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
onion::io_context::~io_context() noexcept {
    // io_context must be stopped before destruction.
    if (this->is_running()) [[unlikely]]
        std::terminate();

    io_uring_queue_exit(&this->m_uring);
    close(this->m_wakeup);
}
#endif

auto onion::io_context::run() noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Stop flag.
    bool stop = false;

    // Local task buffer.
    std::vector<promise_base *> local_tasks;
    local_tasks.reserve(128);

    // Performance counter. Used to handle timeout events.
    LARGE_INTEGER now;

    // IOCP output. Bytes transferred.
    DWORD bytes = 0;

    // IOCP output. Completion key.
    ULONG_PTR key = 0;

    // IOCP output. Pointer to the specified overlapped structure.
    OVERLAPPED *ovlp = nullptr;

    // IOCP parameter. Maximum timeout value.
    DWORD timeout = 1000;

    // Result for GetQueuedCompletionStatus.
    BOOL result = FALSE;

    // Error code for GetQueuedCompletionStatus.
    DWORD error = 0;

    // Helper function to run a task.
    const auto run_task = [](promise_base *promise) -> void {
        promise_base *stack = promise->stack_bottom();
        promise->coroutine().resume();
        if (stack->coroutine().done())
            stack->release();
    };

    // Set running flag for this io_context.
    this->m_running.store(true, std::memory_order_relaxed);

    // Set thread worker.
    current_io_context = this;

    // Handle external tasks before entering event loop.
    if (this->m_has_external.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lock{this->m_mutex};
            local_tasks.swap(this->m_external);
            this->m_has_external.store(false, std::memory_order_relaxed);
        }

        for (promise_base *promise : local_tasks)
            run_task(promise);
        local_tasks.clear();
    }

    // IO event loop.
    while (!stop) [[likely]] {
        // Wait for at most 1 second.
        timeout = 1000;

        // Check for timeout events.
        if (!this->m_timeouts.empty()) {
            QueryPerformanceCounter(&now);
            std::int64_t expire = this->m_timeouts.top().when;
            std::int64_t diff   = expire - now.QuadPart;
            timeout             = std::min(static_cast<DWORD>(diff / this->m_frequency), timeout);
        }

        result = GetQueuedCompletionStatus(this->m_iocp, &bytes, &key, &ovlp, timeout);
        while (true) {
            error = ERROR_SUCCESS;
            if (result == FALSE) [[unlikely]] {
                error = GetLastError();
                if (error == WAIT_TIMEOUT) [[unlikely]]
                    break;
            }

            if (ovlp != nullptr) {
                auto *o = static_cast<overlapped_t *>(ovlp);

                o->error = static_cast<std::int32_t>(error);
                o->bytes = bytes;

                run_task(o->promise);
            } else if (key == 1) {
                stop = true;
            }

            result = GetQueuedCompletionStatus(this->m_iocp, &bytes, &key, &ovlp, 0);
        }

        // Handle timeout events.
        QueryPerformanceCounter(&now);
        while (!this->m_timeouts.empty() && this->m_timeouts.top().when <= now.QuadPart) {
            promise_base *promise = this->m_timeouts.top().promise;
            this->m_timeouts.pop();
            run_task(promise);
            // Update time.
            QueryPerformanceCounter(&now);
        }

        // Handle local tasks.
        local_tasks.swap(this->m_tasks);
        for (promise_base *promise : local_tasks)
            run_task(promise);
        local_tasks.clear();

        // Handle external tasks.
        if (this->m_has_external.load(std::memory_order_relaxed)) [[unlikely]] {
            {
                std::lock_guard<std::mutex> lock{this->m_mutex};
                local_tasks.swap(this->m_external);
                this->m_has_external.store(false, std::memory_order_relaxed);
            }

            for (promise_base *promise : local_tasks)
                run_task(promise);
            local_tasks.clear();
        }
    }

    // Unset thread worker before exiting.
    current_io_context = nullptr;

    // Unset running flag before exiting.
    this->m_running.store(false, std::memory_order_relaxed);

    return {};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    // Stop flag.
    bool stop = false;

    // Local task buffer.
    std::vector<promise_base *> local_tasks;
    local_tasks.reserve(128);

    // io_uring cqe entry.
    io_uring_cqe *cqe = nullptr;

    // io_uring timeout.
    __kernel_timespec timeout{};

    // Buffer for wakeup event file descriptor read operations.
    eventfd_t wakeup_buffer = 0;

    // Result for io_uring_submit_and_wait_timeout.
    int result;

    // Helper function to run a task.
    const auto run_task = [](promise_base *promise) -> void {
        promise_base *stack = promise->stack_bottom();
        promise->coroutine().resume();
        if (stack->coroutine().done())
            stack->release();
    };

    // Helper function to prepare for wakeup event.
    const auto prepare_wakeup = [this, &wakeup_buffer]() -> void {
        io_uring_sqe *sqe = io_uring_get_sqe(&this->m_uring);
        while (sqe == nullptr) [[unlikely]] {
            io_uring_submit(&this->m_uring);
            sqe = io_uring_get_sqe(&this->m_uring);
        }

        io_uring_prep_read(sqe, this->m_wakeup, &wakeup_buffer, sizeof(wakeup_buffer), 0);
        io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
        io_uring_sqe_set_data(sqe, nullptr);
    };

    // Set running flag for this io_context.
    this->m_running.store(true, std::memory_order_relaxed);

    // Set thread worker.
    current_io_context = this;

    // Handle external tasks before entering event loop.
    if (this->m_has_external.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lock{this->m_mutex};
            local_tasks.swap(this->m_external);
            this->m_has_external.store(false, std::memory_order_relaxed);
        }

        for (promise_base *promise : local_tasks)
            run_task(promise);
        local_tasks.clear();
    }

    // Prepare for one wakeup event before entering event loop.
    prepare_wakeup();

    while (!stop) [[likely]] {
        // Wait for at most 1 second.
        timeout.tv_sec  = 1;
        timeout.tv_nsec = 0;

        // Get pending IO events.
        result = io_uring_submit_and_wait_timeout(&this->m_uring, &cqe, 1, &timeout, nullptr);
        if (result >= 0) {
            unsigned head  = 0;
            unsigned count = 0;

            io_uring_for_each_cqe(&this->m_uring, head, cqe) {
                auto *ovlp = static_cast<overlapped_t *>(io_uring_cqe_get_data(cqe));
                if (ovlp != nullptr) [[likely]] {
                    ovlp->result = cqe->res;
                    run_task(ovlp->promise);
                } else if (wakeup_buffer >= std::numeric_limits<std::uint32_t>::max()) [[unlikely]] {
                    stop = true;
                } else {
                    prepare_wakeup();
                }

                ++count;
            }

            io_uring_cq_advance(&this->m_uring, count);
        }

        // Handle local tasks.
        local_tasks.swap(this->m_tasks);
        for (promise_base *promise : local_tasks)
            run_task(promise);
        local_tasks.clear();

        // Handle external tasks.
        if (this->m_has_external.load(std::memory_order_relaxed)) [[unlikely]] {
            {
                std::lock_guard<std::mutex> lock{this->m_mutex};
                local_tasks.swap(this->m_external);
                this->m_has_external.store(false, std::memory_order_relaxed);
            }

            for (promise_base *promise : local_tasks)
                run_task(promise);
            local_tasks.clear();
        }
    }

    // Unset thread worker before exiting.
    current_io_context = nullptr;

    // Unset running flag before exiting.
    this->m_running.store(false, std::memory_order_relaxed);

    return {};
#endif
}

auto onion::io_context::current() noexcept -> io_context * {
    return current_io_context;
}

onion::io_context_pool::io_context_pool() : io_context_pool{0} {}

onion::io_context_pool::io_context_pool(std::uint32_t size)
    : m_running{false},
      m_next{0},
      m_pool{nullptr},
      m_size{size} {
    if (this->m_size == 0)
        this->m_size = std::thread::hardware_concurrency();

    if (this->m_size == 0)
        this->m_size = 1;

    // We assume that memory allocation will not fail.
    this->m_pool = new (std::nothrow) io_context[this->m_size];
    if (this->m_pool == nullptr) [[unlikely]]
        std::terminate();
}

onion::io_context_pool::~io_context_pool() noexcept {
    // io_context_pool must be stopped before destruction.
    if (this->is_running()) [[unlikely]]
        std::terminate();

    delete[] this->m_pool;
}

auto onion::io_context_pool::run() noexcept -> void {
    this->m_running.store(true, std::memory_order_relaxed);

    std::vector<std::thread> threads;
    threads.reserve(this->m_size);

    for (auto &ctx : contexts())
        threads.emplace_back(&io_context::run, &ctx);

    for (auto &thread : threads)
        thread.join();

    this->m_running.store(false, std::memory_order_relaxed);
}
