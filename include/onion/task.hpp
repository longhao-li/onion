#pragma once

#include <coroutine>
#include <cstdint>
#include <exception>
#include <optional>
#include <utility>

namespace onion {

/// \class promise_base
/// \brief
///   Base class for promise types.
class promise_base {
public:
    /// \struct final_awaitable
    /// \brief
    ///   For internal usage. Maintain the coroutine call stack and resume the caller coroutine.
    struct final_awaitable {
        /// \brief
        ///   C++20 coroutine API. Always return false.
        /// \return
        ///   This function always returns false.
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   C++20 coroutine API. Maintain the call stack and resume the caller coroutine.
        /// \tparam T
        ///   Promise type of the coroutine to be finalized.
        /// \param current
        ///   Coroutine handle of the coroutine to be finalized.
        /// \return
        ///   Coroutine handle of the caller coroutine if \p current is not root coroutine. Otherwise, return a noop
        ///   coroutine handle.
        template <typename T>
        static auto await_suspend(std::coroutine_handle<T> current) noexcept -> std::coroutine_handle<> {
            auto caller = static_cast<promise_base &>(current.promise()).m_caller;
            return caller ? caller : std::noop_coroutine();
        }

        /// \brief
        ///   C++20 coroutine API. Called when the suspended coroutine is resumed. Unreachable.
        static constexpr auto await_resume() noexcept -> void {}
    };

public:
    /// \brief
    ///   Create a new \c promise_base object.
    promise_base() noexcept = default;

    /// \brief
    ///   \c promise_base is not copyable.
    promise_base(const promise_base &other) = delete;

    /// \brief
    ///   \c promise_base is not movable.
    promise_base(promise_base &&other) = delete;

    /// \brief
    ///   Destroy this \c promise_base object.
    ~promise_base() = default;

    /// \brief
    ///   \c promise_base is not copyable.
    auto operator=(const promise_base &other) = delete;

    /// \brief
    ///   \c promise_base is not movable.
    auto operator=(promise_base &&other) = delete;

    /// \brief
    ///   C++20 coroutine API. \c task should always be suspended when it is created.
    /// \return
    ///   This function always returns \c std::suspend_always.
    static constexpr auto initial_suspend() noexcept -> std::suspend_always {
        return {};
    }

    /// \brief
    ///   C++20 coroutine API. Maintain the call stack and resume the caller coroutine.
    /// \return
    ///   This function always returns \c final_awaitable.
    static constexpr auto final_suspend() noexcept -> final_awaitable {
        return {};
    }

    /// \brief
    ///   C++20 coroutine API. Capture and store the exception thrown by current coroutine.
    auto unhandled_exception() noexcept -> void {
        this->m_exception = std::current_exception();
    }

    /// \brief
    ///   Increase the reference count of this \c task.
    auto acquire() noexcept -> void {
        this->m_reference_count += 1;
    }

    /// \brief
    ///   Decrease the reference count of this \c task. Destroy the coroutine if the reference count is zero.
    auto release() noexcept -> void {
        if (--this->m_reference_count == 0)
            this->m_coroutine.destroy();
    }

    /// \brief
    ///   Get coroutine handle of this \c task.
    ///
    ///   Maybe we could directly cast \c std::coroutine_handle<> into \c std::coroutine_handle<promise_base> to get
    ///   promise object, but the C++ reference did not mention this. So we cache coroutine handle for promise object in
    ///   the promise object itself.
    /// \return
    ///   Coroutine handle of this \c task.
    [[nodiscard]] auto coroutine() const noexcept -> std::coroutine_handle<> {
        return this->m_coroutine;
    }

    /// \brief
    ///   Get the stack bottom coroutine promise.
    /// \return
    ///   Pointer to the stack bottom coroutine promise.
    [[nodiscard]] auto stack_bottom() const noexcept -> promise_base * {
        return this->m_stack_bottom;
    }

    template <typename>
    friend class task_awaitable;

protected:
    /// \brief
    ///   Reference count of this coroutine.
    std::int32_t m_reference_count = 1;

    /// \brief
    ///   Coroutine handle of this coroutine.
    std::coroutine_handle<> m_coroutine = nullptr;

    /// \brief
    ///   Caller coroutine handle. This is \c nullptr if this coroutine is the root coroutine.
    std::coroutine_handle<> m_caller = nullptr;

    /// \brief
    ///   Promise of the stack bottom coroutine.
    promise_base *m_stack_bottom = this;

    /// \brief
    ///   Exception thrown by the coroutine.
    std::exception_ptr m_exception;
};

/// \class promise
/// \tparam T
///   Return type of the corresponding \c task object.
/// \brief
///   Promise type for \c task to store coroutine states and result of the coroutine.
template <typename T>
class promise;

/// \class task_awaitable
/// \tparam T
///   Return type of the coroutine to be awaited.
/// \brief
///   For internal usage. Helper awaitable type for \c task objects to do coroutine context switch.
template <typename T>
class task_awaitable {
public:
    using value_type   = T;
    using promise_type = promise<T>;

    /// \brief
    ///   For internal usage. Create a \c task_awaitable object for the given coroutine. Awaiting this object will
    ///   suspend current coroutine and switch to the given coroutine.
    /// \param coroutine
    ///   Coroutine handle of the coroutine to be executed. This coroutine should not be null.
    explicit task_awaitable(std::coroutine_handle<promise_type> coroutine) noexcept : m_coroutine{coroutine} {}

    /// \brief
    ///   C++20 coroutine API. Always return false.
    /// \return
    ///   This function always returns false.
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   C++20 coroutine API. Suspend the \p caller coroutine and enter callee coroutine.
    /// \tparam U
    ///   Promise type of the \p caller coroutine.
    /// \param caller
    ///   Coroutine handle of the \p caller coroutine.
    /// \return
    ///   Coroutine handle of the \p callee coroutine.
    template <typename U>
    auto await_suspend(std::coroutine_handle<U> caller) noexcept -> std::coroutine_handle<promise_type> {
        promise_base &promise = this->m_coroutine.promise();
        promise_base &parent  = caller.promise();

        promise.m_caller       = caller;
        promise.m_stack_bottom = parent.m_stack_bottom;

        return this->m_coroutine;
    }

    /// \brief
    ///   C++20 coroutine API. Get result of the callee coroutine.
    /// \note
    ///   This method may throw exception if the callee coroutine throws exception.
    /// \return
    ///   Result of the callee coroutine.
    [[nodiscard]] auto await_resume() const -> decltype(auto) {
        return std::move(this->m_coroutine.promise()).result();
    }

private:
    std::coroutine_handle<promise_type> m_coroutine;
};

/// \class task
/// \tparam T
///   Return type of the coroutine.
/// \brief
///   A \c task object represents a coroutine that can be awaited and called like a function.
template <typename T = void>
class task {
public:
    using value_type   = T;
    using promise_type = onion::promise<T>;

    /// \brief
    ///   Create a null \c task object. Null \c task object cannot be awaited.
    task() noexcept = default;

    /// \brief
    ///   Create a null \c task object. Null \c task object cannot be awaited.
    task(std::nullptr_t) noexcept {}

    /// \brief
    ///   For internal usage. Wrap a raw coroutine handle into a \c task object.
    /// \param coroutine
    ///   The coroutine handle to be wrapped. The wrapped coroutine handle should not be null.
    explicit task(std::coroutine_handle<promise_type> coroutine) noexcept : m_coroutine{coroutine} {}

    /// \brief
    ///   Copy constructor of \c task. Reference counting is used to manage the coroutine.
    /// \note
    ///   Atomic reference counting is not used here for performance consideration. Do not operate on the same \c task
    ///   object in different threads at the same time.
    /// \param other
    ///   The \c task object to be copied.
    task(const task &other) noexcept : m_coroutine{other.m_coroutine} {
        if (this->m_coroutine)
            this->m_coroutine.promise().acquire();
    }

    /// \brief
    ///   Move constructor of \c task.
    /// \param[inout] other
    ///   The \c task object to be moved. The moved \c task object will be null.
    task(task &&other) noexcept : m_coroutine{std::exchange(other.m_coroutine, nullptr)} {}

    /// \brief
    ///   Destroy this \c task object. Release the coroutine if this \c task object is the last reference.
    ~task() noexcept {
        if (this->m_coroutine)
            this->m_coroutine.promise().release();
    }

    /// \brief
    ///   Destroy this \c task object and reset it to null.
    /// \return
    ///   Reference to this \c task object.
    auto operator=(std::nullptr_t) noexcept -> task & {
        if (this->m_coroutine)
            this->m_coroutine.promise().release();

        this->m_coroutine = nullptr;
        return *this;
    }

    /// \brief
    ///   Copy assignment of \c task. Reference counting is used to manage the coroutine.
    /// \note
    ///   Atomic reference counting is not used here for performance consideration. Do not operate on the same \c task
    ///   object in different threads at the same time.
    /// \param other
    ///   The \c task object to be copied.
    /// \return
    ///   Reference to this \c task object.
    auto operator=(const task &other) noexcept -> task & {
        if (this->m_coroutine == other.m_coroutine) [[unlikely]]
            return *this;

        if (this->m_coroutine)
            this->m_coroutine.promise().release();

        this->m_coroutine = other.m_coroutine;
        if (this->m_coroutine)
            this->m_coroutine.promise().acquire();

        return *this;
    }

    /// \brief
    ///   Move assignment of \c task.
    /// \param[inout] other
    ///   The \c task object to be moved. The moved \c task object will be in a valid but undefined state.
    /// \return
    ///   Reference to this \c task object.
    auto operator=(task &&other) noexcept -> task & {
        if (this->m_coroutine == other.m_coroutine) [[unlikely]]
            return *this;

        if (this->m_coroutine)
            this->m_coroutine.promise().release();

        this->m_coroutine = std::exchange(other.m_coroutine, nullptr);
        return *this;
    }

    /// \brief
    ///   Checks if this \c task object has been completed. This method is not concurrent safe.
    /// \retval true
    ///   This \c task object is null or has been completed.
    /// \retval false
    ///   This \c task object has not been completed.
    [[nodiscard]] auto done() const noexcept -> bool {
        return !this->m_coroutine || this->m_coroutine.done();
    }

    /// \brief
    ///   Get coroutine handle of this \c task object.
    /// \return
    ///   Coroutine handle of this \c task object.
    [[nodiscard]] auto coroutine() const noexcept -> std::coroutine_handle<promise_type> {
        return this->m_coroutine;
    }

    /// \brief
    ///   Detach coroutine from this \c task object. This \c task object will be null after this operation and you
    ///   should manage lifetime of the returned coroutine manually.
    /// \return
    ///   Coroutine handle of this \c task that is detached.
    [[nodiscard]] auto detach() noexcept -> std::coroutine_handle<promise_type> {
        return std::exchange(this->m_coroutine, nullptr);
    }

    /// \brief
    ///   Get promise object of this coroutine. Segmentation fault will occur if this \c task object is null.
    /// \return
    ///   Reference to the promise object of this coroutine.
    [[nodiscard]] auto promise() const noexcept -> promise_type & {
        return this->m_coroutine.promise();
    }

    /// \brief
    ///   Checks if this \c task object is valid.
    /// \retval true
    ///   This \c task object is null.
    /// \retval false
    ///   This \c task object is valid.
    [[nodiscard]] auto operator==(std::nullptr_t) const noexcept -> bool {
        return m_coroutine == nullptr;
    }

    /// \brief
    ///   Checks if this \c task object is valid.
    /// \retval true
    ///   This \c task object is valid.
    /// \retval false
    ///   This \c task object is null.
    [[nodiscard]] auto operator!=(std::nullptr_t) const noexcept -> bool {
        return m_coroutine != nullptr;
    }

    /// \brief
    ///   Suspend the caller coroutine and start this one.
    /// \return
    ///   An awaitable object to suspend the caller coroutine and start this \c task coroutine.
    auto operator co_await() const noexcept -> task_awaitable<T> {
        return task_awaitable<T>{this->m_coroutine};
    }

    /// \brief
    ///   Checks if this \c task object is valid.
    /// \retval true
    ///   This \c task object is valid.
    /// \retval false
    ///   This \c task object is null.
    explicit operator bool() const noexcept {
        return this->m_coroutine != nullptr;
    }

private:
    /// \brief
    ///   Coroutine handle of the coroutine.
    std::coroutine_handle<promise_type> m_coroutine = nullptr;
};

/// \class promise
/// \tparam T
///   Return type of the corresponding \c task object.
/// \brief
///   Promise type for \c task to store coroutine states and result of the coroutine.
template <typename T>
class promise final : public promise_base {
public:
    /// \brief
    ///   Create a new \c promise object.
    promise() noexcept = default;

    /// \brief
    ///   C++20 coroutine API. Create a \c task object from this \c promise object.
    /// \return
    ///   The \c task object that refers to this \c promise object.
    [[nodiscard]] auto get_return_object() noexcept -> task<T> {
        auto coroutine    = std::coroutine_handle<promise>::from_promise(*this);
        this->m_coroutine = coroutine;
        return task<T>{coroutine};
    }

    /// \brief
    ///   C++20 coroutine API. Stores return value of the coroutine.
    /// \tparam Arg
    ///   Type of the return value. The actual return type \c T should be constructible from \p Arg.
    /// \param value
    ///   Reference to the return value of the coroutine.
    template <typename Arg = T>
        requires(std::is_constructible_v<T, Arg &&>)
    auto return_value(Arg &&value) noexcept(std::is_nothrow_constructible_v<T, Arg &&>) -> void {
        this->m_value.emplace(std::forward<Arg>(value));
    }

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with an exception.
    /// \return
    ///   Reference to the return value of the coroutine.
    [[nodiscard]] auto result() && -> T && {
        if (this->m_exception != nullptr) [[unlikely]]
            std::rethrow_exception(m_exception);
        return *std::move(this->m_value);
    }

private:
    /// \brief
    ///   Return value of current coroutine.
    std::optional<T> m_value;
};

/// \class promise
/// \tparam T
///   Return type of the corresponding \c task object.
/// \brief
///   Partial specialization of \c promise for \c task objects that returns reference types.
template <typename T>
class promise<T &> final : public promise_base {
public:
    /// \brief
    ///   Create a new \c promise object.
    promise() noexcept = default;

    /// \brief
    ///   C++20 coroutine API. Create a \c task object from this \c promise object.
    /// \return
    ///   The \c task object that refers to this \c promise object.
    [[nodiscard]] auto get_return_object() noexcept -> task<T &> {
        auto coroutine    = std::coroutine_handle<promise>::from_promise(*this);
        this->m_coroutine = coroutine;
        return task<T &>{coroutine};
    }

    /// \brief
    ///   C++20 coroutine API. Stores return value of the coroutine.
    /// \param[in] value
    ///   Return value of this coroutine.
    auto return_value(T &value) noexcept -> void {
        this->m_value = std::addressof(value);
    }

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with an exception.
    /// \return
    ///   Reference to the return value of the coroutine.
    [[nodiscard]] auto result() const -> T & {
        if (this->m_exception != nullptr) [[unlikely]]
            std::rethrow_exception(m_exception);
        return *this->m_value;
    }

private:
    /// \brief
    ///   Return value of current coroutine.
    T *m_value = nullptr;
};

/// \class promise
/// \brief
///   Specialization of \c promise for \c task objects that returns \c void.
template <>
class promise<void> final : public promise_base {
public:
    /// \brief
    ///   Create a new \c promise object.
    promise() noexcept = default;

    /// \brief
    ///   C++20 coroutine API. Create a \c task object from this \c promise object.
    /// \return
    ///   The \c task object that refers to this \c promise object.
    [[nodiscard]] auto get_return_object() noexcept -> task<void> {
        auto coroutine    = std::coroutine_handle<promise>::from_promise(*this);
        this->m_coroutine = coroutine;
        return task<void>{coroutine};
    }

    /// \brief
    ///   C++20 coroutine API. Tells compiler that the coroutine has no return value.
    auto return_void() noexcept -> void {}

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with an exception.
    auto result() const -> void {
        if (this->m_exception) [[unlikely]]
            std::rethrow_exception(m_exception);
    }
};

} // namespace onion
