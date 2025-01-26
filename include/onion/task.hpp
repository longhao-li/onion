#pragma once

#include <coroutine>
#include <exception>
#include <optional>
#include <utility>

namespace onion {
namespace detail {

/// \class Promise
/// \tparam T
///   Return type of the corresponding \c Task object.
/// \brief
///   Promise type for \c Task to store coroutine states and result of the coroutine.
template <typename T>
class Promise;

} // namespace detail

/// \class Task
/// \tparam T
///   Return type of this \c Task object.
/// \brief
///   \c Task represents a coroutine that can be awaited.
template <typename T = void>
class [[nodiscard]] Task {
public:
    using value_type   = T;
    using promise_type = detail::Promise<value_type>;

    /// \brief
    ///   Create a null \c Task object. Null \c Task object cannot be awaited.
    Task() noexcept : m_coroutine{} {}

    /// \brief
    ///   For internal usage. Wrap a raw coroutine handle into a \c Task object.
    /// \param coroutine
    ///   The coroutine handle to be wrapped. The wrapped coroutine handle should not be null.
    explicit Task(std::coroutine_handle<promise_type> coroutine) noexcept
        : m_coroutine{coroutine} {}

    /// \brief
    ///   \c Task is not copyable.
    Task(const Task &other) = delete;

    /// \brief
    ///   Move constructor for \c Task.
    /// \param[inout] other
    ///   The \c Task object to be moved. The moved \c Task object will be null.
    Task(Task &&other) noexcept : m_coroutine{other.m_coroutine} {
        other.m_coroutine = nullptr;
    }

    /// \brief
    ///   Destroy this \c Task object. Destroying a \c Task object will also destroy the coroutine
    ///   promise and the coroutine stack frame.
    ~Task() {
        if (m_coroutine)
            m_coroutine.destroy();
    }

    /// \brief
    ///   \c Task is not copyable.
    auto operator=(const Task &other) = delete;

    /// \brief
    ///   Move assignment for \c Task.
    /// \param[inout] other
    ///   The \c Task object to be moved. The moved \c Task object will be null.
    /// \return
    ///   Reference to this \c Task object.
    auto operator=(Task &&other) noexcept -> Task & {
        if (this == &other) [[unlikely]]
            return *this;

        if (m_coroutine)
            m_coroutine.destroy();

        m_coroutine       = other.m_coroutine;
        other.m_coroutine = nullptr;

        return *this;
    }

    /// \brief
    ///   Checks if this \c Task object has been completed.
    /// \retval true
    ///   This \c Task has been completed.
    /// \retval false
    ///   This \c Task has not been completed and could be awaited or resumed.
    [[nodiscard]]
    auto completed() const noexcept -> bool {
        return !m_coroutine || m_coroutine.done();
    }

    /// \brief
    ///   Get coroutine handle of this \c Task object.
    /// \return
    ///   The coroutine handle of this \c Task object.
    [[nodiscard]]
    auto coroutine() const noexcept -> std::coroutine_handle<promise_type> {
        return m_coroutine;
    }

    /// \brief
    ///   Detach coroutine from this \c Task object. This \c Task object will be null after this
    ///   operation and you should manage lifetime of the returned coroutine manually.
    /// \return
    ///   Coroutine handle of this \c Task that is detached.
    [[nodiscard]]
    auto detach() noexcept -> std::coroutine_handle<promise_type> {
        return std::exchange(m_coroutine, nullptr);
    }

    /// \brief
    ///   Get promise object of this coroutine. Segmentation fault will occur if this \c task object
    ///   is null.
    /// \return
    ///   Reference to the promise object of this coroutine.
    [[nodiscard]]
    auto promise() const noexcept -> promise_type & {
        return m_coroutine.promise();
    }

    /// \brief
    ///   Checks if this \c Task object is valid.
    /// \retval true
    ///   This \c Task object is valid.
    /// \retval false
    ///   This \c Task object is null.
    [[nodiscard]]
    explicit operator bool() const noexcept {
        return m_coroutine != nullptr;
    }

    /// \brief
    ///   Checks if this \c Task object is valid.
    /// \retval true
    ///   This \c Task object is null.
    /// \retval false
    ///   This \c Task object is valid.
    [[nodiscard]]
    auto operator==(std::nullptr_t) const noexcept -> bool {
        return m_coroutine == nullptr;
    }

private:
    /// \brief
    ///   Coroutine handle for this task.
    std::coroutine_handle<promise_type> m_coroutine;
};

} // namespace onion

namespace onion::detail {

/// \class PromiseBase
/// \brief
///   Base class for \c Promise types.
class PromiseBase {
public:
    /// \class FinalAwaitable
    /// \brief
    ///   For internal usage. Maintain the coroutine call stack frames and resume the caller
    ///   coroutine.
    class [[nodiscard]] FinalAwaitable {
    public:
        /// \brief
        ///   C++20 coroutine API. Always enter \c await_suspend to maintain the coroutine call
        ///   stack.
        /// \return
        ///   This method always returns \c false.
        [[nodiscard]]
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   C++20 coroutine API. Maintain the coroutine call stack and resume the caller
        ///   coroutine.
        /// \tparam T
        ///   Promise type of the current coroutine to be finalized.
        /// \param current
        ///   Coroutine handle of the current coroutine to be finalized.
        /// \return
        ///   Coroutine handle of the caller coroutine if \p current is not at the stack bottom.
        ///   Otherwise, return a noop coroutine handle.
        template <typename T>
        static auto await_suspend(std::coroutine_handle<T> current) noexcept
            -> std::coroutine_handle<> {
            std::coroutine_handle<> caller = static_cast<PromiseBase &>(current.promise()).m_caller;
            return caller ? caller : std::noop_coroutine();
        }

        /// \brief
        ///   C++20 coroutine API. Called when the suspended coroutine is resumed. Unreachable.
        static constexpr auto await_resume() noexcept -> void {}
    };

    /// \class TaskAwaitable
    /// \tparam T
    ///   Return type of the coroutine to be awaited.
    /// \brief
    ///   For internal usage. Helper awaitable type for \c Task objects to do coroutine context
    ///   switch.
    template <typename T>
    class [[nodiscard]] TaskAwaitable {
    public:
        using value_type   = T;
        using promise_type = Promise<T>;

        /// \brief
        ///   For internal usage. Create a \c TaskAwaitable object for the given coroutine. Awaiting
        ///   this object will suspend current coroutine and switch to the given coroutine.
        /// \param coroutine
        ///   Coroutine handle of the coroutine to be executed. This coroutine should not be null.
        explicit TaskAwaitable(std::coroutine_handle<T> coroutine) noexcept
            : m_coroutine{coroutine} {}

        /// \brief
        ///   C++20 coroutine API. Always enter \c await_suspend to maintain the coroutine call
        ///   stack.
        /// \return
        ///   This method always returns \c false.
        [[nodiscard]]
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   For internal usage. C++20 coroutine standard API. Suspend current coroutine and start
        ///   the callee coroutine.
        /// \tparam U
        ///   Promise type of the caller coroutine.
        /// \param caller
        ///   Handle to the caller coroutine to be suspended.
        /// \return
        ///   Handle to the callee coroutine to be resumed.
        template <typename U>
        auto await_suspend(std::coroutine_handle<U> caller) noexcept
            -> std::coroutine_handle<promise_type> {
            auto &promise = static_cast<PromiseBase &>(m_coroutine.promise());

            promise.m_caller      = caller;
            promise.m_stackBottom = caller.promise().m_stackBottom;

            return m_coroutine;
        }

        /// \brief
        ///   For internal usage. C++20 coroutine standard API. Get the result of the callee
        ///   coroutine.
        /// \return
        ///   The result of the callee coroutine.
        auto await_resume() const -> decltype(auto) {
            return std::move(m_coroutine.promise()).result();
        }

    private:
        std::coroutine_handle<promise_type> m_coroutine;
    };

public:
    /// \brief
    ///   Create a \c PromiseBase object.
    PromiseBase() noexcept : m_coroutine{}, m_caller{}, m_stackBottom{}, m_exception{} {}

    /// \brief
    ///   \c PromiseBase is not copyable.
    PromiseBase(const PromiseBase &other) = delete;

    /// \brief
    ///   \c PromiseBase is not movable.
    PromiseBase(PromiseBase &&other) = delete;

    /// \brief
    ///   Destroy this \c PromiseBase object.
    ~PromiseBase() = default;

    /// \brief
    ///   \c PromiseBase is not copyable.
    auto operator=(const PromiseBase &other) = delete;

    /// \brief
    ///   \c PromiseBase is not movable.
    auto operator=(PromiseBase &&other) = delete;

    /// \brief
    ///   C++20 coroutine API. \c Task should always be suspended once it is created.
    /// \return
    ///   This method always returns an empty \c std::suspend_always object.
    [[nodiscard]]
    static constexpr auto initial_suspend() noexcept -> std::suspend_always {
        return {};
    }

    /// \brief
    ///   C++20 coroutine API. Maintain the coroutine call stack and resume the caller coroutine.
    /// \return
    ///   This method always returns an empty \c FinalAwaitable object.
    [[nodiscard]]
    static constexpr auto final_suspend() noexcept -> FinalAwaitable {
        return {};
    }

    /// \brief
    ///   For internal usage. C++20 coroutine API. Capture and store the exception thrown by current
    ///   coroutine.
    auto unhandled_exception() noexcept -> void {
        m_exception = std::current_exception();
    }

    /// \brief
    ///   Get coroutine handle of this promise.
    ///
    ///   Maybe we could directly cast \c std::coroutine_handle<> into \c
    ///   std::coroutine_handle<PromiseBase> to get promise object, but the C++ reference did not
    ///   mention this. So we cache coroutine handle for promise object in the promise object
    ///   itself.
    /// \return
    ///   The coroutine handle of this promise.
    [[nodiscard]]
    auto coroutine() const noexcept -> std::coroutine_handle<> {
        return m_coroutine;
    }

    /// \brief
    ///   Get the stack bottom coroutine handle. For the stack bottom coroutine itself, this method
    ///   returns the handle to itself.
    /// \return
    ///   The stack bottom coroutine handle.
    [[nodiscard]]
    auto stackBottom() const noexcept -> std::coroutine_handle<> {
        return m_stackBottom;
    }

    /// \brief
    ///   C++20 coroutine API. Suspend current coroutine and switch to the given coroutine.
    /// \tparam T
    ///   Promise type of the coroutine to be awaited.
    /// \param coroutine
    ///   Coroutine handle of the coroutine to be awaited.
    /// \return
    ///   \c TaskAwaitable object to suspend current coroutine and switch to the given coroutine.
    template <typename T>
    auto await_transform(const Task<T> &task) const noexcept -> TaskAwaitable<T> {
        return TaskAwaitable<T>{task.coroutine()};
    }

protected:
    /// \brief
    ///   Coroutine handle to current coroutine.
    std::coroutine_handle<> m_coroutine;

    /// \brief
    ///   Coroutine handle to the caller coroutine.
    std::coroutine_handle<> m_caller;

    /// \brief
    ///   Coroutine handle to the stack bottom of the current coroutine.
    std::coroutine_handle<> m_stackBottom;

    /// \brief
    ///   Exception thrown by current coroutine.
    std::exception_ptr m_exception;
};

/// \class Promise
/// \tparam T
///   Return type of the corresponding \c Task object.
/// \brief
///   Promise type for \c Task to store coroutine states and result of the coroutine.
template <typename T>
class Promise final : public PromiseBase {
public:
    /// \brief
    ///   Create a new \c Promise object.
    Promise() noexcept : PromiseBase{}, m_value{} {}

    /// \brief
    ///   C++20 coroutine API. Create a \c Task object from this \c Promise object.
    /// \return
    ///   The \c Task object that refers to this \c Promise object.
    [[nodiscard]]
    auto get_return_object() noexcept -> Task<T> {
        auto coroutine = std::coroutine_handle<Promise>::from_promise(*this);
        m_coroutine    = coroutine;
        m_stackBottom  = coroutine;
        return Task<T>{coroutine};
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
        m_value.emplace(std::forward<Arg>(value));
    }

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with
    ///   an exception.
    /// \return
    ///   Reference to the return value of the coroutine.
    [[nodiscard]]
    auto result() -> T && {
        if (m_exception != nullptr) [[unlikely]]
            std::rethrow_exception(m_exception);
        return *std::move(m_value);
    }

private:
    /// \brief
    ///   Result of the coroutine.
    std::optional<T> m_value;
};

/// \class Promise
/// \tparam T
///   Return type of the corresponding \c Task object.
/// \brief
///   Partial specialization of \c Promise for reference types.
template <typename T>
class Promise<T &> final : public PromiseBase {
public:
    /// \brief
    ///   Create a new \c Promise object.
    Promise() noexcept : PromiseBase{}, m_value{} {}

    /// \brief
    ///   C++20 coroutine API. Create a \c Task object from this \c Promise object.
    /// \return
    ///   The \c Task object that refers to this \c Promise object.
    [[nodiscard]]
    auto get_return_object() noexcept -> Task<T &> {
        auto coroutine = std::coroutine_handle<Promise>::from_promise(*this);
        m_coroutine    = coroutine;
        m_stackBottom  = coroutine;
        return Task<T &>{coroutine};
    }

    /// \brief
    ///   C++20 coroutine API. Stores return value of the coroutine.
    /// \param[in] value
    ///   Return value of the coroutine.
    auto return_value(T &value) noexcept -> void {
        m_value = std::addressof(value);
    }

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with
    ///   an exception.
    /// \return
    ///   Reference to the return value of the coroutine.
    [[nodiscard]]
    auto result() -> T & {
        if (m_exception != nullptr) [[unlikely]]
            std::rethrow_exception(m_exception);
        return *m_value;
    }

private:
    /// \brief
    ///   Result of the coroutine.
    T *m_value;
};

/// \class Promise
/// \brief
///   Specialization of \c Promise for \c void return type.
template <>
class Promise<void> final : public PromiseBase {
public:
    /// \brief
    ///   Create a new \c Promise object.
    Promise() noexcept : PromiseBase{} {}

    /// \brief
    ///   C++20 coroutine API. Create a \c Task object from this \c Promise object.
    /// \return
    ///   The \c Task object that refers to this \c Promise object.
    [[nodiscard]]
    auto get_return_object() noexcept -> Task<void> {
        auto coroutine = std::coroutine_handle<Promise>::from_promise(*this);
        m_coroutine    = coroutine;
        m_stackBottom  = coroutine;
        return Task<void>{coroutine};
    }

    /// \brief
    ///   C++20 coroutine API. Stores return value of the coroutine.
    auto return_void() noexcept -> void {}

    /// \brief
    ///   Get result of this coroutine. Exceptions may be thrown if the coroutine is completed with
    ///   an exception.
    auto result() -> void {
        if (m_exception != nullptr) [[unlikely]]
            std::rethrow_exception(m_exception);
    }
};

} // namespace onion::detail
