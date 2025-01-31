#pragma once

#include "error.hpp"
#include "scheduler.hpp"

#include <bit>
#include <cstdint>
#include <expected>

namespace onion::detail {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Windows socket handle type.
using socket_t = std::uintptr_t;
#else
/// \brief
///   Unix socket handle type.
using socket_t = int;
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Invalid socket handle value. This is the same as \c INVALID_SOCKET in WinSock.
inline constexpr socket_t InvalidSocket = ~socket_t{0};
#else
/// \brief
///   Invalid socket handle value.
inline constexpr socket_t InvalidSocket = -1;
#endif

/// \brief
///   Convert a 16-bit value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
[[nodiscard]]
constexpr auto toNetworkEndian(std::uint16_t value) noexcept -> std::uint16_t {
    if constexpr (std::endian::native == std::endian::little) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(value);
#else
        return (value >> 8) | (value << 8);
#endif
    } else {
        return value;
    }
}

/// \brief
///   Convert a 16-bit value from network endian into host endian.
/// \param value
///   The value to be converted into host endian.
/// \return
///   The value converted into host endian.
[[nodiscard]]
constexpr auto toHostEndian(std::uint16_t value) noexcept -> std::uint16_t {
    return toNetworkEndian(value);
}

/// \brief
///   Convert a 32-bit value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
[[nodiscard]]
constexpr auto toNetworkEndian(std::uint32_t value) noexcept -> std::uint32_t {
    if constexpr (std::endian::native == std::endian::little) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(value);
#else
        return (value >> 24) | ((value >> 8) & 0xFF00) | ((value << 8) & 0xFF0000) | (value << 24);
#endif
    } else {
        return value;
    }
}

/// \brief
///   Convert a 32-bit value from network endian into host endian.
/// \param value
///   The value to be converted into host endian.
/// \return
///   The value converted into host endian.
[[nodiscard]]
constexpr auto toHostEndian(std::uint32_t value) noexcept -> std::uint32_t {
    return toNetworkEndian(value);
}

/// \enum SocketAddressFamily
/// \brief
///   Socket address family. The enum values are the same as system \c AF_* values.
enum class SocketAddressFamily : std::uint16_t {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    Unspecified = 0,
    Unix        = 1,
    Internet    = 2,
    Internet6   = 23,
#elif defined(__linux) || defined(__linux__)
    Unspecified = 0,
    Unix        = 1,
    Internet    = 2,
    Internet6   = 10,
#endif
};

/// \class SendAwaitable
/// \brief
///   Awaitable object for asynchronous socket data sending.
class [[nodiscard]] SendAwaitable {
public:
    /// \brief
    ///   Create a new \c SendAwaitable object for asynchronous data sending.
    /// \param socket
    ///   The socket to send data.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    SendAwaitable(socket_t socket, const void *data, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_data{data},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async send operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data sending and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is sent or failed.
    /// \retval false
    ///   Data sending succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous send operation.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (m_ovlp.error == 0) [[likely]]
            return m_ovlp.bytes;
        return std::unexpected<SystemErrorCode>{static_cast<int>(m_ovlp.error)};
#elif defined(__linux) || defined(__linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
#endif
    }

private:
    Overlapped m_ovlp;
    socket_t m_socket;
    const void *m_data;
    std::uint32_t m_size;
};

/// \class ReceiveAwaitable
/// \brief
///   Awaitable object for asynchronous socket data receiving.
class [[nodiscard]] ReceiveAwaitable {
public:
    /// \brief
    ///   Create a new \c ReceiveAwaitable object for asynchronous data receiving.
    /// \param socket
    ///   The socket to receive data.
    /// \param[out] buffer
    ///   Pointer to start of data buffer.
    /// \param size
    ///   Size in byte of data buffer.
    ReceiveAwaitable(socket_t socket, void *buffer, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_buffer{buffer},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async receive operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data receiving and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is received or failed.
    /// \retval false
    ///   Data receiving succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous receive operation.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (m_ovlp.error == 0) [[likely]]
            return m_ovlp.bytes;
        return std::unexpected<SystemErrorCode>{static_cast<int>(m_ovlp.error)};
#elif defined(__linux) || defined(__linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
#endif
    }

private:
    Overlapped m_ovlp;
    socket_t m_socket;
    void *m_buffer;
    std::uint32_t m_size;
};

} // namespace onion::detail
