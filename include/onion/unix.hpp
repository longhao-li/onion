#pragma once

#include "socket.hpp"

namespace onion {

/// \class UnixSocketAddress
/// \brief
///   \c UnixSocketAddress represents a Unix domain socket address.
class [[nodiscard]] UnixSocketAddress {
public:
    /// \brief
    ///   Create an empty Unix domain socket address. An empty \c UnixSocketAddress object will be
    ///   treated as a null abstract Unix socket address.
    constexpr UnixSocketAddress() noexcept
        : m_family{detail::SocketAddressFamily::Unix},
          m_path{} {}

    /// \brief
    ///   Create a Unix domain socket address with a specified path.
    /// \param path
    ///   The path of the Unix domain socket address.
    /// \throws std::invalid_argument
    ///   Thrown if \p path is too long for a Unix domain socket address.
    constexpr UnixSocketAddress(std::string_view path)
        : m_family{detail::SocketAddressFamily::Unix},
          m_path{} {
        if (path.size() >= sizeof(m_path)) [[unlikely]]
            throw std::invalid_argument{"Path is too long for Unix domain socket address."};
        std::ranges::copy(path, m_path);
    }

    /// \brief
    ///   Get the family of this Unix domain socket address.
    /// \return
    ///   Family of this Unix domain socket address. The return value should always be
    ///   \c SocketAddressFamily::Unix.
    [[nodiscard]]
    constexpr auto family() const noexcept -> detail::SocketAddressFamily {
        return m_family;
    }

    /// \brief
    ///   Get the path of this Unix domain socket address.
    /// \return
    ///   Path of this Unix domain socket address.
    [[nodiscard]]
    constexpr auto path() const noexcept -> std::string_view {
        return m_path;
    }

    /// \brief
    ///   Checks if this Unix domain socket address is the same as another one.
    /// \param other
    ///   The Unix domain socket address to be compared with.
    /// \retval true
    ///   This Unix domain socket address is the same as \p other.
    /// \retval false
    ///   This Unix domain socket address is different from \p other.
    [[nodiscard]]
    constexpr auto operator==(const UnixSocketAddress &other) const noexcept -> bool {
        return std::char_traits<char>::compare(m_path, other.m_path, sizeof(m_path)) == 0;
    }

    /// \brief
    ///   Checks if this Unix domain socket address is different from another one.
    /// \param other
    ///   The Unix domain socket address to be compared with.
    /// \retval true
    ///   This Unix domain socket address is different from \p other.
    /// \retval false
    ///   This Unix domain socket address is the same as \p other.
    [[nodiscard]]
    constexpr auto operator!=(const UnixSocketAddress &other) const noexcept -> bool {
        return !(*this == other);
    }

private:
    detail::SocketAddressFamily m_family;
    char m_path[108];
};

/// \class UnixStream
/// \brief
///   \c UnixStream represents a Unix domain stream socket. This class could only be used in
///   workers.
class UnixStream {
public:
    /// \class ConnectAwaitable
    /// \brief
    ///   Awaitable object for asynchronous connection establishment.
    class [[nodiscard]] ConnectAwaitable {
    public:
        /// \brief
        ///   Create a new \c ConnectAwaitable object for asynchronous connection establishment.
        /// \param[in] stream
        ///   The \c UnixStream object to establish connection.
        /// \param address
        ///   The address to connect to.
        ConnectAwaitable(UnixStream &stream, const UnixSocketAddress &address) noexcept
            : m_ovlp{},
              m_socket{detail::InvalidSocket},
              m_address{&address},
              m_stream{&stream} {}

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
        [[nodiscard]]
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   Prepare for async connect operation and suspend the coroutine.
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
        ///   Prepare for asynchronous connection establishment and suspend this coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when connection is established
        ///   or failed.
        /// \retval false
        ///   Connection establishment succeeded or failed immediately and this coroutine should not
        ///   be suspended.
        [[nodiscard]]
        ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

        /// \brief
        ///   Get the result of the asynchronous connect operation.
        /// \return
        ///   Error code of the asynchronous connect operation. The error code is 0 if success.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> SystemErrorCode;

    private:
        detail::Overlapped m_ovlp;
        detail::socket_t m_socket;
        const UnixSocketAddress *m_address;
        UnixStream *m_stream;
    };

public:
    /// \brief
    ///   Create an empty \c UnixStream object. Empty \c UnixStream object is not connected to any
    ///   Unix domain socket.
    UnixStream() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   Wrap a raw Unix socket into a \c UnixStream object.
    /// \param socket
    ///   Raw Unix socket handle of the Unix domain connection.
    /// \param address
    ///   The address of the Unix domain socket.
    UnixStream(detail::socket_t socket, const UnixSocketAddress &address) noexcept
        : m_socket{socket},
          m_address{address} {}

    /// \brief
    ///   \c UnixStream is not copyable.
    UnixStream(const UnixStream &other) = delete;

    /// \brief
    ///   Move constructor of \c UnixStream.
    /// \param[inout] other
    ///   The \c UnixStream object to move. The moved \c UnixStream object will be empty.
    UnixStream(UnixStream &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this Unix domain connection and release resources.
    ONION_API ~UnixStream() noexcept;

    /// \brief
    ///   \c UnixStream is not copyable.
    auto operator=(const UnixStream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c UnixStream.
    /// \param[inout] other
    ///   The \c UnixStream object to move. The moved \c UnixStream object will be empty.
    /// \return
    ///   Reference to this \c UnixStream object.
    ONION_API auto operator=(UnixStream &&other) noexcept -> UnixStream &;

    /// \brief
    ///   Get address of the Unix domain socket. The return value could be random if this
    ///   \c UnixStream object is empty.
    /// \return
    ///   Unix domain socket address of the remote endpoint.
    [[nodiscard]]
    auto remoteAddress() const noexcept -> const UnixSocketAddress & {
        return m_address;
    }

    /// \brief
    ///   Connect to the specified peer address. This method will block current thread until the
    ///   connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c UnixStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    ONION_API auto connect(const UnixSocketAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Connect to the specified peer address asynchronously. This method will suspend this
    ///   coroutine until the connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c UnixStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    auto connectAsync(const UnixSocketAddress &address) noexcept -> ConnectAwaitable {
        return {*this, address};
    }

    /// \brief
    ///   Send data to the peer Unix socket endpoint. This method will block current thread until
    ///   the data is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    ONION_API auto send(const void *data, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode>;

    /// \brief
    ///   Send data to the peer Unix socket endpoint asynchronously. This method will suspend this
    ///   coroutine until the data is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    auto sendAsync(const void *data, std::uint32_t size) noexcept -> detail::SendAwaitable {
        return {m_socket, data, size};
    }

    /// \brief
    ///   Receive data from the peer Unix socket endpoint. This method will block current thread
    ///   until the data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    ONION_API auto receive(void *buffer, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode>;

    /// \brief
    ///   Receive data from the peer Unix socket endpoint asynchronously. This method will suspend
    ///   this coroutine until the data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    auto receiveAsync(void *buffer, std::uint32_t size) noexcept -> detail::ReceiveAwaitable {
        return {m_socket, buffer, size};
    }

    /// \brief
    ///   Set send timeout of this Unix domain connection.
    /// \tparam Rep
    ///   Type of the duration representation. See C++ reference for more information.
    /// \tparam Period
    ///   Period of the duration. See C++ reference for more information.
    /// \param timeout
    ///   Timeout duration. Use 0 or negative value for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    template <typename Rep, typename Period>
    auto setSendTimeout(std::chrono::duration<Rep, Period> timeout) noexcept -> SystemErrorCode {
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
        milliseconds      = milliseconds < 0 ? 0 : milliseconds;
        return this->setSendTimeout(static_cast<std::uint32_t>(milliseconds));
    }

    /// \brief
    ///   Set receive timeout of this Unix domain connection.
    /// \tparam Rep
    ///   Type of the duration representation. See C++ reference for more information.
    /// \tparam Period
    ///   Period of the duration. See C++ reference for more information.
    /// \param timeout
    ///   Timeout duration. Use 0 or negative value for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    template <typename Rep, typename Period>
    auto setReceiveTimeout(std::chrono::duration<Rep, Period> timeout) noexcept -> SystemErrorCode {
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
        milliseconds      = milliseconds < 0 ? 0 : milliseconds;
        return this->setReceiveTimeout(static_cast<std::uint32_t>(milliseconds));
    }

    /// \brief
    ///   Close this Unix domain connection and release all resources. Closing a \c UnixStream
    ///   object will cause errors for pending IO operations. This method does nothing if this is an
    ///   empty \c UnixStream object.
    ONION_API auto close() noexcept -> void;

private:
    /// \brief
    ///   Set send timeout of this Unix domain connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setSendTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

    /// \brief
    ///   Set receive timeout of this Unix domain connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setReceiveTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

private:
    detail::socket_t m_socket;
    UnixSocketAddress m_address;
};

/// \class UnixListener
/// \brief
///   \c UnixListener represents a Unix domain stream socket listener. This class could only be
///   used in workers.
class UnixListener {
public:
    /// \class AcceptAwaitable
    /// \brief
    ///   Awaitable object for asynchronous connection acceptance.
    class [[nodiscard]] AcceptAwaitable {
    public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        /// \brief
        ///   Create a new \c AcceptAwaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The Unix domain listener socket to accept new connection.
        explicit AcceptAwaitable(detail::socket_t listener) noexcept
            : m_ovlp{},
              m_server{listener},
              m_connection{detail::InvalidSocket},
              m_address{},
              m_padding{} {}
#elif defined(__linux) || defined(__linux__)
        /// \brief
        ///   Create a new \c AcceptAwaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The Unix domain listener socket to accept new connection.
        explicit AcceptAwaitable(detail::socket_t listener) noexcept
            : m_ovlp{},
              m_server{listener},
              m_addrlen{},
              m_address{} {}
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
        ///   Prepare for async accept operation and suspend the coroutine.
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
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when a new connection is
        ///   accepted or failed.
        /// \retval false
        ///   Connection accepting succeeded or failed immediately and this coroutine should not be
        ///   suspended.
        [[nodiscard]]
        ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

        /// \brief
        ///   Get the result of the asynchronous accept operation.
        /// \return
        ///   A \c UnixStream object that represents the new accepted Unix domain socket connection.
        ///   Otherwise, return a system error code that represents the IO error.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> std::expected<UnixStream, SystemErrorCode>;

    private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        detail::socket_t m_connection;
        UnixSocketAddress m_address;

        [[maybe_unused]]
        std::byte m_padding[16];
#elif defined(__linux) || defined(__linux__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        unsigned int m_addrlen;
        UnixSocketAddress m_address;
#endif
    };

public:
    /// \brief
    ///   Create an empty \c UnixListener object. Empty \c UnixListener object is not bound to any
    ///   Unix domain socket.
    UnixListener() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   \c UnixListener is not copyable.
    UnixListener(const UnixListener &other) = delete;

    /// \brief
    ///   Move constructor of \c UnixListener.
    /// \param[inout] other
    ///   The \c UnixListener object to move. The moved \c UnixListener object will be empty.
    UnixListener(UnixListener &&other) noexcept
        : m_socket{other.m_socket},
          m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this Unix domain listener and release resources.
    ONION_API ~UnixListener() noexcept;

    /// \brief
    ///   \c UnixListener is not copyable.
    auto operator=(const UnixListener &other) = delete;

    /// \brief
    ///   Move assignment operator of \c UnixListener.
    /// \param[inout] other
    ///   The \c UnixListener object to move. The moved \c UnixListener object will be empty.
    /// \return
    ///   Reference to this \c UnixListener object.
    ONION_API auto operator=(UnixListener &&other) noexcept -> UnixListener &;

    /// \brief
    ///   Get local address of this listener. The return value could be random if this
    ///   \c UnixListener object is empty.
    /// \return
    ///   Local address of this listener.
    [[nodiscard]]
    auto localAddress() const noexcept -> const UnixSocketAddress & {
        return m_address;
    }

    /// \brief
    ///   Start listening to the specified address. This \c UnixListener object will not be affected
    ///   if failed to bind to the specified address.
    /// \param[in] address
    ///   The Unix domain socket address to bind.
    /// \return
    ///   A system error code object that represents system error. The error code is 0 if this
    ///   operation is succeeded.
    ONION_API auto listen(const UnixSocketAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Accept a new incoming Unix domain socket connection. This method will block current thread
    ///   until a new incoming connection is established or any error occurs.
    /// \return
    ///   A \c UnixStream object that represents the new accepted Unix domain socket connection.
    ///   Otherwise, return a system error code that represents the IO error.
    [[nodiscard]]
    ONION_API auto accept() const noexcept -> std::expected<UnixStream, SystemErrorCode>;

    /// \brief
    ///   Accept a new incoming Unix domain socket connection asynchronously. This method will block
    ///   current thread until a new incoming connection is established or any error occurs.
    /// \return
    ///   A \c UnixStream object that represents the new accepted Unix domain socket connection.
    ///   Otherwise, return a system error code that represents the IO error.
    auto acceptAsync() const noexcept -> AcceptAwaitable {
        return AcceptAwaitable{m_socket};
    }

    /// \brief
    ///   Stop listening and release all resources. Closing a \c UnixListener object will cause
    ///   errors for pending accept operations. This method does nothing if this is an empty
    ///   \c UnixListener object.
    ONION_API auto close() noexcept -> void;

private:
    detail::socket_t m_socket;
    UnixSocketAddress m_address;
};

} // namespace onion
