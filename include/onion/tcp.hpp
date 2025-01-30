#pragma once

#include "error.hpp"
#include "inet_address.hpp"
#include "scheduler.hpp"

#include <expected>

namespace onion {

/// \class TcpStream
/// \brief
///   \c TcpStream represents a TCP connection. This class could only be used in workers.
class TcpStream {
public:
    /// \class ConnectAwaitable
    /// \brief
    ///   Awaitable object for asynchronous connection establishment.
    class [[nodiscard]] ConnectAwaitable {
    public:
        /// \brief
        ///   Create a new \c ConnectAwaitable object for asynchronous connection establishment.
        /// \param[in] stream
        ///   The \c TcpStream object to establish connection.
        /// \param address
        ///   The peer address to connect to.
        ConnectAwaitable(TcpStream &stream, const InetAddress &address) noexcept
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
            m_ovlp.promise = &coroutine.promise();
            return this->await_suspend();
        }

        /// \brief
        ///   Get the result of the asynchronous connect operation.
        /// \return
        ///   Error code of the asynchronous connect operation. The error code is 0 if success.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> SystemErrorCode;

    private:
        /// \brief
        ///   Prepare for asynchronous connection establishment and suspend this coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when connection is established
        ///   or failed.
        /// \retval false
        ///   Connection establishment succeeded or failed immediately and this coroutine should not
        ///   be suspended.
        ONION_API auto await_suspend() noexcept -> bool;

    private:
        detail::Overlapped m_ovlp;
        detail::socket_t m_socket;
        const InetAddress *m_address;
        TcpStream *m_stream;
    };

    /// \class SendAwaitable
    /// \brief
    ///   Awaitable object for asynchronous data sending.
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
        SendAwaitable(detail::socket_t socket, const void *data, std::uint32_t size) noexcept
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
            m_ovlp.promise = &coroutine.promise();
            return this->await_suspend();
        }

        /// \brief
        ///   Get the result of the asynchronous send operation.
        /// \return
        ///   Number of bytes sent if succeeded. Otherwise, return a system error code that
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
        /// \brief
        ///   Prepare for asynchronous data sending and suspend this coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when data is sent or failed.
        /// \retval false
        ///   Data sending succeeded or failed immediately and this coroutine should not be
        ///   suspended.
        ONION_API auto await_suspend() noexcept -> bool;

    private:
        detail::Overlapped m_ovlp;
        detail::socket_t m_socket;
        const void *m_data;
        std::uint32_t m_size;
    };

    /// \class ReceiveAwaitable
    /// \brief
    ///   Awaitable object for asynchronous data receiving.
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
        ReceiveAwaitable(detail::socket_t socket, void *buffer, std::uint32_t size) noexcept
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
            m_ovlp.promise = &coroutine.promise();
            return this->await_suspend();
        }

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
        /// \brief
        ///   Prepare for asynchronous data receiving and suspend this coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when data is received or
        ///   failed.
        /// \retval false
        ///   Data receiving succeeded or failed immediately and this coroutine should not be
        ///   suspended.
        ONION_API auto await_suspend() noexcept -> bool;

    private:
        detail::Overlapped m_ovlp;
        detail::socket_t m_socket;
        void *m_buffer;
        std::uint32_t m_size;
    };

public:
    /// \brief
    ///   Create an empty \c TcpStream object. Empty \c TcpStream object is not connected to any TCP
    ///   endpoint.
    TcpStream() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   Wrap a raw TCP socket into a \c TcpStream object.
    /// \param socket
    ///   Raw TCP socket handle of the TCP connection.
    /// \param address
    ///   Peer address of the TCP connection.
    TcpStream(detail::socket_t socket, const InetAddress &address) noexcept
        : m_socket{socket},
          m_address{address} {}

    /// \brief
    ///   \c TcpStream is not copyable.
    TcpStream(const TcpStream &other) = delete;

    /// \brief
    ///   Move constructor of \c TcpStream.
    /// \param[inout] other
    ///   The \c TcpStream object to move. The moved \c TcpStream object will be empty.
    TcpStream(TcpStream &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this TCP connection and release resources.
    ONION_API ~TcpStream() noexcept;

    /// \brief
    ///   \c TcpStream is not copyable.
    auto operator=(const TcpStream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c TcpStream.
    /// \param[inout] other
    ///   The \c TcpStream object to move. The moved \c TcpStream object will be empty.
    /// \return
    ///   Reference to this \c TcpStream object.
    ONION_API auto operator=(TcpStream &&other) noexcept -> TcpStream &;

    /// \brief
    ///   Get remote address of the TCP connection. The return value could be random if this
    ///   \c TcpStream object is empty.
    /// \return
    ///   Remote address of this TCP connection.
    [[nodiscard]]
    auto remoteAddress() const noexcept -> const InetAddress & {
        return m_address;
    }

    /// \brief
    ///   Connect to the specified peer address. This method will block current thread until the
    ///   connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c TcpStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    ONION_API auto connect(const InetAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Connect to the specified peer address asynchronously. This method will suspend this
    ///   coroutine until the connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c TcpStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    auto connectAsync(const InetAddress &address) noexcept -> ConnectAwaitable {
        return {*this, address};
    }

    /// \brief
    ///   Send data to the peer TCP endpoint. This method will block current thread until the data
    ///   is sent or any error occurs.
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
    ///   Send data to the peer TCP endpoint asynchronously. This method will suspend this coroutine
    ///   until the data is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    auto sendAsync(const void *data, std::uint32_t size) noexcept -> SendAwaitable {
        return {m_socket, data, size};
    }

    /// \brief
    ///   Receive data from the peer TCP endpoint. This method will block current thread until the
    ///   data is received or any error occurs.
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
    ///   Receive data from the peer TCP endpoint asynchronously. This method will suspend this
    ///   coroutine until the data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    auto receiveAsync(void *buffer, std::uint32_t size) noexcept -> ReceiveAwaitable {
        return {m_socket, buffer, size};
    }

    /// \brief
    ///   Enable or disable keep-alive mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable keep-alive mechanism. \c false to disable keep-alive mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setKeepAlive(bool enable) noexcept -> SystemErrorCode;

    /// \brief
    ///   Enable or disable TCP no-delay mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable TCP no-delay mechanism. \c false to disable TCP no-delay mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setNoDelay(bool enable) noexcept -> SystemErrorCode;

    /// \brief
    ///   Set send timeout of this TCP connection.
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
    ///   Set receive timeout of this TCP connection.
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
    ///   Close this TCP connection and release all resources. Closing a \c TcpStream object will
    ///   cause errors for pending IO operations. This method does nothing if this is an empty
    ///   \c TcpStream object.
    ONION_API auto close() noexcept -> void;

private:
    /// \brief
    ///   Set send timeout of this TCP connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setSendTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

    /// \brief
    ///   Set receive timeout of this TCP connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setReceiveTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

private:
    detail::socket_t m_socket;
    InetAddress m_address;
};

/// \class TcpListener
/// \brief
///   \c TcpListener represents a TCP connection listener. This class could only be used in workers.
class TcpListener {
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
        ///   The TCP listener socket to accept new connection.
        explicit AcceptAwaitable(detail::socket_t listener) noexcept
            : m_ovlp{},
              m_server{listener},
              m_connection{detail::InvalidSocket},
              m_address{} {}
#elif defined(__linux) || defined(__linux__)
        /// \brief
        ///   Create a new \c AcceptAwaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The TCP listener socket to accept new connection.
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
            m_ovlp.promise = &coroutine.promise();
            return this->await_suspend();
        }

        /// \brief
        ///   Get the result of the asynchronous accept operation.
        /// \return
        ///   A \c TcpStream object that represents the new accepted TCP connection. Otherwise,
        ///   return a system error code that represents the IO error.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> std::expected<TcpStream, SystemErrorCode>;

    private:
        /// \brief
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when a new connection is
        ///   accepted or failed.
        /// \retval false
        ///   Connection accepting succeeded or failed immediately and this coroutine should not be
        ///   suspended.
        ONION_API auto await_suspend() noexcept -> bool;

    private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        detail::socket_t m_connection;
        InetAddress m_address;

        [[maybe_unused]]
        std::byte m_padding[16];
#elif defined(__linux) || defined(__linux__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        unsigned int m_addrlen;
        InetAddress m_address;
#endif
    };

public:
    /// \brief
    ///   Create an empty \c TcpListener object. Empty \c TcpListener object is not bound to any TCP
    ///   address and cannot accept any connection.
    TcpListener() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   \c TcpListener is not copyable.
    TcpListener(const TcpListener &other) = delete;

    /// \brief
    ///   Move constructor of \c TcpListener.
    /// \param[inout] other
    ///   The \c TcpListener object to move. The moved \c TcpListener object will be empty.
    TcpListener(TcpListener &&other) noexcept
        : m_socket{other.m_socket},
          m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this TCP listener and release resources.
    ONION_API ~TcpListener() noexcept;

    /// \brief
    ///   \c TcpListener is not copyable.
    auto operator=(const TcpListener &other) = delete;

    /// \brief
    ///   Move assignment operator of \c TcpListener.
    /// \param[inout] other
    ///   The \c TcpListener object to move. The moved \c TcpListener object will be empty.
    /// \return
    ///   Reference to this \c TcpListener object.
    ONION_API auto operator=(TcpListener &&other) noexcept -> TcpListener &;

    /// \brief
    ///   Get local address of this server. The return value could be random if this \c TcpListener
    ///   object is empty.
    /// \return
    ///   Local address of this server.
    [[nodiscard]]
    auto localAddress() const noexcept -> const InetAddress & {
        return m_address;
    }

    /// \brief
    ///   Start listening to the specified address. This \c TcpListener object will not be affected
    ///   if failed to bind to the specified address.
    /// \param[in] address
    ///   The address to bind. The address could be either an IPv4 or IPv6 address.
    /// \return
    ///   A system error code object that represents system error. The error code is 0 if this
    ///   operation is succeeded.
    ONION_API auto listen(const InetAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Accept a new incoming TCP connection. This method will block current thread until a new
    ///   incoming connection is established or any error occurs.
    /// \return
    ///   A \c TcpStream object that represents the new accepted TCP connection. Otherwise, return a
    ///   system error code that represents the IO error.
    [[nodiscard]]
    ONION_API auto accept() const noexcept -> std::expected<TcpStream, SystemErrorCode>;

    /// \brief
    ///   Accept a new incoming TCP connection asynchronously. This method will suspend this
    ///   coroutine until a new incoming connection is established or any error occurs.
    /// \return
    ///   A \c TcpStream object that represents the new accepted TCP connection.
    /// \throws std::system_error
    ///   Thrown if failed to accept new connection.
    auto acceptAsync() const noexcept -> AcceptAwaitable {
        return AcceptAwaitable{m_socket};
    }

    /// \brief
    ///   Stop listening and release all resources. Closing a \c TcpListener object will cause
    ///   errors for pending accept operations. This method does nothing if this is an empty
    ///   \c TcpListener object.
    ONION_API auto close() noexcept -> void;

private:
    detail::socket_t m_socket;
    InetAddress m_address;
};

} // namespace onion
