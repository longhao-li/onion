#include "onion/tcp.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WS2tcpip.h>
#    include <mswsock.h>
#elif defined(__linux) || defined(__linux__)
#    include <liburing.h>
#    include <netinet/in.h>
#    include <netinet/tcp.h>
#endif

using namespace onion;
using namespace onion::detail;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Try to acquire the \c ConnectEx function pointer.
/// \return
///   The \c ConnectEx function pointer if successful. Otherwise, return \c nullptr and the error
///   code is set to \c WSAGetLastError().
[[nodiscard]]
static auto acquireConnectEx() noexcept -> LPFN_CONNECTEX {
    // Create a dummy socket to call WSAIoctl
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) [[unlikely]]
        return nullptr;

    // Get the ConnectEx function pointer
    LPFN_CONNECTEX connectEx = nullptr;

    DWORD bytes = 0;
    GUID guid   = WSAID_CONNECTEX;

    int result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &connectEx,
                          sizeof(connectEx), &bytes, nullptr, nullptr);

    if (result != 0) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        WSASetLastError(error);
        return nullptr;
    }

    closesocket(s);
    return connectEx;
}

/// \brief
///   Try to connect to a remote server asynchronously.
/// \param s
///   The socket to connect to the remote server. This socket must be manually created and bound
///   before calling this function.
/// \param[in] name
///   The address of the remote server.
/// \param namelen
///   The length of the address.
/// \param[in] sendBuffer
///   The data to send to the remote server.
/// \param sendDataLength
///   The length of the data to send.
/// \param[out] bytesSent
///   The number of bytes sent to the remote server. Note that this value should not be \c nullptr.
/// \param[inout] overlapped
///   The overlapped structure to handle the asynchronous operation.
static auto connectEx(SOCKET s,
                      const struct sockaddr *name,
                      int namelen,
                      PVOID sendBuffer,
                      DWORD sendDataLength,
                      LPDWORD bytesSent,
                      LPOVERLAPPED overlapped) noexcept -> BOOL {
    static std::atomic<LPFN_CONNECTEX> function{nullptr};

    // Try to connect if the function pointer is valid.
    LPFN_CONNECTEX connect = function.load(std::memory_order_relaxed);
    if (connect != nullptr) [[likely]]
        return connect(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);

    connect = acquireConnectEx();
    if (connect == nullptr) [[unlikely]]
        return FALSE;

    // It is safe to store the function pointer for multiple times in multiple threads. We just need
    // to ensure that one of them is correct.
    function.store(connect, std::memory_order_relaxed);
    return connect(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

/// \brief
///   Try to acquire the \c AcceptEx function pointer.
/// \return
///   The \c AcceptEx function pointer if successful. Otherwise, return \c nullptr and the error
///   code is set to \c WSAGetLastError().
[[nodiscard]]
static auto acquireAcceptEx() noexcept -> LPFN_ACCEPTEX {
    // Create a dummy socket to call WSAIoctl
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) [[unlikely]]
        return nullptr;

    // Get the AcceptEx function pointer
    LPFN_ACCEPTEX acceptEx = nullptr;

    DWORD bytes = 0;
    GUID guid   = WSAID_ACCEPTEX;

    int result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &acceptEx,
                          sizeof(acceptEx), &bytes, nullptr, nullptr);

    if (result != 0) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        WSASetLastError(error);
        return nullptr;
    }

    closesocket(s);
    return acceptEx;
}

/// \brief
///   Try to accept a new connection asynchronously.
/// \param listenSocket
///   The socket that listens for incoming connections.
/// \param acceptSocket
///   The socket that accepts the new connection.
/// \param outputBuffer
///   The buffer to store extra received data.
/// \param receiveDataLength
///   Size of the output buffer.
/// \param localAddressLength
///   Size of the local address.
/// \param remoteAddressLength
///   Size of the remote address.
/// \param[out] bytesReceived
///   The number of bytes received in output buffer.
/// \param[inout] overlapped
///   The overlapped structure for asynchronous operation.
static auto acceptEx(SOCKET listenSocket,
                     SOCKET acceptSocket,
                     PVOID outputBuffer,
                     DWORD receiveDataLength,
                     DWORD localAddressLength,
                     DWORD remoteAddressLength,
                     LPDWORD bytesReceived,
                     LPOVERLAPPED overlapped) noexcept -> BOOL {
    std::atomic<LPFN_ACCEPTEX> function(nullptr);

    // Try to accept new connection if the function pointer is valid.
    LPFN_ACCEPTEX accept = function.load(std::memory_order_relaxed);
    if (accept != nullptr) [[likely]]
        return accept(listenSocket, acceptSocket, outputBuffer, receiveDataLength,
                      localAddressLength, remoteAddressLength, bytesReceived, overlapped);

    accept = acquireAcceptEx();
    if (accept == nullptr) [[unlikely]]
        return FALSE;

    // It is safe to store the function pointer for multiple times in multiple threads. We just need
    // to ensure that one of them is correct.
    function.store(accept, std::memory_order_relaxed);
    return accept(listenSocket, acceptSocket, outputBuffer, receiveDataLength, localAddressLength,
                  remoteAddressLength, bytesReceived, overlapped);
}

/// \brief
///   A helper function to register the socket with IOCP and set the notification modes.
/// \param s
///   The socket to register.
/// \retval TRUE
///   The socket is successfully registered with IOCP and the notification modes are set.
/// \retval FALSE
///   An error occurred when registering the socket with IOCP or setting the notification modes. The
///   error code can be retrieved by calling \c GetLastError().
[[nodiscard]]
static auto registerAndSetNotificationModes(SOCKET s) noexcept -> BOOL {
    // Register the socket with IOCP.
    auto handle  = reinterpret_cast<HANDLE>(s);
    auto *worker = SchedulerWorker::threadWorker();
    if (CreateIoCompletionPort(handle, worker->ioMultiplexer(), 0, 0) == nullptr) [[unlikely]]
        return FALSE;

    // Disable IOCP notification if the IO event is handled immediately.
    UCHAR modes = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    if (SetFileCompletionNotificationModes(handle, modes) == FALSE) [[unlikely]]
        return FALSE;

    return TRUE;
}
#endif

auto TcpStream::ConnectAwaitable::await_resume() const noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_ovlp.error == 0) [[likely]] {
        if (m_stream->m_socket != INVALID_SOCKET)
            closesocket(m_stream->m_socket);

        m_stream->m_socket  = m_socket;
        m_stream->m_address = *m_address;

        return {};
    }

    if (m_socket != INVALID_SOCKET)
        closesocket(m_socket);

    return m_ovlp.error;
#elif defined(__linux) || defined(__linux__)
    if (m_ovlp.result == 0) {
        if (m_stream->m_socket != InvalidSocket)
            ::close(m_stream->m_socket);

        m_stream->m_socket  = m_socket;
        m_stream->m_address = *m_address;

        return {};
    }

    if (m_socket != InvalidSocket)
        ::close(m_socket);

    return -m_ovlp.result;
#endif
}

auto TcpStream::ConnectAwaitable::await_suspend() noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the connection.
    auto *addr  = reinterpret_cast<const sockaddr *>(m_address);
    int addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    m_socket = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                          WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

    if (m_socket == INVALID_SOCKET) [[unlikely]] {
        m_ovlp.error = static_cast<std::uint32_t>(WSAGetLastError());
        return false;
    }

    { // ConnectEx requires manually binding.
        sockaddr_in6 local{};
        local.sin6_family = addr->sa_family;

        auto *localAddr = reinterpret_cast<sockaddr *>(&local);
        if (bind(m_socket, localAddr, addrlen) == SOCKET_ERROR) [[unlikely]] {
            m_ovlp.error = static_cast<std::uint32_t>(WSAGetLastError());
            return false;
        }
    }

    // Register the socket with IOCP and set the notification modes.
    if (registerAndSetNotificationModes(m_socket) == FALSE) [[unlikely]] {
        m_ovlp.error = GetLastError();
        return false;
    }

    // Try to connect to the peer address.
    DWORD bytes = 0;
    if (connectEx(m_socket, addr, addrlen, nullptr, 0, &bytes,
                  reinterpret_cast<LPOVERLAPPED>(&m_ovlp)) == TRUE) [[unlikely]] {
        m_ovlp.error = 0;
        return false;
    }

    int error = WSAGetLastError();
    if (error == 0) [[unlikely]] {
        m_ovlp.error = 0;
        return false;
    }

    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    // Create a new socket for the connection.
    auto *addr        = reinterpret_cast<const sockaddr *>(m_address);
    socklen_t addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    m_socket = ::socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_socket == -1) [[unlikely]] {
        m_ovlp.result = -errno;
        return false;
    }

    // Prepare for async connect operation.
    auto *worker = SchedulerWorker::threadWorker();

    auto *ring        = static_cast<io_uring *>(worker->ioMultiplexer());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_connect(sqe, m_socket, addr, addrlen);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

auto TcpStream::SendAwaitable::await_suspend() noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    auto ovlp = reinterpret_cast<LPOVERLAPPED>(&m_ovlp);

    DWORD bytes = 0;
    WSABUF buffer{
        .len = m_size,
        .buf = static_cast<char *>(const_cast<void *>(m_data)),
    };

    // We do not need to check the return value of WSASend because we will check the error code
    // later.
    std::ignore = WSASend(m_socket, &buffer, 1, &bytes, 0, ovlp, nullptr);
    int error   = WSAGetLastError();

    // Send operation is completed immediately.
    if (error == 0) {
        m_ovlp.error = 0;
        m_ovlp.bytes = bytes;
        return false;
    }

    // Send operation is pending.
    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    // Send operation failed.
    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    // Try to send data immediately.
    int result = ::send(m_socket, m_data, m_size, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (result >= 0) {
        m_ovlp.result = result;
        return false;
    }

    // Error sending data.
    int error = errno;
    if (error != EAGAIN && error != EWOULDBLOCK) {
        m_ovlp.result = -error;
        return false;
    }

    // Schedule the send operation.
    auto *worker = SchedulerWorker::threadWorker();

    auto *ring        = static_cast<io_uring *>(worker->ioMultiplexer());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_send(sqe, m_socket, m_data, m_size, MSG_NOSIGNAL);
    io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

auto TcpStream::ReceiveAwaitable::await_suspend() noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    auto ovlp = reinterpret_cast<LPOVERLAPPED>(&m_ovlp);

    DWORD bytes = 0;
    DWORD flags = 0;
    WSABUF buffer{
        .len = m_size,
        .buf = static_cast<char *>(m_buffer),
    };

    // We do not need to check the return value of WSARecv because we will check the error code
    // later.
    std::ignore = WSARecv(m_socket, &buffer, 1, &bytes, &flags, ovlp, nullptr);
    int error   = WSAGetLastError();

    // Receive operation is completed immediately.
    if (error == 0) {
        m_ovlp.error = 0;
        m_ovlp.bytes = bytes;
        return false;
    }

    // Receive operation is pending.
    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    // Receive operation failed.
    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    // Try to receive data immediately.
    int result = ::recv(m_socket, m_buffer, m_size, MSG_DONTWAIT);
    if (result >= 0) {
        m_ovlp.result = result;
        return false;
    }

    // Error receiving data.
    int error = errno;
    if (error != EAGAIN && error != EWOULDBLOCK) {
        m_ovlp.result = -error;
        return false;
    }

    // Schedule the receive operation.
    auto *worker = SchedulerWorker::threadWorker();

    auto *ring        = static_cast<io_uring *>(worker->ioMultiplexer());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_recv(sqe, m_socket, m_buffer, m_size, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

TcpStream::~TcpStream() noexcept {
    this->close();
}

auto TcpStream::operator=(TcpStream &&other) noexcept -> TcpStream & {
    if (this == &other) [[unlikely]]
        return *this;

    this->close();

    m_socket  = other.m_socket;
    m_address = other.m_address;

    other.m_socket  = InvalidSocket;
    other.m_address = {};

    return *this;
}

auto TcpStream::connect(const InetAddress &address) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the connection.
    auto *addr  = reinterpret_cast<const sockaddr *>(&m_address);
    int addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    SOCKET s = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                          WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

    if (s == INVALID_SOCKET) [[unlikely]]
        return WSAGetLastError();

    // Register to IOCP.
    if (registerAndSetNotificationModes(s) == FALSE) [[unlikely]] {
        DWORD error = GetLastError();
        closesocket(s);
        return static_cast<std::int32_t>(error);
    }

    // Try to connect to the peer address.
    if (WSAConnect(s, addr, addrlen, nullptr, nullptr, nullptr, nullptr) == SOCKET_ERROR)
        [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return error;
    }

    this->close();

    m_socket  = s;
    m_address = address;

    return {};
#elif defined(__linux) || defined(__linux__)
    // Create a new socket for the connection.
    auto *addr        = reinterpret_cast<const sockaddr *>(&m_address);
    socklen_t addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    int s = ::socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (s == -1) [[unlikely]]
        return errno;

    // Try to connect to the peer address.
    if (::connect(s, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    this->close();

    m_socket  = s;
    m_address = address;

    return {};
#endif
}

auto TcpStream::send(const void *data, std::uint32_t size) noexcept
    -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD bytes = 0;
    WSABUF buffer{
        .len = size,
        .buf = static_cast<char *>(const_cast<void *>(data)),
    };

    if (WSASend(m_socket, &buffer, 1, &bytes, 0, nullptr, nullptr) == TRUE) [[likely]]
        return bytes;
    return std::unexpected<SystemErrorCode>{WSAGetLastError()};
#elif defined(__linux) || defined(__linux__)
    ssize_t result = ::send(m_socket, data, size, MSG_NOSIGNAL);
    if (result >= 0) [[likely]]
        return static_cast<std::uint32_t>(result);
    return std::unexpected<SystemErrorCode>{errno};
#endif
}

auto TcpStream::receive(void *buffer, std::uint32_t size) noexcept
    -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD bytes = 0;
    DWORD flags = 0;
    WSABUF buf{
        .len = size,
        .buf = static_cast<char *>(buffer),
    };

    if (WSARecv(m_socket, &buf, 1, &bytes, &flags, nullptr, nullptr) == TRUE) [[likely]]
        return bytes;
    return std::unexpected<SystemErrorCode>{WSAGetLastError()};
#elif defined(__linux) || defined(__linux__)
    ssize_t result = ::recv(m_socket, buffer, size, 0);
    if (result >= 0) [[likely]]
        return static_cast<std::uint32_t>(result);
    return std::unexpected<SystemErrorCode>{errno};
#endif
}

auto TcpStream::setKeepAlive(bool enable) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = enable ? 1 : 0;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#elif defined(__linux) || defined(__linux__)
    int value = enable ? 1 : 0;
    if (setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) == -1) [[unlikely]]
        return errno;
    return {};
#endif
}

auto TcpStream::setNoDelay(bool enable) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = enable ? 1 : 0;
    std::ignore = setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#elif defined(__linux) || defined(__linux__)
    int value = enable ? 1 : 0;
    if (setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == -1) [[unlikely]]
        return errno;
    return {};
#endif
}

auto TcpStream::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#elif defined(__linux) || defined(__linux__)
    if (m_socket != InvalidSocket) {
        ::close(m_socket);
        m_socket = InvalidSocket;
    }
#endif
}

auto TcpStream::setSendTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#elif defined(__linux) || defined(__linux__)
    struct timeval timeout{
        .tv_sec  = milliseconds / 1000,
        .tv_usec = (milliseconds % 1000) * 1000,
    };

    if (setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) [[unlikely]]
        return errno;
    return {};
#endif
}

auto TcpStream::setReceiveTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#elif defined(__linux) || defined(__linux__)
    struct timeval timeout{
        .tv_sec  = milliseconds / 1000,
        .tv_usec = (milliseconds % 1000) * 1000,
    };

    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) [[unlikely]]
        return errno;
    return {};
#endif
}

auto TcpListener::AcceptAwaitable::await_resume() const noexcept
    -> std::expected<TcpStream, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_ovlp.error != 0) [[unlikely]] {
        if (m_connection != INVALID_SOCKET)
            closesocket(m_connection);
        return std::unexpected<SystemErrorCode>{static_cast<int>(m_ovlp.error)};
    }

    return std::expected<TcpStream, SystemErrorCode>{std::in_place, m_connection, m_address};
#elif defined(__linux) || defined(__linux__)
    if (m_ovlp.result < 0) [[unlikely]]
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
    return std::expected<TcpStream, SystemErrorCode>{std::in_place, m_ovlp.result, m_address};
#endif
}

auto TcpListener::AcceptAwaitable::await_suspend() noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the incoming connection.
    auto *addr   = reinterpret_cast<sockaddr *>(&m_address);
    m_connection = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

    if (m_connection == INVALID_SOCKET) [[unlikely]] {
        m_ovlp.error = static_cast<std::uint32_t>(WSAGetLastError());
        return false;
    }

    // Register to IOCP.
    if (registerAndSetNotificationModes(m_connection) == FALSE) [[unlikely]] {
        m_ovlp.error = static_cast<std::uint32_t>(GetLastError());
        closesocket(m_connection);
        return false;
    }

    // Try to accept a new incoming connection.
    DWORD bytes = 0;
    if (acceptEx(m_server, m_connection, &m_address, 0, 0, sizeof(m_address) + sizeof(m_padding),
                 &bytes, reinterpret_cast<LPOVERLAPPED>(&m_ovlp)) == TRUE) {
        m_ovlp.error = 0;
        return false;
    }

    int error = WSAGetLastError();
    if (error == 0) [[unlikely]] {
        m_ovlp.error = 0;
        return false;
    }

    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    auto *worker = SchedulerWorker::threadWorker();

    auto *ring        = static_cast<io_uring *>(worker->ioMultiplexer());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    auto *addr    = reinterpret_cast<sockaddr *>(&m_address);
    auto *addrlen = &m_addrlen;

    io_uring_prep_accept(sqe, m_server, addr, addrlen, SOCK_CLOEXEC);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

TcpListener::~TcpListener() noexcept {
    this->close();
}

auto TcpListener::operator=(TcpListener &&other) noexcept -> TcpListener & {
    if (this == &other) [[unlikely]]
        return *this;

    this->close();

    m_socket  = other.m_socket;
    m_address = other.m_address;

    other.m_socket  = InvalidSocket;
    other.m_address = {};

    return *this;
}

auto TcpListener::listen(const InetAddress &address) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the server.
    auto *addr  = reinterpret_cast<const sockaddr *>(&address);
    int addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    SOCKET s    = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                             WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

    if (s == INVALID_SOCKET) [[unlikely]]
        return WSAGetLastError();

    // Enable SO_REUSEADDR option.
    const DWORD value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&value),
                   sizeof(value)) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return error;
    }

    // Register the socket to IOCP.
    if (registerAndSetNotificationModes(s) == FALSE) [[unlikely]] {
        DWORD error = GetLastError();
        closesocket(s);
        return error;
    }

    // Bind the socket to the specified address.
    if (::bind(s, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return error;
    }

    // Start listening on the socket.
    if (::listen(s, SOMAXCONN) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return error;
    }

    this->close();

    m_socket  = s;
    m_address = address;

    return {};
#elif defined(__linux) || defined(__linux__)
    // Create a new socket for the server.
    auto *addr        = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    int s             = ::socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);

    if (s == -1) [[unlikely]]
        return errno;

    // Enable SO_REUSEADDR option.
    int value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    // Enable SO_REUSEPORT option.
    value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    // Bind the socket to the specified address.
    if (::bind(s, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    // Start listening on the socket.
    if (::listen(s, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    this->close();

    m_socket  = s;
    m_address = address;

    return {};
#endif
}

auto TcpListener::accept() const noexcept -> std::expected<TcpStream, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    InetAddress address;
    int addrlen = sizeof(address);

    SOCKET s = WSAAccept(m_socket, reinterpret_cast<sockaddr *>(&address), &addrlen, nullptr, 0);
    if (s == INVALID_SOCKET) [[unlikely]]
        return std::unexpected<SystemErrorCode>{static_cast<int>(WSAGetLastError())};

    return std::expected<TcpStream, SystemErrorCode>{std::in_place, s, address};
#elif defined(__linux) || defined(__linux__)
    InetAddress address{};
    socklen_t addrlen = sizeof(address);

    int s = ::accept4(m_socket, reinterpret_cast<sockaddr *>(&address), &addrlen, SOCK_CLOEXEC);
    if (s == -1) [[unlikely]]
        return std::unexpected<SystemErrorCode>{errno};

    return std::expected<TcpStream, SystemErrorCode>{std::in_place, s, address};
#endif
}

auto TcpListener::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#elif defined(__linux) || defined(__linux__)
    if (m_socket != InvalidSocket) {
        ::close(m_socket);
        m_socket = InvalidSocket;
    }
#endif
}
