#include "onion/unix.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WinSock2.h>
#    include <afunix.h>
#elif defined(__linux) || defined(__linux__)
#    include <liburing.h>
#    include <netinet/in.h>
#    include <sys/un.h>
#endif

using namespace onion;
using namespace onion::detail;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
namespace onion::detail {

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
auto connectEx(SOCKET s,
               const struct sockaddr *name,
               int namelen,
               PVOID sendBuffer,
               DWORD sendDataLength,
               LPDWORD bytesSent,
               LPOVERLAPPED overlapped) noexcept -> BOOL;

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
auto acceptEx(SOCKET listenSocket,
              SOCKET acceptSocket,
              PVOID outputBuffer,
              DWORD receiveDataLength,
              DWORD localAddressLength,
              DWORD remoteAddressLength,
              LPDWORD bytesReceived,
              LPOVERLAPPED overlapped) noexcept -> BOOL;

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
auto registerAndSetNotificationModes(SOCKET s) noexcept -> BOOL;

} // namespace onion::detail
#endif

auto UnixStream::ConnectAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    static_assert(sizeof(UnixSocketAddress) == sizeof(sockaddr_un));
    m_ovlp.promise = &promise;

    auto *addr  = reinterpret_cast<const sockaddr *>(m_address);
    int addrlen = sizeof(sockaddr_un);

    // Create a new socket for the connection.
    m_socket = WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0,
                          WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (m_socket == INVALID_SOCKET) [[unlikely]] {
        m_ovlp.error = static_cast<std::uint32_t>(WSAGetLastError());
        return false;
    }

    { // ConnectEx requires manually binding.
        sockaddr_un local{};
        local.sun_family = AF_UNIX;

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
    if (error == 0) {
        m_ovlp.error = 0;
        return false;
    }

    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    static_assert(sizeof(UnixSocketAddress) == sizeof(sockaddr_un));
    m_ovlp.promise = &promise;

    // Create a new socket for the connection.
    m_socket = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

    auto *addr        = reinterpret_cast<const sockaddr *>(m_address);
    socklen_t addrlen = sizeof(UnixSocketAddress);

    io_uring_prep_connect(sqe, m_socket, addr, addrlen);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

auto UnixStream::ConnectAwaitable::await_resume() const noexcept -> SystemErrorCode {
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

    return static_cast<int>(m_ovlp.error);
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

UnixStream::~UnixStream() noexcept {
    this->close();
}

auto UnixStream::operator=(UnixStream &&other) noexcept -> UnixStream & {
    if (this == &other) [[unlikely]]
        return *this;

    this->close();

    m_socket  = other.m_socket;
    m_address = other.m_address;

    other.m_socket  = InvalidSocket;
    other.m_address = {};

    return *this;
}

auto UnixStream::connect(const UnixSocketAddress &address) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the connection.
    auto *addr  = reinterpret_cast<const sockaddr *>(&m_address);
    int addrlen = sizeof(sockaddr_un);

    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0,
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
    int s = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) [[unlikely]]
        return errno;

    // Try to connect to the peer address.
    auto *addr        = reinterpret_cast<const sockaddr *>(&m_address);
    socklen_t addrlen = sizeof(UnixSocketAddress);

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

auto UnixStream::send(const void *data, std::uint32_t size) noexcept
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

auto UnixStream::receive(void *buffer, std::uint32_t size) noexcept
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

auto UnixStream::close() noexcept -> void {
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

auto UnixStream::setSendTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
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

auto UnixStream::setReceiveTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
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

auto UnixListener::AcceptAwaitable::await_resume() const noexcept
    -> std::expected<UnixStream, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_ovlp.error != 0) [[unlikely]] {
        if (m_connection != INVALID_SOCKET)
            closesocket(m_connection);
        return std::unexpected<SystemErrorCode>{static_cast<int>(m_ovlp.error)};
    }

    return std::expected<UnixStream, SystemErrorCode>{std::in_place, m_connection, m_address};
#elif defined(__linux) || defined(__linux__)
    if (m_ovlp.result < 0) [[unlikely]]
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
    return std::expected<UnixStream, SystemErrorCode>{std::in_place, m_ovlp.result, m_address};
#endif
}

auto UnixListener::AcceptAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    m_ovlp.promise = &promise;

    // Create a new socket for the incoming connection.
    m_connection = WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0,
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
                 &bytes, reinterpret_cast<LPOVERLAPPED>(&m_ovlp)) == TRUE) [[unlikely]] {
        m_ovlp.error = 0;
        return false;
    }

    int error = WSAGetLastError();
    if (error == 0) {
        m_ovlp.error = 0;
        return false;
    }

    if (error == ERROR_IO_PENDING) [[likely]]
        return true;

    m_ovlp.error = static_cast<std::uint32_t>(error);
    return false;
#elif defined(__linux) || defined(__linux__)
    m_ovlp.promise = &promise;

    auto *worker      = SchedulerWorker::threadWorker();
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

    m_addrlen = sizeof(m_address);

    auto *addr    = reinterpret_cast<sockaddr *>(&m_address);
    auto *addrlen = &m_addrlen;

    io_uring_prep_accept(sqe, m_server, addr, addrlen, SOCK_CLOEXEC);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
#endif
}

UnixListener::~UnixListener() noexcept {
    this->close();
}

auto UnixListener::listen(const UnixSocketAddress &address) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the server.
    SOCKET s = WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0,
                          WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) [[unlikely]]
        return WSAGetLastError();

    // Unix socket on Windows does not support SO_REUSEADDR.
    // Register the socket to IOCP.
    if (registerAndSetNotificationModes(s) == FALSE) [[unlikely]] {
        DWORD error = GetLastError();
        closesocket(s);
        return error;
    }

    // Bind the socket to the specified address.
    auto *addr  = reinterpret_cast<const sockaddr *>(&address);
    int addrlen = sizeof(UnixSocketAddress);
    if (::bind(s, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
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
    int s = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) [[unlikely]]
        return errno;

    // Enable SO_REUSEADDR option.
    const int value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return error;
    }

    // Bind the socket to the specified address.
    auto *addr        = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = sizeof(UnixSocketAddress);

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

auto UnixListener::accept() const noexcept -> std::expected<UnixStream, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    UnixSocketAddress address;
    int addrlen = sizeof(address);

    SOCKET s = WSAAccept(m_socket, reinterpret_cast<sockaddr *>(&address), &addrlen, nullptr, 0);
    if (s == INVALID_SOCKET) [[unlikely]]
        return std::unexpected<SystemErrorCode>{WSAGetLastError()};

    return std::expected<UnixStream, SystemErrorCode>{std::in_place, s, address};
#elif defined(__linux) || defined(__linux__)
    UnixSocketAddress address;
    socklen_t addrlen = sizeof(address);

    int s = ::accept4(m_socket, reinterpret_cast<sockaddr *>(&address), &addrlen, SOCK_CLOEXEC);
    if (s == -1) [[unlikely]]
        return std::unexpected<SystemErrorCode>{errno};

    return std::expected<UnixStream, SystemErrorCode>{std::in_place, s, address};
#endif
}

auto UnixListener::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#elif defined(__linux) || defined(__linux__)
    if (m_socket != InvalidSocket) {
        ::close(m_socket);
        ::unlink(m_address.path().data());
        m_socket = InvalidSocket;
    }
#endif
}
