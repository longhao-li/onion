#include "onion/unix.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WinSock2.h>
#    include <afunix.h>
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
#endif
}

auto UnixStream::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#endif
}

auto UnixStream::setSendTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#endif
}

auto UnixStream::setReceiveTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
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
#endif
}

auto UnixListener::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#endif
}
