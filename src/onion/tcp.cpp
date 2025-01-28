#include "onion/tcp.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WS2tcpip.h>
#    include <mswsock.h>
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
#endif
}

auto TcpStream::send(const void *data, std::uint32_t size) noexcept -> SystemIoResult {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD bytes = 0;
    WSABUF buffer{
        .len = size,
        .buf = static_cast<char *>(const_cast<void *>(data)),
    };

    std::ignore = WSASend(m_socket, &buffer, 1, &bytes, 0, nullptr, nullptr);
    return {.status = WSAGetLastError(), .size = bytes};
#endif
}

auto TcpStream::receive(void *buffer, std::uint32_t size) noexcept -> SystemIoResult {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD bytes = 0;
    DWORD flags = 0;
    WSABUF buf{
        .len = size,
        .buf = static_cast<char *>(buffer),
    };

    std::ignore = WSARecv(m_socket, &buf, 1, &bytes, &flags, nullptr, nullptr);
    return {.status = WSAGetLastError(), .size = bytes};
#endif
}

auto TcpStream::setKeepAlive(bool enable) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = enable ? 1 : 0;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#endif
}

auto TcpStream::setNoDelay(bool enable) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = enable ? 1 : 0;
    std::ignore = setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#endif
}

auto TcpStream::close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#endif
}

auto TcpStream::setSendTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#endif
}

auto TcpStream::setReceiveTimeout(std::uint32_t milliseconds) noexcept -> SystemErrorCode {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    DWORD value = milliseconds;
    std::ignore = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO,
                             reinterpret_cast<const char *>(&value), sizeof(value));
    return WSAGetLastError();
#endif
}
