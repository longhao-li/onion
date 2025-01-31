#include "onion/socket.hpp"

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
namespace onion::detail {

/// \brief
///   Try to acquire the \c ConnectEx function pointer.
/// \return
///   The \c ConnectEx function pointer if successful. Otherwise, return \c nullptr and the error
///   code is set to \c WSAGetLastError().
[[nodiscard]]
auto acquireConnectEx() noexcept -> LPFN_CONNECTEX {
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
auto connectEx(SOCKET s,
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
auto acquireAcceptEx() noexcept -> LPFN_ACCEPTEX {
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
auto acceptEx(SOCKET listenSocket,
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
auto registerAndSetNotificationModes(SOCKET s) noexcept -> BOOL {
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

} // namespace onion::detail
#endif

auto SendAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    m_ovlp.promise = &promise;
    auto ovlp      = reinterpret_cast<LPOVERLAPPED>(&m_ovlp);

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
    m_ovlp.promise = &promise;

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

auto ReceiveAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    m_ovlp.promise = &promise;
    auto ovlp      = reinterpret_cast<LPOVERLAPPED>(&m_ovlp);

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
    m_ovlp.promise = &promise;

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
