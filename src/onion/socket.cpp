#include "onion/socket.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <mswsock.h>
#endif

#include <algorithm>

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Try to acquire the \c ConnectEx function pointer.
/// \return
///   The \c ConnectEx function pointer if successful. Otherwise, return \c nullptr and the error
///   code is set to \c WSAGetLastError().
[[nodiscard]] static auto acquire_connect_ex() noexcept -> LPFN_CONNECTEX {
    // Create a dummy socket to call WSAIoctl
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) [[unlikely]]
        return nullptr;

    // Get the ConnectEx function pointer
    LPFN_CONNECTEX func = nullptr;

    DWORD bytes = 0;
    GUID  guid  = WSAID_CONNECTEX;

    int result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &func, sizeof(func), &bytes,
                          nullptr, nullptr);

    if (result != 0) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        WSASetLastError(error);
        return nullptr;
    }

    closesocket(s);
    return func;
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
static auto connect_ex(SOCKET          s,
                       const sockaddr *name,
                       int             namelen,
                       PVOID           sendBuffer,
                       DWORD           sendDataLength,
                       LPDWORD         bytesSent,
                       LPOVERLAPPED    overlapped) noexcept -> BOOL {
    static std::atomic<LPFN_CONNECTEX> function{nullptr};

    // Try to connect if the function pointer is valid.
    LPFN_CONNECTEX connect = function.load(std::memory_order_relaxed);
    if (connect != nullptr) [[likely]]
        return connect(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);

    connect = acquire_connect_ex();
    if (connect == nullptr) [[unlikely]]
        return FALSE;

    // It is safe to store the function pointer for multiple times in multiple threads. We just need to ensure that one
    // of them is correct.
    function.store(connect, std::memory_order_relaxed);
    return connect(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

/// \brief
///   Try to acquire the \c AcceptEx function pointer.
/// \return
///   The \c AcceptEx function pointer if successful. Otherwise, return \c nullptr and the error
///   code is set to \c WSAGetLastError().
[[nodiscard]] static auto acquire_accept_ex() noexcept -> LPFN_ACCEPTEX {
    // Create a dummy socket to call WSAIoctl
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) [[unlikely]]
        return nullptr;

    // Get the AcceptEx function pointer
    LPFN_ACCEPTEX acceptEx = nullptr;

    DWORD bytes = 0;
    GUID  guid  = WSAID_ACCEPTEX;

    int result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &acceptEx, sizeof(acceptEx),
                          &bytes, nullptr, nullptr);

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
static auto accept_ex(SOCKET       listenSocket,
                      SOCKET       acceptSocket,
                      PVOID        outputBuffer,
                      DWORD        receiveDataLength,
                      DWORD        localAddressLength,
                      DWORD        remoteAddressLength,
                      LPDWORD      bytesReceived,
                      LPOVERLAPPED overlapped) noexcept -> BOOL {
    static std::atomic<LPFN_ACCEPTEX> function{nullptr};

    // Try to accept new connection if the function pointer is valid.
    LPFN_ACCEPTEX accept = function.load(std::memory_order_relaxed);
    if (accept != nullptr) [[likely]]
        return accept(listenSocket, acceptSocket, outputBuffer, receiveDataLength, localAddressLength,
                      remoteAddressLength, bytesReceived, overlapped);

    accept = acquire_accept_ex();
    if (accept == nullptr) [[unlikely]]
        return FALSE;

    // It is safe to store the function pointer for multiple times in multiple threads. We just need to ensure that one
    // of them is correct.
    function.store(accept, std::memory_order_relaxed);
    return accept(listenSocket, acceptSocket, outputBuffer, receiveDataLength, localAddressLength, remoteAddressLength,
                  bytesReceived, overlapped);
}
#endif

auto onion::inet_address::to_string() const noexcept -> std::string {
    char        buffer[INET6_ADDRSTRLEN + 9]{};
    std::size_t length;

    if (this->is_ipv4()) {
        inet_ntop(AF_INET, &this->m_addr.v4.sin_addr, buffer, INET6_ADDRSTRLEN);
        length = std::char_traits<char>::length(buffer);
    } else {
        buffer[0] = '[';
        inet_ntop(AF_INET6, &this->m_addr.v6.sin6_addr, buffer + 1, INET6_ADDRSTRLEN);
        length           = std::char_traits<char>::length(buffer);
        buffer[length++] = ']';
    }

    buffer[length++] = ':';

    // Parse port.
    std::uint16_t port = this->port();

    auto first = buffer + length;
    auto last  = first;
    while (port != 0) {
        *last++ = static_cast<char>((port % 10) + '0');
        port /= 10;
    }

    if (first == last) [[unlikely]]
        *last++ = '0';
    else
        std::ranges::reverse(first, last);

    length = static_cast<std::size_t>(last - buffer);
    return {buffer, length};
}

auto onion::send_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    DWORD  bytes = 0;
    WSABUF buffer{this->m_size, static_cast<CHAR *>(const_cast<void *>(this->m_data))};

    // Send operation is completed immediately.
    if (WSASend(this->m_socket, &buffer, 1, &bytes, 0, &this->m_ovlp, nullptr) == 0) {
        this->m_ovlp.error = 0;
        this->m_ovlp.bytes = bytes;
        return false;
    }

    int error = WSAGetLastError();

    // Send operation is pending.
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    // Send operation failed.
    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_send(sqe, this->m_socket, this->m_data, this->m_size, MSG_NOSIGNAL);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

auto onion::receive_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    DWORD  bytes = 0;
    DWORD  flags = 0;
    WSABUF buffer{this->m_size, static_cast<CHAR *>(this->m_buffer)};

    // Receive operation is completed immediately.
    if (WSARecv(this->m_socket, &buffer, 1, &bytes, &flags, &this->m_ovlp, nullptr) == 0) {
        this->m_ovlp.error = 0;
        this->m_ovlp.bytes = bytes;
        return false;
    }

    int error = WSAGetLastError();

    // Receive operation is pending.
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    // Receive operation failed.
    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_recv(sqe, this->m_socket, this->m_buffer, this->m_size, 0);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    return true;
#endif
}

auto onion::send_to_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    DWORD  bytes = 0;
    WSABUF buffer{this->m_size, static_cast<CHAR *>(const_cast<void *>(this->m_data))};
    auto  *address = reinterpret_cast<const sockaddr *>(this->m_address);
    int    addrlen = (this->m_address->is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    if (WSASendTo(this->m_socket, &buffer, 1, &bytes, 0, address, addrlen, &this->m_ovlp, nullptr) == 0) {
        this->m_ovlp.bytes = bytes;
        return false;
    }

    int error = WSAGetLastError();
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    this->m_message.msg_iov    = &this->m_io_vector;
    this->m_message.msg_iovlen = 1;

    io_uring_prep_sendmsg(sqe, this->m_socket, &this->m_message, MSG_NOSIGNAL);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

auto onion::receive_from_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;
    this->m_addrlen      = sizeof(inet_address);

    DWORD  bytes = 0;
    WSABUF buffer{this->m_size, static_cast<CHAR *>(this->m_buffer)};
    auto  *address = reinterpret_cast<sockaddr *>(this->m_address);

    if (WSARecvFrom(this->m_socket, &buffer, 1, &bytes, &this->m_flags, address, &this->m_addrlen, &this->m_ovlp,
                    nullptr) == 0) {
        this->m_ovlp.bytes = bytes;
        return false;
    }

    int error = WSAGetLastError();
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    this->m_message.msg_iov    = &this->m_io_vector;
    this->m_message.msg_iovlen = 1;

    io_uring_prep_recvmsg(sqe, this->m_socket, &this->m_message, 0);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

auto onion::tcp_stream::connect_awaitable::await_resume() noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (this->m_ovlp.error == ERROR_SUCCESS) [[likely]] {
        if (this->m_stream->m_socket != invalid_socket)
            closesocket(this->m_stream->m_socket);

        this->m_stream->m_socket  = this->m_socket;
        this->m_stream->m_address = *this->m_address;

        return {};
    }

    if (this->m_socket != invalid_socket)
        closesocket(this->m_socket);

    return {this->m_ovlp.error, std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    if (this->m_ovlp.result == 0) [[likely]] {
        if (this->m_stream->m_socket != invalid_socket)
            ::close(this->m_stream->m_socket);

        this->m_stream->m_socket  = this->m_socket;
        this->m_stream->m_address = *this->m_address;

        return {};
    }

    if (this->m_socket != invalid_socket)
        ::close(this->m_socket);

    return {-this->m_ovlp.result, std::system_category()};
#endif
}

auto onion::tcp_stream::connect_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    auto *address = reinterpret_cast<const sockaddr *>(this->m_address);
    int   addrlen = (address->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    // Create a new socket for the connection.
    this->m_socket = WSASocketW(address->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (this->m_socket == INVALID_SOCKET) [[unlikely]] {
        this->m_ovlp.error = WSAGetLastError();
        return false;
    }

    { // ConnectEx requires manually binding.
        sockaddr_in6 local_address{};
        local_address.sin6_family = address->sa_family;
        if (bind(this->m_socket, reinterpret_cast<sockaddr *>(&local_address), addrlen) == SOCKET_ERROR) [[unlikely]] {
            this->m_ovlp.error = WSAGetLastError();
            return false;
        }
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(this->m_socket), iocp, 0, 0) == nullptr) [[unlikely]] {
            this->m_ovlp.error = static_cast<int>(GetLastError());
            return false;
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(this->m_socket), mode) == FALSE) [[unlikely]] {
            this->m_ovlp.error = static_cast<int>(GetLastError());
            return false;
        }
    }

    { // Try to connect to the peer address.
        DWORD bytes = 0;
        if (connect_ex(this->m_socket, address, addrlen, nullptr, 0, &bytes, &this->m_ovlp) == TRUE) {
            this->m_ovlp.error = ERROR_SUCCESS;
            return false;
        }
    }

    int error = WSAGetLastError();

    // Connect operation is pending.
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    // Connect operation failed.
    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    // Create a new socket for the connection.
    auto     *address = reinterpret_cast<const sockaddr *>(this->m_address);
    socklen_t addrlen = (address->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    this->m_socket = ::socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (this->m_socket == invalid_socket) [[unlikely]] {
        this->m_ovlp.result = -errno;
        return false;
    }

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_connect(sqe, this->m_socket, address, addrlen);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

auto onion::tcp_listener::accept_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    // Create a new socket for the incoming connection.
    this->m_stream = WSASocketW(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (this->m_stream == INVALID_SOCKET) [[unlikely]] {
        this->m_ovlp.error = WSAGetLastError();
        return false;
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(this->m_stream), iocp, 0, 0) == nullptr) [[unlikely]] {
            this->m_ovlp.error = static_cast<int>(GetLastError());
            return false;
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(this->m_stream), mode) == FALSE) [[unlikely]] {
            this->m_ovlp.error = static_cast<int>(GetLastError());
            return false;
        }
    }

    { // Try to accept a new incoming connection.
        DWORD bytes = 0;
        if (accept_ex(this->m_listener, this->m_stream, &this->m_address, 0, 0,
                      sizeof(this->m_address) + sizeof(this->m_padding), &bytes, &this->m_ovlp) == TRUE) {
            this->m_ovlp.error = ERROR_SUCCESS;
            return false;
        }
    }

    int error = WSAGetLastError();

    // Accept operation is pending.
    if (error == WSA_IO_PENDING) [[likely]]
        return true;

    // Accept operation failed.
    this->m_ovlp.error = error;
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;
    this->m_addrlen      = sizeof(this->m_address);

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_accept(sqe, this->m_listener, reinterpret_cast<sockaddr *>(&this->m_address), &this->m_addrlen, 0);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
onion::tcp_listener::tcp_listener(const inet_address &address) : m_address{address} {
    // Create a new socket for the server.
    auto *addr    = reinterpret_cast<const sockaddr *>(&address);
    int   addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    this->m_socket = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (this->m_socket == invalid_socket) [[unlikely]]
        throw std::system_error{WSAGetLastError(), std::system_category(), "Failed to create socket"};

    { // Enable SO_REUSEADDR option.
        DWORD value  = 1;
        auto *optval = reinterpret_cast<const CHAR *>(&value);
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEADDR, optval, sizeof(value)) == SOCKET_ERROR) [[unlikely]] {
            int error = WSAGetLastError();
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEADDR"};
        }
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(this->m_socket), iocp, 0, 0) == nullptr) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to register IOCP"};
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(this->m_socket), mode) == FALSE) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to set notification mode"};
        }
    }

    // Bind the socket to the address.
    if (::bind(this->m_socket, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to bind socket"};
    }

    // Listen for incoming connections.
    if (::listen(this->m_socket, SOMAXCONN) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to listen for incoming connections"};
    }
}
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
onion::tcp_listener::tcp_listener(const inet_address &address) : m_address{address} {
    // Create a new socket for the server.
    auto     *addr    = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = address.is_ipv4() ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    this->m_socket = ::socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (this->m_socket == -1) [[unlikely]]
        throw std::system_error{errno, std::system_category(), "Failed to create socket"};

    { // Enable SO_REUSEADDR option.
        const int value = 1;
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEADDR"};
        }
    }

    { // Enable SO_REUSEPORT option.
        const int value = 1;
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEPORT"};
        }
    }

    // Bind the socket to the address.
    if (::bind(this->m_socket, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to bind socket"};
    }

    // Listen for incoming connections.
    if (::listen(this->m_socket, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to listen for incoming connections"};
    }
}
#endif

auto onion::tcp_listener::listen(const inet_address &address) noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the server.
    auto *addr    = reinterpret_cast<const sockaddr *>(&address);
    int   addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    socket_t s = WSASocketW(addr->sa_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == invalid_socket) [[unlikely]]
        return {WSAGetLastError(), std::system_category()};

    { // Enable SO_REUSEADDR option.
        DWORD value  = 1;
        auto *optval = reinterpret_cast<const CHAR *>(&value);
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, optval, sizeof(value)) == SOCKET_ERROR) [[unlikely]] {
            int error = WSAGetLastError();
            closesocket(s);
            return {error, std::system_category()};
        }
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), iocp, 0, 0) == nullptr) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(s);
            return {error, std::system_category()};
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(s), mode) == FALSE) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(s);
            return {error, std::system_category()};
        }
    }

    // Bind the socket to the address.
    if (::bind(s, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return {error, std::system_category()};
    }

    // Listen for incoming connections.
    if (::listen(s, SOMAXCONN) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return {error, std::system_category()};
    }

    if (this->m_socket != invalid_socket)
        closesocket(this->m_socket);

    this->m_socket  = s;
    this->m_address = address;

    return {};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    // Create a new socket for the server.
    auto     *addr    = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    socket_t s = ::socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == -1) [[unlikely]]
        return {errno, std::system_category()};

    { // Enable SO_REUSEADDR option.
        const int value = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(s);
            return {error, std::system_category()};
        }
    }

    { // Enable SO_REUSEPORT option.
        const int value = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(s);
            return {error, std::system_category()};
        }
    }

    // Bind the socket to the address.
    if (::bind(s, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return {error, std::system_category()};
    }

    // Listen for incoming connections.
    if (::listen(s, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return {error, std::system_category()};
    }

    if (this->m_socket != invalid_socket)
        ::close(this->m_socket);

    this->m_socket  = s;
    this->m_address = address;

    return {};
#endif
}

auto onion::udp_socket::connect_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    this->m_ovlp.promise = &promise;

    auto *address = reinterpret_cast<const sockaddr *>(this->m_address);
    int   addrlen = (address->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    // Try to connect to the peer address.
    // FIXME: Is this blocking?
    if (WSAConnect(this->m_socket, address, addrlen, nullptr, nullptr, nullptr, nullptr) == 0) [[likely]] {
        this->m_ovlp.error = ERROR_SUCCESS;
        return false;
    }

    // Connect operation failed.
    this->m_ovlp.error = WSAGetLastError();
    return false;
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    auto     *address = reinterpret_cast<const sockaddr *>(this->m_address);
    socklen_t addrlen = (address->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    io_uring_prep_connect(sqe, this->m_socket, address, addrlen);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
#endif
}

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
onion::udp_socket::udp_socket(const inet_address &address) : m_address{address} {
    // Create a new socket for the server.
    auto *addr    = reinterpret_cast<const sockaddr *>(&address);
    int   addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    this->m_socket = WSASocketW(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (this->m_socket == invalid_socket) [[unlikely]]
        throw std::system_error{WSAGetLastError(), std::system_category(), "Failed to create socket"};

    { // Enable SO_REUSEADDR option.
        DWORD value  = 1;
        auto *optval = reinterpret_cast<const CHAR *>(&value);
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEADDR, optval, sizeof(value)) == SOCKET_ERROR) [[unlikely]] {
            int error = WSAGetLastError();
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEADDR"};
        }
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(this->m_socket), iocp, 0, 0) == nullptr) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to register IOCP"};
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(this->m_socket), mode) == FALSE) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to set notification mode"};
        }
    }

    // Bind the socket to the address.
    if (::bind(this->m_socket, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to bind socket"};
    }
}
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
onion::udp_socket::udp_socket(const inet_address &address) : m_address{address} {
    // Create a new socket for the server.
    auto     *addr    = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = address.is_ipv4() ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    this->m_socket = ::socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (this->m_socket == invalid_socket) [[unlikely]]
        throw std::system_error{errno, std::system_category(), "Failed to create socket"};

    { // Enable SO_REUSEADDR option.
        const int value = 1;
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEADDR"};
        }
    }

    { // Enable SO_REUSEPORT option.
        const int value = 1;
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(this->m_socket);
            throw std::system_error{error, std::system_category(), "Failed to enable SO_REUSEPORT"};
        }
    }

    // Bind the socket to the address.
    if (::bind(this->m_socket, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to bind socket"};
    }
}
#endif

auto onion::udp_socket::bind(const inet_address &address) noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    // Create a new socket for the server.
    auto *addr    = reinterpret_cast<const sockaddr *>(&address);
    int   addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    socket_t s = WSASocketW(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == invalid_socket) [[unlikely]]
        return {WSAGetLastError(), std::system_category()};

    { // Enable SO_REUSEADDR option.
        DWORD value  = 1;
        auto *optval = reinterpret_cast<const CHAR *>(&value);
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, optval, sizeof(value)) == SOCKET_ERROR) [[unlikely]] {
            int error = WSAGetLastError();
            closesocket(s);
            return {error, std::system_category()};
        }
    }

    { // Register the socket with IOCP and set the notification modes.
        HANDLE iocp = io_context::current()->iocp();
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), iocp, 0, 0) == nullptr) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(s);
            return {error, std::system_category()};
        }
    }

    { // Set notification mode for this socket.
        UCHAR mode = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
        if (SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(s), mode) == FALSE) [[unlikely]] {
            int error = static_cast<int>(GetLastError());
            closesocket(this->m_socket);
            return {error, std::system_category()};
        }
    }

    // Bind the socket to the address.
    if (::bind(s, addr, addrlen) == SOCKET_ERROR) [[unlikely]] {
        int error = WSAGetLastError();
        closesocket(s);
        return {error, std::system_category()};
    }

    if (this->m_socket != invalid_socket)
        closesocket(this->m_socket);

    this->m_socket  = s;
    this->m_address = address;

    return {};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    // Create a new socket for the server.
    auto     *addr    = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = (address.is_ipv4()) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    socket_t s = ::socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) [[unlikely]]
        return {errno, std::system_category()};

    { // Enable SO_REUSEADDR option.
        const int value = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(s);
            return {error, std::system_category()};
        }
    }

    { // Enable SO_REUSEPORT option.
        const int value = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
            int error = errno;
            ::close(s);
            return {error, std::system_category()};
        }
    }

    // Bind the socket to the address.
    if (::bind(s, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return {error, std::system_category()};
    }

    if (this->m_socket != invalid_socket)
        ::close(this->m_socket);

    this->m_socket  = s;
    this->m_address = address;

    return {};
#endif
}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
auto onion::unix_stream::connect_awaitable::await_resume() noexcept -> std::error_code {
    if (this->m_ovlp.result == 0) [[likely]] {
        if (this->m_stream->m_socket != invalid_socket)
            ::close(this->m_stream->m_socket);

        this->m_stream->m_socket  = this->m_socket;
        this->m_stream->m_address = this->m_address;

        return {};
    }

    if (this->m_socket != invalid_socket)
        ::close(this->m_socket);

    return {-this->m_ovlp.result, std::system_category()};
}

auto onion::unix_stream::connect_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
    this->m_ovlp.promise = &promise;

    // Create a new socket for the connection.
    this->m_socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->m_socket == invalid_socket) [[unlikely]] {
        this->m_ovlp.result = -errno;
        return false;
    }

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    auto     *address = reinterpret_cast<const sockaddr *>(&this->m_address);
    socklen_t addrlen = sizeof(this->m_address);

    io_uring_prep_connect(sqe, this->m_socket, address, addrlen);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
}

auto onion::unix_listener::accept_awaitable::prepare_overlapped(promise_base &promise) noexcept -> bool {
    this->m_ovlp.promise = &promise;

    io_uring     *ring = io_context::current()->uring();
    io_uring_sqe *sqe  = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_accept(sqe, this->m_listener, reinterpret_cast<sockaddr *>(&this->m_address), &this->m_addrlen, 0);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &this->m_ovlp);

    return true;
}

onion::unix_listener::unix_listener(std::string_view address) {
    if (address.size() >= std::size(this->m_address.sun_path)) [[unlikely]]
        throw std::invalid_argument{"Address is too long"};

    this->m_address.sun_family = AF_UNIX;
    std::ranges::copy(address, this->m_address.sun_path);
    this->m_address.sun_path[address.size()] = '\0';

    // Create a new socket for the server.
    this->m_socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->m_socket == -1) [[unlikely]]
        throw std::system_error{errno, std::system_category(), "Failed to create socket"};

    // Bind the socket to the address.
    auto *addr = reinterpret_cast<const sockaddr *>(&this->m_address);
    if (::bind(this->m_socket, addr, sizeof(this->m_address)) == -1) [[unlikely]] {
        int error = errno;
        ::close(this->m_socket);
        throw std::system_error{error, std::system_category(), "Failed to bind socket"};
    }

    // Listen for incoming connections.
    if (::listen(this->m_socket, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(this->m_socket);
        ::unlink(this->m_address.sun_path);
        throw std::system_error{error, std::system_category(), "Failed to listen for incoming connections"};
    }
}

auto onion::unix_listener::listen(std::string_view address) noexcept -> std::error_code {
    if (address.size() >= std::size(this->m_address.sun_path)) [[unlikely]]
        return std::make_error_code(std::errc::invalid_argument);

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::ranges::copy(address, addr.sun_path);
    addr.sun_path[address.size()] = '\0';

    // Try to unlink the previous socket if exists.
    if (::access(addr.sun_path, F_OK) == 0)
        ::unlink(addr.sun_path);

    // Create a new socket for the server.
    socket_t s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) [[unlikely]]
        return {errno, std::system_category()};

    // Bind the socket to the address.
    if (::bind(s, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return {error, std::system_category()};
    }

    // Listen for incoming connections.
    if (::listen(s, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        ::unlink(addr.sun_path);
        return {error, std::system_category()};
    }

    if (this->m_socket != invalid_socket) {
        ::close(this->m_socket);
        ::unlink(this->m_address.sun_path);
    }

    this->m_socket  = s;
    this->m_address = addr;

    return {};
}
#endif
