#include "onion/socket.hpp"

#include <liburing.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <algorithm>
#include <array>
#include <cassert>

using namespace onion;
using namespace onion::detail;

IpAddress::IpAddress(std::string_view address) : m_isIpv6{}, m_addr{} {
    std::array<char, INET6_ADDRSTRLEN> buffer;
    if (address.size() >= buffer.size())
        throw std::invalid_argument("Invalid IP address: " + std::string(address));

    // Copy the address into the buffer to make it null-terminated.
    std::ranges::copy(address, buffer.begin());
    buffer[address.size()] = '\0';

    std::uint16_t family;
    if (address.find(':') == std::string_view::npos) {
        family   = AF_INET;
        m_isIpv6 = false;
    } else {
        family   = AF_INET6;
        m_isIpv6 = true;
    }

    if (inet_pton(family, buffer.data(), &m_addr) != 1) [[unlikely]]
        throw std::invalid_argument("Invalid IP address: " + std::string(address));
}

auto IpAddress::toString() const noexcept -> std::string {
    std::array<char, INET6_ADDRSTRLEN + 1> buffer{};
    inet_ntop(m_isIpv6 ? AF_INET6 : AF_INET, &m_addr, buffer.data(), buffer.size());
    std::size_t length = std::char_traits<char>::length(buffer.data());
    return {buffer.data(), length};
}

auto InetAddress::toString() const noexcept -> std::string {
    std::array<char, INET6_ADDRSTRLEN + 9> buffer{};
    std::size_t length;
    if (isIpv4()) {
        inet_ntop(AF_INET, &m_addr.v4.address, buffer.data(), INET6_ADDRSTRLEN);
        length = std::char_traits<char>::length(buffer.data());
    } else {
        buffer[0] = '[';
        inet_ntop(AF_INET6, &m_addr.v6.address, buffer.data() + 1, INET6_ADDRSTRLEN);
        length           = std::char_traits<char>::length(buffer.data());
        buffer[length++] = ']';
    }

    buffer[length++] = ':';

    // Parse port.
    std::uint16_t port = toHostEndian(m_port);

    auto first = buffer.begin() + length;
    auto last  = first;
    while (port != 0) {
        *last++ = static_cast<char>((port % 10) + '0');
        port /= 10;
    }

    if (first == last) [[unlikely]]
        *last++ = '0';
    else
        std::ranges::reverse(first, last);

    length = static_cast<std::size_t>(last - buffer.begin());
    return {buffer.data(), length};
}

auto SendAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
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
    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
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
}

auto ReceiveAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
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
    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
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
}

auto TcpStream::ConnectAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
    m_ovlp.promise = &promise;

    // Create a new socket for the connection.
    auto *addr        = reinterpret_cast<const sockaddr *>(m_address);
    socklen_t addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    m_socket = ::socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_socket == -1) [[unlikely]] {
        m_ovlp.result = -errno;
        return false;
    }

    // Schedule the connect operation.
    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
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
}

auto TcpStream::ConnectAwaitable::await_resume() const noexcept -> std::errc {
    if (m_ovlp.result == 0) [[likely]] {
        if (m_stream->m_socket != InvalidSocket)
            ::close(m_stream->m_socket);

        m_stream->m_socket  = m_socket;
        m_stream->m_address = *m_address;

        return {};
    }

    if (m_socket != InvalidSocket)
        ::close(m_socket);

    return static_cast<std::errc>(-m_ovlp.result);
}

TcpStream::~TcpStream() noexcept {
    if (m_socket != InvalidSocket)
        ::close(m_socket);
}

auto TcpStream::operator=(TcpStream &&other) noexcept -> TcpStream & {
    if (this == &other) [[unlikely]]
        return *this;

    if (m_socket != InvalidSocket)
        ::close(m_socket);

    m_socket  = other.m_socket;
    m_address = other.m_address;

    other.m_socket  = InvalidSocket;
    other.m_address = {};

    return *this;
}

auto TcpStream::setKeepAlive(bool enable) noexcept -> std::errc {
    const int value = enable ? 1 : 0;
    if (setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) == -1) [[unlikely]]
        return static_cast<std::errc>(errno);
    return {};
}

auto TcpStream::setNoDelay(bool enable) noexcept -> std::errc {
    int value = enable ? 1 : 0;
    if (setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == -1) [[unlikely]]
        return static_cast<std::errc>(errno);
    return {};
}

auto TcpStream::close() noexcept -> void {
    if (m_socket != InvalidSocket) {
        ::close(m_socket);
        m_socket = InvalidSocket;
    }
}

auto TcpStream::setSendTimeout(std::uint32_t milliseconds) noexcept -> std::errc {
    const timeval value{
        .tv_sec  = milliseconds / 1000,
        .tv_usec = (milliseconds % 1000) * 1000,
    };

    if (setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) == -1) [[unlikely]]
        return static_cast<std::errc>(errno);
    return {};
}

auto TcpStream::setReceiveTimeout(std::uint32_t milliseconds) noexcept -> std::errc {
    const timeval value{
        .tv_sec  = milliseconds / 1000,
        .tv_usec = (milliseconds % 1000) * 1000,
    };

    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == -1) [[unlikely]]
        return static_cast<std::errc>(errno);
    return {};
}

auto TcpListener::AcceptAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
    m_ovlp.promise = &promise;

    m_addrlen  = sizeof(m_address);
    auto *addr = reinterpret_cast<sockaddr *>(&m_address);

    // Schedule the accept operation.
    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_accept(sqe, m_server, addr, &m_addrlen, SOCK_CLOEXEC);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
}

auto TcpListener::AcceptAwaitable::await_resume() const noexcept
    -> std::expected<TcpStream, std::errc> {
    if (m_ovlp.result < 0) [[unlikely]]
        return std::unexpected{static_cast<std::errc>(-m_ovlp.result)};
    return std::expected<TcpStream, std::errc>{std::in_place, m_ovlp.result, m_address};
}

TcpListener::~TcpListener() noexcept {
    if (m_socket != InvalidSocket)
        ::close(m_socket);
}

auto TcpListener::operator=(TcpListener &&other) noexcept -> TcpListener & {
    if (this == &other) [[unlikely]]
        return *this;

    if (m_socket != InvalidSocket)
        ::close(m_socket);

    m_socket  = other.m_socket;
    m_address = other.m_address;

    other.m_socket  = InvalidSocket;
    other.m_address = {};

    return *this;
}

auto TcpListener::listen(const InetAddress &address) noexcept -> std::errc {
    // Create a new socket for the server.
    auto *addr        = reinterpret_cast<const sockaddr *>(&address);
    socklen_t addrlen = (addr->sa_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    int s = ::socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (s == -1) [[unlikely]]
        return static_cast<std::errc>(errno);

    // Enable SO_REUSEADDR option.
    const int value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return static_cast<std::errc>(error);
    }

    // Enable SO_REUSEPORT option.
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return static_cast<std::errc>(error);
    }

    // Bind the socket to the specified address.
    if (::bind(s, addr, addrlen) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return static_cast<std::errc>(error);
    }

    // Start listening on the socket.
    if (::listen(s, SOMAXCONN) == -1) [[unlikely]] {
        int error = errno;
        ::close(s);
        return static_cast<std::errc>(error);
    }

    if (m_socket != InvalidSocket)
        ::close(m_socket);

    m_socket  = s;
    m_address = address;

    return {};
}

auto TcpListener::close() noexcept -> void {
    if (m_socket != InvalidSocket) {
        ::close(m_socket);
        m_socket = InvalidSocket;
    }
}
