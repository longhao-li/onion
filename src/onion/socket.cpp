#include "onion/socket.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WS2tcpip.h>
#elif defined(__linux) || defined(__linux__)
#    include <liburing.h>
#    include <netinet/in.h>
#    include <netinet/tcp.h>
#endif

using namespace onion;
using namespace onion::detail;

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
