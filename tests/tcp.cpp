#include "onion/tcp.hpp"

#include <doctest/doctest.h>

using namespace onion;
using namespace std::chrono_literals;

TEST_CASE("[TcpListener] TCP ping-pong") {
    constexpr std::size_t PacketCount = 1000;
    constexpr std::size_t PacketSize  = 1024;
    constexpr std::size_t BufferSize  = 1024;

    Scheduler scheduler;
    std::atomic_bool serverReady{false};

    auto server = [&](TcpStream stream) -> Task<> {
        char buffer[BufferSize];
        std::size_t totalSize = 0;

        while (totalSize < PacketSize * PacketCount) {
            std::uint32_t recvSize = std::min(PacketSize, PacketSize * PacketCount - totalSize);

            auto result = co_await stream.receiveAsync(buffer, recvSize);
            CHECK(result.has_value());
            totalSize += *result;

            recvSize               = *result;
            std::uint32_t sentSize = 0;
            while (sentSize < recvSize) {
                result = co_await stream.sendAsync(buffer + sentSize, recvSize - sentSize);
                CHECK(result.has_value());
                sentSize += *result;
            }
        }
    };

    auto listener = [&](InetAddress address) -> Task<> {
        TcpListener srv;

        SystemErrorCode error = srv.listen(address);
        CHECK(error.ok());
        CHECK(srv.localAddress() == address);

        serverReady.store(true, std::memory_order_release);

        auto stream = co_await srv.acceptAsync();
        CHECK(stream.has_value());

        schedule(server(*std::move(stream)));
    };

    auto client = [&](InetAddress address) -> Task<> {
        TcpStream stream;

        while (!serverReady.load(std::memory_order_acquire))
            co_await yield();

        SystemErrorCode error = co_await stream.connectAsync(address);
        CHECK(error.ok());
        CHECK(stream.remoteAddress() == address);

        CHECK(stream.setKeepAlive(true).ok());
        CHECK(stream.setNoDelay(true).ok());
        CHECK(stream.setSendTimeout(5s).ok());
        CHECK(stream.setReceiveTimeout(5s).ok());

        char buffer[BufferSize]{};
        std::size_t totalSize = 0;

        while (totalSize < PacketSize * PacketCount) {
            std::uint32_t sendSize = std::min(BufferSize, PacketSize * PacketCount - totalSize);

            auto result = co_await stream.sendAsync(buffer, sendSize);
            CHECK(result.has_value());
            totalSize += *result;

            sendSize               = *result;
            std::uint32_t recvSize = 0;
            while (recvSize < sendSize) {
                result = co_await stream.receiveAsync(buffer + recvSize, sendSize - recvSize);
                CHECK(result.has_value());
                recvSize += *result;
            }
        }

        scheduler.stop();
    };

    InetAddress address{Ipv6Loopback, 23333};
    scheduler.schedule(listener(address));
    scheduler.schedule(client(address));

    scheduler.start();
}
