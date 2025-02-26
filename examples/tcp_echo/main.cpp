#include "onion/socket.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace onion;

/// \brief
///   The acceptor worker for the server.
/// \param address
///   The address to listen for incoming connections.
static auto acceptor(InetAddress address) noexcept -> Task<>;

/// \brief
///   Server the incoming connection.
/// \param stream
///   Stream of the incoming connection.
static auto server(TcpStream stream) noexcept -> Task<>;

auto main(int argc, char **argv) -> int {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <address> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        // This may throw exception.
        IpAddress ip{argv[1]};
        std::uint16_t port = std::atoi(argv[2]);

        InetAddress address{ip, port};
        IoContext ctx;
        ctx.dispatch(acceptor, address);

        // Actually noreturn here.
        ctx.start();
    } catch (std::invalid_argument &e) {
        std::fprintf(stderr, "Invalid IP address: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return 0;
}

/// \brief
///   The acceptor worker for the server.
/// \param address
///   The address to listen for incoming connections.
static auto acceptor(InetAddress address) noexcept -> Task<> {
    std::string addrstr = address.toString();
    std::printf("Thread %d listening on %s\n", gettid(), addrstr.c_str());

    // Bind server to the address.
    TcpListener listener;
    auto error = listener.listen(address);
    if (error != std::errc{}) [[unlikely]] {
        addrstr = address.toString();
        std::fprintf(stderr, "TcpListener::listen on address %s failed: %s\n", addrstr.c_str(),
                     std::strerror(static_cast<int>(error)));
        std::terminate();
    }

    // Listen for incoming connections.
    while (true) {
        auto result = co_await listener.accept();

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::fprintf(stderr, "TcpListener::acceptAsync failed: %s\n",
                         std::strerror(static_cast<int>(result.error())));
            std::terminate();
        }

        // Schedule a new connection.
        co_await schedule(server(std::move(*result)));
    }
}

/// \brief
///   Server the incoming connection.
/// \param stream
///   Stream of the incoming connection.
static auto server(TcpStream stream) noexcept -> Task<> {
    InetAddress remoteAddress = stream.remoteAddress();
    std::string addrstr       = remoteAddress.toString();
    std::printf("Connection with %s established.\n", addrstr.c_str());

    char buffer[65536];
    while (true) {
        auto result = co_await stream.receive(buffer, sizeof(buffer));

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::fprintf(stderr, "TcpStream::receive from %s failed: %s\n", addrstr.c_str(),
                         std::strerror(static_cast<int>(result.error())));
            co_return;
        }

        // Connection closed.
        std::uint32_t received = *result;
        if (received == 0) [[unlikely]] {
            std::printf("Connection with %s closed.\n", addrstr.c_str());
            co_return;
        }

        // Write a log.
        std::printf("Received %u bytes from %s.\n", received, addrstr.c_str());

        // Send received data back.
        std::uint32_t totalSent = 0;
        while (totalSent < received) {
            result = co_await stream.send(buffer + totalSent, received - totalSent);

            // Handle error.
            if (!result.has_value()) [[unlikely]] {
                std::fprintf(stderr, "TcpStream::send to %s failed: %s", addrstr.c_str(),
                             std::strerror(static_cast<int>(result.error())));
                co_return;
            }

            totalSent += *result;
        }
    }
}
