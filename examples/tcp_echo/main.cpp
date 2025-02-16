#include "onion/socket.hpp"

#include <cstdlib>
#include <format>
#include <print>
#include <thread>

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
        std::println(stderr, "Usage: {} <address> <port>", argv[0]);
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
        std::println(stderr, "Invalid IP address: {}", e.what());
        return EXIT_FAILURE;
    }

    return 0;
}

/// \brief
///   The acceptor worker for the server.
/// \param address
///   The address to listen for incoming connections.
static auto acceptor(InetAddress address) noexcept -> Task<> {
    std::println("Thread {} listening on {}", std::this_thread::get_id(), address.toString());

    // Bind server to the address.
    TcpListener listener;
    auto error = listener.listen(address);
    if (!error.ok()) [[unlikely]] {
        std::println(stderr, "TcpListener::listen on address {} failed: {}", address.toString(),
                     error.message());
        std::terminate();
    }

    // Listen for incoming connections.
    while (true) {
        auto result = co_await listener.acceptAsync();

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::println(stderr, "TcpListener::acceptAsync failed: {}", result.error().message());
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
    std::println("Connection with {} established.", remoteAddress.toString());

    char buffer[65536];
    while (true) {
        auto result = co_await stream.receive(buffer, sizeof(buffer));

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::println(stderr, "TcpStream::receive from {} failed: {}", remoteAddress.toString(),
                         result.error().message());
            co_return;
        }

        // Connection closed.
        std::uint32_t received = *result;
        if (received == 0) [[unlikely]] {
            std::println("Connection with {} closed.", remoteAddress.toString());
            co_return;
        }

        // Write a log.
        std::println("Received {} bytes from {}.", received, remoteAddress.toString());

        // Send received data back.
        std::uint32_t totalSent = 0;
        while (totalSent < received) {
            result = co_await stream.send(buffer + totalSent, received - totalSent);

            // Handle error.
            if (!result.has_value()) [[unlikely]] {
                std::println(stderr, "TcpStream::send to {} failed: {}", remoteAddress.toString(),
                             result.error().message());
                co_return;
            }

            totalSent += *result;
        }
    }
}
