#include "onion/socket.hpp"

using namespace onion;

/// \brief
///   The acceptor worker for the server.
/// \param address
///   The address to listen for incoming connections.
static auto acceptor(inet_address address) noexcept -> task<>;

/// \brief
///   Server the incoming connection.
/// \param stream
///   Stream of the incoming connection.
static auto server(tcp_stream stream) noexcept -> task<>;

auto main(int argc, char **argv) -> int {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        auto         port = static_cast<std::uint16_t>(std::atoi(argv[1]));
        inet_address address{ipv4_any, port};

        io_context context;
        context.schedule(acceptor(address));
        context.run();
    } catch (std::exception &e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
}

/// \brief
///   The acceptor worker for the server.
/// \param address
///   The address to listen for incoming connections.
static auto acceptor(inet_address address) noexcept -> task<> {
    std::printf("Listening on %s\n", address.to_string().c_str());

    // Bind server to the address.
    tcp_listener    listener;
    std::error_code error = listener.listen(address);

    if (error) [[unlikely]] {
        std::fprintf(stderr, "tcp_listener failed to listen to address %s: %s\n", address.to_string().c_str(),
                     error.message().c_str());
        std::terminate();
    }

    // Listen for incoming connections.
    while (true) {
        auto result = co_await listener.accept();

        if (!result.has_value()) [[unlikely]] {
            std::fprintf(stderr, "tcp_listener failed to accept incoming connection: %s\n",
                         result.error().message().c_str());
            continue;
        }

        // Schedule a new connection.
        co_await schedule(server(std::move(*result)));
    }
}

/// \brief
///   Server the incoming connection.
/// \param stream
///   Stream of the incoming connection.
static auto server(tcp_stream stream) noexcept -> task<> {
    std::printf("Connection established with %s\n", stream.peer_address().to_string().c_str());

    char buffer[16384];
    while (true) {
        auto result = co_await stream.receive(buffer, sizeof(buffer));

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::fprintf(stderr, "tcp_stream failed to receive data: %s\n", result.error().message().c_str());
            break;
        }

        // Connection closed.
        std::uint32_t received = *result;
        if (received == 0) {
            std::printf("Connection closed with %s\n", stream.peer_address().to_string().c_str());
            break;
        }

        // Echo the received data.
        std::uint32_t total_sent = 0;
        while (total_sent < received) {
            result = co_await stream.send(buffer + total_sent, received - total_sent);
            if (!result.has_value()) [[unlikely]] {
                std::fprintf(stderr, "tcp_stream failed to send data: %s\n", result.error().message().c_str());
                break;
            }

            total_sent += *result;
        }
    }
}
