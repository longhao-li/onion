#include "onion/socket.hpp"

using namespace onion;

/// \brief
///   Server the incoming UDP packets.
/// \param address
///   The address to listen for incoming packets.
static auto server(inet_address address) noexcept -> task<>;

auto main(int argc, char **argv) -> int {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        auto         port = static_cast<std::uint16_t>(std::atoi(argv[1]));
        inet_address address{ipv4_any, port};

        io_context context;
        for (std::size_t i = 0; i < 8; ++i)
            context.schedule(server(address));

        context.run();
    } catch (std::exception &e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
}

/// \brief
///   Server the incoming UDP packets.
/// \param address
///   The address to listen for incoming packets.
static auto server(inet_address address) noexcept -> task<> {
    udp_socket      udp;
    std::error_code error = udp.bind(address);

    if (error) [[unlikely]] {
        std::fprintf(stderr, "udp_socket failed to bind to address %s: %s\n", address.to_string().c_str(),
                     error.message().c_str());
        co_return;
    }

    // Listen to incoming packets.
    inet_address peer;
    char         buffer[65507];
    while (true) {
        auto result = co_await udp.receive(buffer, sizeof(buffer), peer);

        // Handle error.
        if (!result.has_value()) [[unlikely]] {
            std::fprintf(stderr, "udp_socket failed to receive packet: %s\n", result.error().message().c_str());
            std::terminate();
        }

        // Echo the received data.
        co_await udp.send(buffer, *result, peer);
    }
}
