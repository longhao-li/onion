#include "onion/http.hpp"

#include <cstdio>

using namespace onion;

/// \class logger
/// \brief
///   Interface class for simple logger.
class logger {
public:
    /// \brief
    ///   Destroy the logger.
    virtual ~logger() = default;

    /// \brief
    ///   Write a message.
    virtual auto write(std::string_view message) -> void = 0;
};

/// \class console_logger
/// \brief
///   Simple logger that writes to the console.
class console_logger final : public logger {
public:
    /// \brief
    ///   Write a message to the console.
    auto write(std::string_view message) -> void override {
        std::fwrite(message.data(), sizeof(char), message.size(), stdout);
        std::fwrite("\n", sizeof(char), 1, stdout);
    }
};

auto main(int argc, char **argv) -> int {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        inet_address address{ipv4_any, static_cast<std::uint16_t>(std::atoi(argv[1]))};
        http_server  server{address};

        // Add a logger middleware to the server.
        server.use([](http_context &context, task<> next) -> task<> {
            co_await next;
            std::fprintf(stdout, "%s %d\n", context.request.path.c_str(), context.response.status);
        });

        // Add a logger service to the server.
        server.add_service<logger, console_logger>();
        server.add_service<console_logger>();

        // HTTP GET example. The URL should be like: /hello
        server.map(http_method_get, "/hello", [](http_context &context) -> task<> {
            auto *log = context.server.get_service<logger>();
            log->write("Handling HTTP GET /hello");
            context.response.ok("Hello, world!");
            co_return;
        });

        // HTTP GET example with URL parameters. The URL should be like: /greetings/longhao-li
        server.map(http_method_get, "/greetings/:name", [](http_context &context) -> task<> {
            auto *log = context.server.get_service<console_logger>();
            log->write("Handling HTTP GET /greetings/:name");
            context.response.ok("Hello, " + context.request.params["name"] + "!");
            co_return;
        });

        // HTTP POST example. The body should be plaintext.
        server.map(http_method_post, "/reverse", [](http_context &context) -> task<> {
            context.response.ok(std::string{context.request.body.rbegin(), context.request.body.rend()});
            co_return;
        });

        // HTTP URL query example. The URL should be like: /info?name=longhao-li
        server.map(http_method_get, "/info", [](http_context &context) -> task<> {
            auto &request = context.request;
            if (auto iter = request.queries.find("name"); iter != request.queries.end()) {
                context.response.ok("Hello, " + iter->second + ", your name takes " +
                                    std::to_string(iter->second.size()) + " bytes!");
            } else {
                context.response.ok("What is your name?");
            }
            co_return;
        });

        server.run();
    } catch (std::exception &e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return 0;
}
