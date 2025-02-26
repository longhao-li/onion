#include "onion/socket.hpp"

#include <doctest/doctest.h>

using namespace onion;

TEST_CASE("[InetAddress] To string") {
    CHECK_NOTHROW(std::ignore = InetAddress{"127.0.0.1", 2333});
    CHECK_NOTHROW(std::ignore = InetAddress{"::1", 2333});

    InetAddress v4{"127.0.0.1", 2333};
    CHECK(v4.toString() == "127.0.0.1:2333");

    InetAddress v6{"::1", 2333};
    CHECK(v6.toString() == "[::1]:2333");
}
