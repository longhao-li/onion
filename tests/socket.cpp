#include "onion/socket.hpp"

#include <doctest/doctest.h>

#include <stdexcept>
#include <tuple>

using namespace onion;

TEST_CASE("[ip_address] ipv4 any address") {
    CHECK_NOTHROW(std::ignore = ip_address{"0.0.0.0"});

    ip_address addr{0, 0, 0, 0};
    CHECK(addr == ipv4_any);
    CHECK(addr == ip_address{"0.0.0.0"});

    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "0.0.0.0");

    CHECK(!addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv4() == addr);

    CHECK(!ip_address{1, 0, 0, 0}.is_ipv4_any());
    CHECK(!ip_address{0, 1, 0, 0}.is_ipv4_any());
    CHECK(!ip_address{0, 0, 1, 0}.is_ipv4_any());
    CHECK(!ip_address{0, 0, 0, 1}.is_ipv4_any());
}

TEST_CASE("[ip_address] ipv4 broadcast address") {
    CHECK_NOTHROW(std::ignore = ip_address{"255.255.255.255"});

    ip_address addr{255, 255, 255, 255};
    CHECK(addr == ipv4_broadcast);
    CHECK(addr == ip_address{"255.255.255.255"});

    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "255.255.255.255");

    CHECK(!addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv4() == addr);

    CHECK(!ip_address{1, 255, 255, 255}.is_ipv4_broadcast());
    CHECK(!ip_address{255, 1, 255, 255}.is_ipv4_broadcast());
    CHECK(!ip_address{255, 255, 1, 255}.is_ipv4_broadcast());
    CHECK(!ip_address{255, 255, 255, 1}.is_ipv4_broadcast());
}

TEST_CASE("[ip_address] ipv4 link-local address") {
    CHECK_NOTHROW(std::ignore = ip_address{"169.254.0.1"});

    ip_address addr{169, 254, 0, 1};
    CHECK(addr == ip_address{"169.254.0.1"});

    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "169.254.0.1");

    CHECK(!addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv4() == addr);
    CHECK(!ip_address{169, 255, 0, 1}.is_ipv4_link_local());
}

TEST_CASE("[ip_address] ipv4 loopback address") {
    CHECK_NOTHROW(std::ignore = ip_address{"127.0.0.1"});
    CHECK_THROWS_AS(std::ignore = ip_address{""}, std::invalid_argument);
    CHECK_THROWS_AS(std::ignore = ip_address{"123.456.789.0"}, std::invalid_argument);

    std::string longAddress(46, 'a');
    CHECK_THROWS_AS(std::ignore = ip_address{longAddress}, std::invalid_argument);

    longAddress = std::string(72, '1');
    CHECK_THROWS_AS(std::ignore = ip_address{longAddress}, std::invalid_argument);

    ip_address addr{127, 0, 0, 1};
    CHECK(addr == ipv4_loopback);
    CHECK(addr == ip_address{"127.0.0.1"});

    CHECK(addr.is_ipv4());
    CHECK(addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "127.0.0.1");

    CHECK(!addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv4() == addr);

    ip_address addr2{"::FFFF:7F00:0001"};
    ip_address v6 = addr.to_ipv6();
    CHECK(v6 == addr2);

    CHECK(!ip_address{128, 0, 0, 1}.is_ipv4_loopback());
    CHECK(!ip_address{127, 1, 0, 1}.is_ipv4_loopback());
    CHECK(!ip_address{127, 0, 1, 1}.is_ipv4_loopback());
    CHECK(!ip_address{127, 0, 0, 2}.is_ipv4_loopback());
}

TEST_CASE("[ip_address] ipv4-mapped ipv6 address") {
    CHECK_NOTHROW(std::ignore = ip_address{"::FFFF:7F00:0001"});

    ip_address addr{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001};
    CHECK(addr == ip_address{"::FFFF:7F00:0001"});

    CHECK(!addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());

    CHECK(addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv6() == addr);
    CHECK(addr.to_ipv4() == ip_address{127, 0, 0, 1});

    CHECK(!ip_address{1, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
    CHECK(!ip_address{0, 1, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
    CHECK(!ip_address{0, 0, 1, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
    CHECK(!ip_address{0, 0, 0, 1, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
    CHECK(!ip_address{0, 0, 0, 0, 1, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
    CHECK(!ip_address{0, 0, 0, 0, 0, 0xFFFE, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6());
}

TEST_CASE("[ip_address] ipv4 multicast address") {
    CHECK_NOTHROW(std::ignore = ip_address{"224.0.2.1"});

    ip_address addr{224, 0, 2, 1};
    CHECK(addr == ip_address{"224.0.2.1"});

    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "224.0.2.1");

    CHECK(!addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv4() == addr);
}

TEST_CASE("[ip_address] ipv4 private address") {
    CHECK_NOTHROW(std::ignore = ip_address{"10.114.5.14"});
    CHECK_NOTHROW(std::ignore = ip_address{"172.31.0.1"});
    CHECK_NOTHROW(std::ignore = ip_address{"192.168.114.1"});

    ip_address a{10, 114, 5, 14};

    CHECK(a == ip_address{"10.114.5.14"});
    CHECK(a.is_ipv4());
    CHECK(!a.is_ipv4_loopback());
    CHECK(!a.is_ipv4_any());
    CHECK(!a.is_ipv4_broadcast());
    CHECK(a.is_ipv4_private());
    CHECK(!a.is_ipv4_link_local());
    CHECK(!a.is_ipv4_multicast());
    CHECK(a.to_string() == "10.114.5.14");

    CHECK(!a.is_ipv6());
    CHECK(!a.is_ipv6_loopback());
    CHECK(!a.is_ipv6_any());
    CHECK(!a.is_ipv6_multicast());
    CHECK(!a.is_ipv4_mapped_ipv6());

    CHECK(a.to_ipv4() == a);

    ip_address b{172, 31, 0, 1};

    CHECK(b == ip_address{"172.31.0.1"});
    CHECK(b.is_ipv4());
    CHECK(!b.is_ipv4_loopback());
    CHECK(!b.is_ipv4_any());
    CHECK(!b.is_ipv4_broadcast());
    CHECK(b.is_ipv4_private());
    CHECK(!b.is_ipv4_link_local());
    CHECK(!b.is_ipv4_multicast());
    CHECK(b.to_string() == "172.31.0.1");

    CHECK(!b.is_ipv6());
    CHECK(!b.is_ipv6_loopback());
    CHECK(!b.is_ipv6_any());
    CHECK(!b.is_ipv6_multicast());
    CHECK(!b.is_ipv4_mapped_ipv6());

    CHECK(b.to_ipv4() == b);
    CHECK(!ip_address{172, 32, 0, 1}.is_ipv4_private());

    ip_address c{192, 168, 0, 1};

    CHECK(c == ip_address{"192.168.0.1"});
    CHECK(c.is_ipv4());
    CHECK(!c.is_ipv4_loopback());
    CHECK(!c.is_ipv4_any());
    CHECK(!c.is_ipv4_broadcast());
    CHECK(c.is_ipv4_private());
    CHECK(!c.is_ipv4_link_local());
    CHECK(!c.is_ipv4_multicast());
    CHECK(c.to_string() == "192.168.0.1");

    CHECK(!c.is_ipv6());
    CHECK(!c.is_ipv6_loopback());
    CHECK(!c.is_ipv6_any());
    CHECK(!c.is_ipv6_multicast());
    CHECK(!c.is_ipv4_mapped_ipv6());

    CHECK(c.to_ipv4() == c);
    CHECK(!ip_address{192, 169, 0, 1}.is_ipv4_private());
}

TEST_CASE("[ip_address] ipv6 any address") {
    CHECK_NOTHROW(std::ignore = ip_address{"::"});

    ip_address addr{0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(addr == ipv6_any);
    CHECK(addr == ip_address{"::"});

    CHECK(!addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "::");

    CHECK(addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv6() == addr);

    CHECK(!ip_address{1, 0, 0, 0, 0, 0, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 1, 0, 0, 0, 0, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 1, 0, 0, 0, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 0, 1, 0, 0, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 0, 0, 1, 0, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 0, 0, 0, 1, 0, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 0, 0, 0, 0, 1, 0}.is_ipv6_any());
    CHECK(!ip_address{0, 0, 0, 0, 0, 0, 0, 1}.is_ipv6_any());
}

TEST_CASE("[ip_address] ipv6 loopback address") {
    CHECK_NOTHROW(std::ignore = ip_address{"::1"});
    CHECK_NOTHROW(std::ignore = ip_address{"0:0:0:0:0:0:0:1"});
    CHECK_THROWS_AS(std::ignore = ip_address{":::1"}, std::invalid_argument);
    CHECK_THROWS_AS(std::ignore = ip_address{"0:0:0:0:0:0:0:0:1"}, std::invalid_argument);

    ip_address addr{0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(addr == ipv6_loopback);
    CHECK(addr == ip_address{"::1"});

    CHECK(!addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());
    CHECK(addr.to_string() == "::1");

    CHECK(addr.is_ipv6());
    CHECK(addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(!addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(!ip_address{1, 0, 0, 0, 0, 0, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 1, 0, 0, 0, 0, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 1, 0, 0, 0, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 0, 1, 0, 0, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 0, 0, 1, 0, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 0, 0, 0, 1, 0, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 0, 0, 0, 0, 1, 0}.is_ipv6_loopback());
    CHECK(!ip_address{0, 0, 0, 0, 0, 0, 0, 0}.is_ipv6_loopback());

    CHECK(ip_address{1, 0, 0, 0, 0, 0, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 1, 0, 0, 0, 0, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 1, 0, 0, 0, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 0, 1, 0, 0, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 0, 0, 1, 0, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 0, 0, 0, 1, 0, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 0, 0, 0, 0, 1, 0} != ipv6_any);
    CHECK(ip_address{0, 0, 0, 0, 0, 0, 0, 1} != ipv6_any);
}

TEST_CASE("[ip_address] ipv6 multicast address") {
    CHECK_NOTHROW(std::ignore = ip_address{"FF02::1"});

    ip_address addr{0xFF02, 0, 0, 0, 0, 0, 0, 1};
    CHECK(addr == ip_address{"FF02::1"});

    CHECK(!addr.is_ipv4());
    CHECK(!addr.is_ipv4_loopback());
    CHECK(!addr.is_ipv4_any());
    CHECK(!addr.is_ipv4_broadcast());
    CHECK(!addr.is_ipv4_private());
    CHECK(!addr.is_ipv4_link_local());
    CHECK(!addr.is_ipv4_multicast());

    CHECK(addr.is_ipv6());
    CHECK(!addr.is_ipv6_loopback());
    CHECK(!addr.is_ipv6_any());
    CHECK(addr.is_ipv6_multicast());
    CHECK(!addr.is_ipv4_mapped_ipv6());

    CHECK(addr.to_ipv6() == addr);
}

TEST_CASE("[tcp_listener] tcp ping-pong") {
    constexpr std::size_t packet_count = 1000;
    constexpr std::size_t packet_size  = 1024;
    constexpr std::size_t buffer_size  = 1024;

    io_context       ctx;
    std::atomic_bool server_ready{false};

    auto server = [&](tcp_stream stream) -> task<> {
        char        buffer[buffer_size];
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t recv_size = (std::min)(packet_size, packet_size * packet_count - total_size);

            auto result = co_await stream.receive(buffer, recv_size);
            CHECK(result.has_value());
            total_size += *result;

            recv_size               = *result;
            std::uint32_t sent_size = 0;
            while (sent_size < recv_size) {
                result = co_await stream.send(buffer + sent_size, recv_size - sent_size);
                CHECK(result.has_value());
                sent_size += *result;
            }
        }
    };

    auto listener = [&](inet_address address) -> task<> {
        tcp_listener srv;

        auto error = srv.listen(address);
        CHECK(error.value() == 0);
        CHECK(srv.local_address() == address);

        server_ready.store(true, std::memory_order_release);

        auto stream = co_await srv.accept();
        CHECK(stream.has_value());

        co_await schedule(server(*std::move(stream)));
    };

    auto client = [&](inet_address address) -> task<> {
        tcp_stream stream;

        while (!server_ready.load(std::memory_order_acquire))
            co_await yield();

        auto error = co_await stream.connect(address);
        CHECK(error.value() == 0);
        CHECK(stream.peer_address() == address);

        CHECK(stream.set_keepalive(true).value() == 0);
        CHECK(stream.set_nodelay(true).value() == 0);

        char        buffer[buffer_size]{};
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t send_size = (std::min)(buffer_size, packet_size * packet_count - total_size);

            auto result = co_await stream.send(buffer, send_size);
            CHECK(result.has_value());
            total_size += *result;

            send_size               = *result;
            std::uint32_t recv_size = 0;
            while (recv_size < send_size) {
                result = co_await stream.receive(buffer + recv_size, send_size - recv_size);
                CHECK(result.has_value());
                recv_size += *result;
            }
        }

        ctx.stop();
    };

    inet_address address{ipv6_loopback, 23333};
    ctx.schedule(listener(address));
    ctx.schedule(client(address));
    ctx.run();
}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
TEST_CASE("[unix_listener] unix socket ping-pong") {
    constexpr std::size_t packet_count = 1000;
    constexpr std::size_t packet_size  = 1024;
    constexpr std::size_t buffer_size  = 1024;

    io_context       ctx;
    std::atomic_bool server_ready{false};

    auto server = [&](unix_stream stream) -> task<> {
        char        buffer[buffer_size];
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t recv_size = (std::min)(packet_size, packet_size * packet_count - total_size);

            auto result = co_await stream.receive(buffer, recv_size);
            CHECK(result.has_value());
            total_size += *result;

            recv_size               = *result;
            std::uint32_t sent_size = 0;
            while (sent_size < recv_size) {
                result = co_await stream.send(buffer + sent_size, recv_size - sent_size);
                CHECK(result.has_value());
                sent_size += *result;
            }
        }
    };

    auto listener = [&](std::string_view address) -> task<> {
        unix_listener srv;

        auto error = srv.listen(address);
        CHECK(error.value() == 0);
        CHECK(srv.local_address() == address);

        server_ready.store(true, std::memory_order_release);

        auto stream = co_await srv.accept();
        CHECK(stream.has_value());

        co_await schedule(server(*std::move(stream)));
    };

    auto client = [&](std::string_view address) -> task<> {
        unix_stream stream;

        while (!server_ready.load(std::memory_order_acquire))
            co_await yield();

        auto error = co_await stream.connect(address);
        CHECK(error.value() == 0);
        CHECK(stream.peer_address() == address);

        char        buffer[buffer_size]{};
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t send_size = (std::min)(buffer_size, packet_size * packet_count - total_size);

            auto result = co_await stream.send(buffer, send_size);
            CHECK(result.has_value());
            total_size += *result;

            send_size               = *result;
            std::uint32_t recv_size = 0;
            while (recv_size < send_size) {
                result = co_await stream.receive(buffer + recv_size, send_size - recv_size);
                CHECK(result.has_value());
                recv_size += *result;
            }
        }

        ctx.stop();
    };

    std::string address{"onion-test.sock"};
    ctx.schedule(listener(address));
    ctx.schedule(client(address));
    ctx.run();
}
#endif
