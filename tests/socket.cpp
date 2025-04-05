#include "onion/socket.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <tuple>

using namespace onion;

// A dirty hack to use google test in coroutines.
#define assert_true(statement)             [&] { ASSERT_TRUE(statement); }()
#define assert_false(statement)            [&] { ASSERT_FALSE(statement); }()
#define assert_eq(val1, val2)              [&] { ASSERT_EQ(val1, val2); }()
#define assert_ne(val1, val2)              [&] { ASSERT_NE(val1, val2); }()
#define assert_ge(val1, val2)              [&] { ASSERT_GE(val1, val2); }()
#define assert_throw(statement, exception) [&] { ASSERT_THROW(statement, exception); }()

TEST(ip_address, ipv4_any_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"0.0.0.0"});

    ip_address addr{0, 0, 0, 0};
    ASSERT_EQ(addr, ipv4_any);
    ASSERT_EQ(addr, ip_address{"0.0.0.0"});

    ASSERT_TRUE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_TRUE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_TRUE(addr.to_string() == "0.0.0.0");

    ASSERT_FALSE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv4(), addr);

    ASSERT_FALSE((ip_address{1, 0, 0, 0}.is_ipv4_any()));
    ASSERT_FALSE((ip_address{0, 1, 0, 0}.is_ipv4_any()));
    ASSERT_FALSE((ip_address{0, 0, 1, 0}.is_ipv4_any()));
    ASSERT_FALSE((ip_address{0, 0, 0, 1}.is_ipv4_any()));
}

TEST(ip_address, ipv4_broadcast_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"255.255.255.255"});

    ip_address addr{255, 255, 255, 255};
    ASSERT_EQ(addr, ipv4_broadcast);
    ASSERT_EQ(addr, ip_address{"255.255.255.255"});

    ASSERT_TRUE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_TRUE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "255.255.255.255");

    ASSERT_FALSE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv4(), addr);

    ASSERT_FALSE((ip_address{1, 255, 255, 255}.is_ipv4_broadcast()));
    ASSERT_FALSE((ip_address{255, 1, 255, 255}.is_ipv4_broadcast()));
    ASSERT_FALSE((ip_address{255, 255, 1, 255}.is_ipv4_broadcast()));
    ASSERT_FALSE((ip_address{255, 255, 255, 1}.is_ipv4_broadcast()));
}

TEST(ip_address, ipv4_link_local_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"169.254.0.1"});

    ip_address addr{169, 254, 0, 1};
    ASSERT_EQ(addr, ip_address{"169.254.0.1"});

    ASSERT_TRUE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_TRUE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "169.254.0.1");

    ASSERT_FALSE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv4(), addr);
    ASSERT_FALSE((ip_address{169, 255, 0, 1}.is_ipv4_link_local()));
}

TEST(ip_address, ipv4_loopback_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"127.0.0.1"});
    ASSERT_THROW(std::ignore = ip_address{""}, std::invalid_argument);
    ASSERT_THROW(std::ignore = ip_address{"123.456.789.0"}, std::invalid_argument);

    std::string longAddress(46, 'a');
    ASSERT_THROW(std::ignore = ip_address{longAddress}, std::invalid_argument);

    longAddress = std::string(72, '1');
    ASSERT_THROW(std::ignore = ip_address{longAddress}, std::invalid_argument);

    ip_address addr{127, 0, 0, 1};
    ASSERT_EQ(addr, ipv4_loopback);
    ASSERT_EQ(addr, ip_address{"127.0.0.1"});

    ASSERT_TRUE(addr.is_ipv4());
    ASSERT_TRUE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "127.0.0.1");

    ASSERT_FALSE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv4(), addr);

    ip_address addr2{"::FFFF:7F00:0001"};
    ip_address v6 = addr.to_ipv6();
    ASSERT_EQ(v6, addr2);

    ASSERT_FALSE((ip_address{128, 0, 0, 1}.is_ipv4_loopback()));
    ASSERT_FALSE((ip_address{127, 1, 0, 1}.is_ipv4_loopback()));
    ASSERT_FALSE((ip_address{127, 0, 1, 1}.is_ipv4_loopback()));
    ASSERT_FALSE((ip_address{127, 0, 0, 2}.is_ipv4_loopback()));
}

TEST(ip_address, ipv4_mapped_ipv6_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"::FFFF:7F00:0001"});

    ip_address addr{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001};
    ASSERT_EQ(addr, ip_address{"::FFFF:7F00:0001"});

    ASSERT_FALSE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());

    ASSERT_TRUE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_TRUE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv6(), addr);
    ASSERT_EQ(addr.to_ipv4(), (ip_address{127, 0, 0, 1}));

    ASSERT_FALSE((ip_address{1, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
    ASSERT_FALSE((ip_address{0, 1, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
    ASSERT_FALSE((ip_address{0, 0, 1, 0, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
    ASSERT_FALSE((ip_address{0, 0, 0, 1, 0, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 1, 0xFFFF, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 0xFFFE, 0x7F00, 0x0001}.is_ipv4_mapped_ipv6()));
}

TEST(ip_address, ipv4_multicast_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"224.0.2.1"});

    ip_address addr{224, 0, 2, 1};
    ASSERT_EQ(addr, ip_address{"224.0.2.1"});

    ASSERT_TRUE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_TRUE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "224.0.2.1");

    ASSERT_FALSE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv4(), addr);
}

TEST(ip_address, ipv4_private_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"10.114.5.14"});
    ASSERT_NO_THROW(std::ignore = ip_address{"172.31.0.1"});
    ASSERT_NO_THROW(std::ignore = ip_address{"192.168.114.1"});

    ip_address a{10, 114, 5, 14};

    ASSERT_EQ(a, ip_address{"10.114.5.14"});
    ASSERT_TRUE(a.is_ipv4());
    ASSERT_FALSE(a.is_ipv4_loopback());
    ASSERT_FALSE(a.is_ipv4_any());
    ASSERT_FALSE(a.is_ipv4_broadcast());
    ASSERT_TRUE(a.is_ipv4_private());
    ASSERT_FALSE(a.is_ipv4_link_local());
    ASSERT_FALSE(a.is_ipv4_multicast());
    ASSERT_EQ(a.to_string(), "10.114.5.14");

    ASSERT_FALSE(a.is_ipv6());
    ASSERT_FALSE(a.is_ipv6_loopback());
    ASSERT_FALSE(a.is_ipv6_any());
    ASSERT_FALSE(a.is_ipv6_multicast());
    ASSERT_FALSE(a.is_ipv4_mapped_ipv6());

    ASSERT_EQ(a.to_ipv4(), a);

    ip_address b{172, 31, 0, 1};

    ASSERT_EQ(b, ip_address{"172.31.0.1"});
    ASSERT_TRUE(b.is_ipv4());
    ASSERT_FALSE(b.is_ipv4_loopback());
    ASSERT_FALSE(b.is_ipv4_any());
    ASSERT_FALSE(b.is_ipv4_broadcast());
    ASSERT_TRUE(b.is_ipv4_private());
    ASSERT_FALSE(b.is_ipv4_link_local());
    ASSERT_FALSE(b.is_ipv4_multicast());
    ASSERT_EQ(b.to_string(), "172.31.0.1");

    ASSERT_FALSE(b.is_ipv6());
    ASSERT_FALSE(b.is_ipv6_loopback());
    ASSERT_FALSE(b.is_ipv6_any());
    ASSERT_FALSE(b.is_ipv6_multicast());
    ASSERT_FALSE(b.is_ipv4_mapped_ipv6());

    ASSERT_EQ(b.to_ipv4(), b);
    ASSERT_FALSE((ip_address{172, 32, 0, 1}).is_ipv4_private());

    ip_address c{192, 168, 0, 1};

    ASSERT_EQ(c, ip_address{"192.168.0.1"});
    ASSERT_TRUE(c.is_ipv4());
    ASSERT_FALSE(c.is_ipv4_loopback());
    ASSERT_FALSE(c.is_ipv4_any());
    ASSERT_FALSE(c.is_ipv4_broadcast());
    ASSERT_TRUE(c.is_ipv4_private());
    ASSERT_FALSE(c.is_ipv4_link_local());
    ASSERT_FALSE(c.is_ipv4_multicast());
    ASSERT_EQ(c.to_string(), "192.168.0.1");

    ASSERT_FALSE(c.is_ipv6());
    ASSERT_FALSE(c.is_ipv6_loopback());
    ASSERT_FALSE(c.is_ipv6_any());
    ASSERT_FALSE(c.is_ipv6_multicast());
    ASSERT_FALSE(c.is_ipv4_mapped_ipv6());

    ASSERT_EQ(c.to_ipv4(), c);
    ASSERT_FALSE((ip_address{192, 169, 0, 1}).is_ipv4_private());
}

TEST(ip_address, ipv6_any_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"::"});

    ip_address addr{0, 0, 0, 0, 0, 0, 0, 0};
    ASSERT_EQ(addr, ipv6_any);
    ASSERT_EQ(addr, ip_address{"::"});

    ASSERT_FALSE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "::");

    ASSERT_TRUE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_TRUE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv6(), addr);

    ASSERT_FALSE((ip_address{1, 0, 0, 0, 0, 0, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 1, 0, 0, 0, 0, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 1, 0, 0, 0, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 0, 1, 0, 0, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 1, 0, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 1, 0, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 0, 1, 0}).is_ipv6_any());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 0, 0, 1}).is_ipv6_any());
}

TEST(ip_address, ipv6_loopback_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"::1"});
    ASSERT_NO_THROW(std::ignore = ip_address{"0:0:0:0:0:0:0:1"});
    ASSERT_THROW(std::ignore = ip_address{":::1"}, std::invalid_argument);
    ASSERT_THROW(std::ignore = ip_address{"0:0:0:0:0:0:0:0:1"}, std::invalid_argument);

    ip_address addr{0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT_EQ(addr, ipv6_loopback);
    ASSERT_EQ(addr, ip_address{"::1"});

    ASSERT_FALSE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());
    ASSERT_EQ(addr.to_string(), "::1");

    ASSERT_TRUE(addr.is_ipv6());
    ASSERT_TRUE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_FALSE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_FALSE((ip_address{1, 0, 0, 0, 0, 0, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 1, 0, 0, 0, 0, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 1, 0, 0, 0, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 0, 1, 0, 0, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 1, 0, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 1, 0, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 0, 1, 0}).is_ipv6_loopback());
    ASSERT_FALSE((ip_address{0, 0, 0, 0, 0, 0, 0, 0}).is_ipv6_loopback());

    ASSERT_NE((ip_address{1, 0, 0, 0, 0, 0, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 1, 0, 0, 0, 0, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 1, 0, 0, 0, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 0, 1, 0, 0, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 0, 0, 1, 0, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 0, 0, 0, 1, 0, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 0, 0, 0, 0, 1, 0}), ipv6_any);
    ASSERT_NE((ip_address{0, 0, 0, 0, 0, 0, 0, 1}), ipv6_any);
}

TEST(ip_address, ipv6_multicast_address) {
    ASSERT_NO_THROW(std::ignore = ip_address{"FF02::1"});

    ip_address addr{0xFF02, 0, 0, 0, 0, 0, 0, 1};
    ASSERT_EQ(addr, ip_address{"FF02::1"});

    ASSERT_FALSE(addr.is_ipv4());
    ASSERT_FALSE(addr.is_ipv4_loopback());
    ASSERT_FALSE(addr.is_ipv4_any());
    ASSERT_FALSE(addr.is_ipv4_broadcast());
    ASSERT_FALSE(addr.is_ipv4_private());
    ASSERT_FALSE(addr.is_ipv4_link_local());
    ASSERT_FALSE(addr.is_ipv4_multicast());

    ASSERT_TRUE(addr.is_ipv6());
    ASSERT_FALSE(addr.is_ipv6_loopback());
    ASSERT_FALSE(addr.is_ipv6_any());
    ASSERT_TRUE(addr.is_ipv6_multicast());
    ASSERT_FALSE(addr.is_ipv4_mapped_ipv6());

    ASSERT_EQ(addr.to_ipv6(), addr);
}

TEST(tcp_listener, tcp_ping_pong) {
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
            assert_true(result.has_value());
            total_size += *result;

            recv_size               = *result;
            std::uint32_t sent_size = 0;
            while (sent_size < recv_size) {
                result = co_await stream.send(buffer + sent_size, recv_size - sent_size);
                assert_true(result.has_value());
                sent_size += *result;
            }
        }
    };

    auto listener = [&](inet_address address) -> task<> {
        tcp_listener srv;

        auto error = srv.listen(address);
        assert_eq(error.value(), 0);
        assert_eq(srv.local_address(), address);

        server_ready.store(true, std::memory_order_relaxed);

        auto stream = co_await srv.accept();
        assert_true(stream.has_value());

        co_await schedule(server(*std::move(stream)));
    };

    auto client = [&](inet_address address) -> task<> {
        tcp_stream stream;

        while (!server_ready.load(std::memory_order_acquire))
            co_await yield();

        auto error = co_await stream.connect(address);
        assert_eq(error.value(), 0);
        assert_eq(stream.peer_address(), address);

        assert_eq(stream.set_keepalive(true).value(), 0);
        assert_eq(stream.set_nodelay(true).value(), 0);

        char        buffer[buffer_size]{};
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t send_size = (std::min)(buffer_size, packet_size * packet_count - total_size);

            auto result = co_await stream.send(buffer, send_size);
            assert_true(result.has_value());
            total_size += *result;

            send_size               = *result;
            std::uint32_t recv_size = 0;
            while (recv_size < send_size) {
                result = co_await stream.receive(buffer + recv_size, send_size - recv_size);
                assert_true(result.has_value());
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

TEST(udp_socket, udp_ping_pong) {
    constexpr std::size_t packet_count = 1000;
    constexpr std::size_t packet_size  = 1024;
    constexpr std::size_t buffer_size  = 1024;

    io_context       context;
    std::atomic_bool server_ready{false};
    inet_address     client_address{ipv6_loopback, 23334};
    inet_address     server_address{ipv6_loopback, 23335};

    auto server = [&]() -> task<> {
        udp_socket socket;

        auto error = socket.bind(server_address);
        assert_eq(error.value(), 0);
        assert_eq(socket.local_address(), server_address);

        server_ready.store(true, std::memory_order_relaxed);

        inet_address peer;
        char         buffer[buffer_size];

        for (std::size_t i = 0; i < packet_count; ++i) {
            auto result = co_await socket.receive(buffer, buffer_size, peer);

            assert_true(result.has_value());
            assert_eq(*result, packet_size);
            assert_eq(peer, client_address);

            result = co_await socket.send(buffer, *result, peer);
            assert_true(result.has_value());
            assert_eq(*result, packet_size);
        }
    };

    auto client = [&]() -> task<> {
        udp_socket socket;

        auto error = socket.bind(client_address);
        assert_eq(error.value(), 0);
        assert_eq(socket.local_address(), client_address);

        while (!server_ready.load(std::memory_order_acquire))
            co_await yield();

        error = co_await socket.connect(server_address);
        assert_eq(error.value(), 0);

        char buffer[buffer_size]{};
        for (std::size_t i = 0; i < packet_count; ++i) {
            auto result = co_await socket.send(buffer, packet_size);
            assert_true(result.has_value());
            assert_eq(*result, packet_size);

            result = co_await socket.receive(buffer, buffer_size);
            assert_true(result.has_value());
            assert_eq(*result, packet_size);
        }

        context.stop();
    };

    context.schedule(server());
    context.schedule(client());
    context.run();
}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
TEST(unix_listener, unix_socket_ping_pong) {
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
            assert_true(result.has_value());
            total_size += *result;

            recv_size               = *result;
            std::uint32_t sent_size = 0;
            while (sent_size < recv_size) {
                result = co_await stream.send(buffer + sent_size, recv_size - sent_size);
                assert_true(result.has_value());
                sent_size += *result;
            }
        }
    };

    auto listener = [&](std::string_view address) -> task<> {
        unix_listener srv;

        auto error = srv.listen(address);
        assert_eq(error.value(), 0);
        assert_eq(srv.local_address(), address);

        server_ready.store(true, std::memory_order_release);

        auto stream = co_await srv.accept();
        assert_true(stream.has_value());

        co_await schedule(server(*std::move(stream)));
    };

    auto client = [&](std::string_view address) -> task<> {
        unix_stream stream;

        while (!server_ready.load(std::memory_order_acquire))
            co_await yield();

        auto error = co_await stream.connect(address);
        assert_eq(error.value(), 0);
        assert_eq(stream.peer_address(), address);

        char        buffer[buffer_size]{};
        std::size_t total_size = 0;

        while (total_size < packet_size * packet_count) {
            std::uint32_t send_size = (std::min)(buffer_size, packet_size * packet_count - total_size);

            auto result = co_await stream.send(buffer, send_size);
            assert_true(result.has_value());
            total_size += *result;

            send_size               = *result;
            std::uint32_t recv_size = 0;
            while (recv_size < send_size) {
                result = co_await stream.receive(buffer + recv_size, send_size - recv_size);
                assert_true(result.has_value());
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
