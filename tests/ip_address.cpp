#include "onion/inet_address.hpp"

#include <doctest/doctest.h>

#include <stdexcept>
#include <tuple>

using namespace onion;

TEST_CASE("[IpAddress] IPv4 any address") {
    CHECK_NOTHROW(std::ignore = IpAddress("0.0.0.0"));

    IpAddress addr(0, 0, 0, 0);
    CHECK(addr == Ipv4Any);
    CHECK(addr == IpAddress("0.0.0.0"));

    CHECK(addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(!addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv4() == addr);

    CHECK(!IpAddress(1, 0, 0, 0).isIpv4Any());
    CHECK(!IpAddress(0, 1, 0, 0).isIpv4Any());
    CHECK(!IpAddress(0, 0, 1, 0).isIpv4Any());
    CHECK(!IpAddress(0, 0, 0, 1).isIpv4Any());
}

TEST_CASE("[IpAddress] IPv4 broadcast address") {
    CHECK_NOTHROW(std::ignore = IpAddress("255.255.255.255"));

    IpAddress addr(255, 255, 255, 255);
    CHECK(addr == Ipv4Broadcast);
    CHECK(addr == IpAddress("255.255.255.255"));

    CHECK(addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(!addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv4() == addr);

    CHECK(!IpAddress(1, 255, 255, 255).isIpv4Broadcast());
    CHECK(!IpAddress(255, 1, 255, 255).isIpv4Broadcast());
    CHECK(!IpAddress(255, 255, 1, 255).isIpv4Broadcast());
    CHECK(!IpAddress(255, 255, 255, 1).isIpv4Broadcast());
}

TEST_CASE("[IpAddress] IPv4 link-local address") {
    CHECK_NOTHROW(std::ignore = IpAddress("169.254.0.1"));

    IpAddress addr(169, 254, 0, 1);
    CHECK(addr == IpAddress("169.254.0.1"));

    CHECK(addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(!addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv4() == addr);
    CHECK(!IpAddress(169, 255, 0, 1).isIpv4LinkLocal());
}

TEST_CASE("[IpAddress] IPv4 loopback address") {
    CHECK_NOTHROW(std::ignore = IpAddress("127.0.0.1"));
    CHECK_THROWS_AS(std::ignore = IpAddress(""), std::invalid_argument);
    CHECK_THROWS_AS(std::ignore = IpAddress("123.456.789.0"), std::invalid_argument);

    std::string longAddress(46, 'a');
    CHECK_THROWS_AS(std::ignore = IpAddress(longAddress), std::invalid_argument);

    longAddress = std::string(72, '1');
    CHECK_THROWS_AS(std::ignore = IpAddress(longAddress), std::invalid_argument);

    IpAddress addr(127, 0, 0, 1);
    CHECK(addr == Ipv4Loopback);
    CHECK(addr == IpAddress("127.0.0.1"));

    CHECK(addr.isIpv4());
    CHECK(addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(!addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv4() == addr);
    CHECK(addr.toIpv6() == IpAddress("::FFFF:7F00:0001"));

    CHECK(!IpAddress(128, 0, 0, 1).isIpv4Loopback());
    CHECK(!IpAddress(127, 1, 0, 1).isIpv4Loopback());
    CHECK(!IpAddress(127, 0, 1, 1).isIpv4Loopback());
    CHECK(!IpAddress(127, 0, 0, 2).isIpv4Loopback());
}

TEST_CASE("[IpAddress] IPv4-mapped IPv6 address") {
    CHECK_NOTHROW(std::ignore = IpAddress("::FFFF:7F00:0001"));

    IpAddress addr(0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001);
    CHECK(addr == IpAddress("::FFFF:7F00:0001"));

    CHECK(!addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv6() == addr);
    CHECK(addr.toIpv4() == IpAddress(127, 0, 0, 1));

    CHECK(!IpAddress(1, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001).isIpv4MappedIpv6());
    CHECK(!IpAddress(0, 1, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001).isIpv4MappedIpv6());
    CHECK(!IpAddress(0, 0, 1, 0, 0, 0xFFFF, 0x7F00, 0x0001).isIpv4MappedIpv6());
    CHECK(!IpAddress(0, 0, 0, 1, 0, 0xFFFF, 0x7F00, 0x0001).isIpv4MappedIpv6());
    CHECK(!IpAddress(0, 0, 0, 0, 1, 0xFFFF, 0x7F00, 0x0001).isIpv4MappedIpv6());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 0xFFFE, 0x7F00, 0x0001).isIpv4MappedIpv6());
}

TEST_CASE("[IpAddress] IPv4 multicast address") {
    CHECK_NOTHROW(std::ignore = IpAddress("224.0.2.1"));

    IpAddress addr(224, 0, 2, 1);
    CHECK(addr == IpAddress("224.0.2.1"));

    CHECK(addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(addr.isIpv4Multicast());

    CHECK(!addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv4() == addr);
}

TEST_CASE("[IpAddress] IPv4 private address") {
    CHECK_NOTHROW(std::ignore = IpAddress("10.114.5.14"));
    CHECK_NOTHROW(std::ignore = IpAddress("172.31.0.1"));
    CHECK_NOTHROW(std::ignore = IpAddress("192.168.114.1"));

    IpAddress a(10, 114, 5, 14);

    CHECK(a == IpAddress("10.114.5.14"));
    CHECK(a.isIpv4());
    CHECK(!a.isIpv4Loopback());
    CHECK(!a.isIpv4Any());
    CHECK(!a.isIpv4Broadcast());
    CHECK(a.isIpv4Private());
    CHECK(!a.isIpv4LinkLocal());
    CHECK(!a.isIpv4Multicast());

    CHECK(!a.isIpv6());
    CHECK(!a.isIpv6Loopback());
    CHECK(!a.isIpv6Any());
    CHECK(!a.isIpv6Multicast());
    CHECK(!a.isIpv4MappedIpv6());

    CHECK(a.toIpv4() == a);

    IpAddress b(172, 31, 0, 1);

    CHECK(b == IpAddress("172.31.0.1"));
    CHECK(b.isIpv4());
    CHECK(!b.isIpv4Loopback());
    CHECK(!b.isIpv4Any());
    CHECK(!b.isIpv4Broadcast());
    CHECK(b.isIpv4Private());
    CHECK(!b.isIpv4LinkLocal());
    CHECK(!b.isIpv4Multicast());

    CHECK(!b.isIpv6());
    CHECK(!b.isIpv6Loopback());
    CHECK(!b.isIpv6Any());
    CHECK(!b.isIpv6Multicast());
    CHECK(!b.isIpv4MappedIpv6());

    CHECK(b.toIpv4() == b);
    CHECK(!IpAddress(172, 32, 0, 1).isIpv4Private());

    IpAddress c(192, 168, 0, 1);

    CHECK(c == IpAddress("192.168.0.1"));
    CHECK(c.isIpv4());
    CHECK(!c.isIpv4Loopback());
    CHECK(!c.isIpv4Any());
    CHECK(!c.isIpv4Broadcast());
    CHECK(c.isIpv4Private());
    CHECK(!c.isIpv4LinkLocal());
    CHECK(!c.isIpv4Multicast());

    CHECK(!c.isIpv6());
    CHECK(!c.isIpv6Loopback());
    CHECK(!c.isIpv6Any());
    CHECK(!c.isIpv6Multicast());
    CHECK(!c.isIpv4MappedIpv6());

    CHECK(c.toIpv4() == c);
    CHECK(!IpAddress(192, 169, 0, 1).isIpv4Private());
}

TEST_CASE("[IpAddress] IPv6 any address") {
    CHECK_NOTHROW(std::ignore = IpAddress("::"));

    IpAddress addr(0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(addr == Ipv6Any);
    CHECK(addr == IpAddress("::"));

    CHECK(!addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv6() == addr);

    CHECK(!IpAddress(1, 0, 0, 0, 0, 0, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 1, 0, 0, 0, 0, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 1, 0, 0, 0, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 0, 1, 0, 0, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 0, 0, 1, 0, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 1, 0, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 0, 1, 0).isIpv6Any());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 0, 0, 1).isIpv6Any());
}

TEST_CASE("[IpAddress] IPv6 loopback address") {
    CHECK_NOTHROW(std::ignore = IpAddress("::1"));
    CHECK_NOTHROW(std::ignore = IpAddress("0:0:0:0:0:0:0:1"));
    CHECK_THROWS_AS(std::ignore = IpAddress(":::1"), std::invalid_argument);
    CHECK_THROWS_AS(std::ignore = IpAddress("0:0:0:0:0:0:0:0:1"), std::invalid_argument);

    IpAddress addr(0, 0, 0, 0, 0, 0, 0, 1);
    CHECK(addr == Ipv6Loopback);
    CHECK(addr == IpAddress("::1"));

    CHECK(!addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(addr.isIpv6());
    CHECK(addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(!addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(!IpAddress(1, 0, 0, 0, 0, 0, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 1, 0, 0, 0, 0, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 1, 0, 0, 0, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 0, 1, 0, 0, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 0, 0, 1, 0, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 1, 0, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 0, 1, 0).isIpv6Loopback());
    CHECK(!IpAddress(0, 0, 0, 0, 0, 0, 0, 0).isIpv6Loopback());

    CHECK(IpAddress(1, 0, 0, 0, 0, 0, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 1, 0, 0, 0, 0, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 1, 0, 0, 0, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 0, 1, 0, 0, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 0, 0, 1, 0, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 0, 0, 0, 1, 0, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 0, 0, 0, 0, 1, 0) != Ipv6Any);
    CHECK(IpAddress(0, 0, 0, 0, 0, 0, 0, 1) != Ipv6Any);
}

TEST_CASE("[IpAddress] IPv6 multicast address") {
    CHECK_NOTHROW(std::ignore = IpAddress("FF02::1"));

    IpAddress addr(0xFF02, 0, 0, 0, 0, 0, 0, 1);
    CHECK(addr == IpAddress("FF02::1"));

    CHECK(!addr.isIpv4());
    CHECK(!addr.isIpv4Loopback());
    CHECK(!addr.isIpv4Any());
    CHECK(!addr.isIpv4Broadcast());
    CHECK(!addr.isIpv4Private());
    CHECK(!addr.isIpv4LinkLocal());
    CHECK(!addr.isIpv4Multicast());

    CHECK(addr.isIpv6());
    CHECK(!addr.isIpv6Loopback());
    CHECK(!addr.isIpv6Any());
    CHECK(addr.isIpv6Multicast());
    CHECK(!addr.isIpv4MappedIpv6());

    CHECK(addr.toIpv6() == addr);
}
