#pragma once

#include "socket.hpp"

#include <string_view>

namespace onion {

/// \class IpAddress
/// \brief
///   Represents either an IPv4 or IPv6 address.
class [[nodiscard]] IpAddress {
public:
    /// \brief
    ///   Create an empty IP address. An empty IP address is a zero-initialized IPv4 address.
    constexpr IpAddress() noexcept : m_isIpv6{}, m_addr{} {}

    /// \brief
    ///   Create an IPv4 address.
    /// \param v0
    ///   The first byte of the address.
    /// \param v1
    ///   The second byte of the address.
    /// \param v2
    ///   The third byte of the address.
    /// \param v3
    ///   The fourth byte of the address.
    constexpr IpAddress(std::uint8_t v0, std::uint8_t v1, std::uint8_t v2, std::uint8_t v3) noexcept
        : m_isIpv6{false},
          m_addr{.v4{.u8{v0, v1, v2, v3}}} {}

    /// \brief
    ///   Create an IPv6 address.
    /// \param v0
    ///   The first 16-bit value of the address in native endian.
    /// \param v1
    ///   The second 16-bit value of the address in native endian.
    /// \param v2
    ///   The third 16-bit value of the address in native endian.
    /// \param v3
    ///   The fourth 16-bit value of the address in native endian.
    /// \param v4
    ///   The fifth 16-bit value of the address in native endian.
    /// \param v5
    ///   The sixth 16-bit value of the address in native endian.
    /// \param v6
    ///   The seventh 16-bit value of the address in native endian.
    /// \param v7
    ///   The eighth 16-bit value of the address in native endian.
    constexpr IpAddress(std::uint16_t v0,
                        std::uint16_t v1,
                        std::uint16_t v2,
                        std::uint16_t v3,
                        std::uint16_t v4,
                        std::uint16_t v5,
                        std::uint16_t v6,
                        std::uint16_t v7) noexcept
        : m_isIpv6{true},
          m_addr{.v6{.u16{detail::toNetworkEndian(v0), detail::toNetworkEndian(v1),
                          detail::toNetworkEndian(v2), detail::toNetworkEndian(v3),
                          detail::toNetworkEndian(v4), detail::toNetworkEndian(v5),
                          detail::toNetworkEndian(v6), detail::toNetworkEndian(v7)}}} {}

    /// \brief
    ///   Create an IP address from a string.
    /// \param address
    ///   The string representation of the address.
    /// \throws std::invalid_argument
    ///   Thrown if \p address is neither a valid IPv4 nor a valid IPv6 address.
    ONION_API IpAddress(std::string_view address);

    /// \brief
    ///   Checks if this is an IPv4 address. An \c IpAddress object is either an IPv4 or an IPv6
    ///   address.
    /// \retval true
    ///   This is an IPv4 address.
    /// \retval false
    ///   This is an IPv6 address.
    [[nodiscard]]
    constexpr auto isIpv4() const noexcept -> bool {
        return !m_isIpv6;
    }

    /// \brief
    ///   Checks if this is an IPv6 address. An \c IpAddress object is either an IPv4 or an IPv6
    ///   address.
    /// \retval true
    ///   This is an IPv6 address.
    /// \retval false
    ///   This is an IPv4 address.
    [[nodiscard]]
    constexpr auto isIpv6() const noexcept -> bool {
        return m_isIpv6;
    }

    /// \brief
    ///   Checks if this address is an IPv4 loopback address. IPv4 loopback address is \c 127.0.0.1.
    /// \retval true
    ///   This address is an IPv4 loopback address.
    /// \retval false
    ///   This address is not an IPv4 loopback address.
    [[nodiscard]]
    constexpr auto isIpv4Loopback() const noexcept -> bool {
        if (!isIpv4())
            return false;
        return m_addr.v4.u8[0] == 127 && m_addr.v4.u8[1] == 0 && m_addr.v4.u8[2] == 0 &&
               m_addr.v4.u8[3] == 1;
    }

    /// \brief
    ///   Checks if this address is an IPv4 any address. IPv4 any address is \c 0.0.0.0.
    /// \retval true
    ///   This address is an IPv4 any address.
    /// \retval false
    ///   This address is not an IPv4 any address.
    [[nodiscard]]
    constexpr auto isIpv4Any() const noexcept -> bool {
        return isIpv4() && (m_addr.v4.u32[0] == 0);
    }

    /// \brief
    ///   Checks if this address is an IPv4 broadcast address. IPv4 broadcast address is
    ///   \c 255.255.255.255.
    /// \retval true
    ///   This address is an IPv4 broadcast address.
    /// \retval false
    ///   This address is not an IPv4 broadcast address.
    [[nodiscard]]
    constexpr auto isIpv4Broadcast() const noexcept -> bool {
        return isIpv4() && (m_addr.v4.u32[0] == 0xFFFFFFFFU);
    }

    /// \brief
    ///   Checks if this address is an IPv4 private address. An IPv4 private network is a network
    ///   that used for local area networks. Private address ranges are defined in RFC 1918 as
    ///   follows:
    ///   - \c 10.0.0.0/8
    ///   - \c 172.16.0.0/12
    ///   - \c 192.168.0.0/16
    /// \retval true
    ///   This address is an IPv4 private address.
    /// \retval false
    ///   This address is not an IPv4 private address.
    [[nodiscard]]
    constexpr auto isIpv4Private() const noexcept -> bool {
        if (!isIpv4())
            return false;

        // 10.0.0.0/8
        if (m_addr.v4.u8[0] == 10)
            return true;

        // 172.16.0.0/12
        if (m_addr.v4.u8[0] == 172 && (m_addr.v4.u8[1] & 0xF0) == 16)
            return true;

        // 192.168.0.0/16
        if (m_addr.v4.u8[0] == 192 && m_addr.v4.u8[1] == 168)
            return true;

        return false;
    }

    /// \brief
    ///   Checks if this address is an IPv4 link local address. IPv4 link local address is
    ///   \c 169.254.0.0/16 as defined in RFC 3927.
    /// \retval true
    ///   This address is an IPv4 link local address.
    /// \retval false
    ///   This address is not an IPv4 link local address.
    [[nodiscard]]
    constexpr auto isIpv4LinkLocal() const noexcept -> bool {
        if (!isIpv4())
            return false;
        return (m_addr.v4.u8[0] == 169) && (m_addr.v4.u8[1] == 254);
    }

    /// \brief
    ///   Checks if this address is an IPv4 multicast address. IPv4 multicast address is \c
    ///   224.0.0.0/4 as defined in RFC 5771.
    /// \retval true
    ///   This address is an IPv4 multicast address.
    /// \retval false
    ///   This address is not an IPv4 multicast address.
    [[nodiscard]]
    constexpr auto isIpv4Multicast() const noexcept -> bool {
        if (!isIpv4())
            return false;
        return (m_addr.v4.u8[0] & 0xF0) == 224;
    }

    /// \brief
    ///   Checks if this address is an IPv6 loopback address. IPv6 loopback address is \c ::1.
    /// \retval true
    ///   This address is an IPv6 loopback address.
    /// \retval false
    ///   This address is not an IPv6 loopback address.
    [[nodiscard]]
    constexpr auto isIpv6Loopback() const noexcept -> bool {
        if (!isIpv6())
            return false;

        return m_addr.v6.u16[0] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[1] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[2] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[3] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[4] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[5] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[6] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[7] == detail::toNetworkEndian(std::uint16_t{1});
    }

    /// \brief
    ///   Checks if this address is an IPv6 any address. IPv6 any address is \c ::.
    /// \retval true
    ///   This address is an IPv6 any address.
    /// \retval false
    ///   This address is not an IPv6 any address.
    [[nodiscard]]
    constexpr auto isIpv6Any() const noexcept -> bool {
        if (!isIpv6())
            return false;
        return (m_addr.v6.u32[0] == 0) && (m_addr.v6.u32[1] == 0) && (m_addr.v6.u32[2] == 0) &&
               (m_addr.v6.u32[3] == 0);
    }

    /// \brief
    ///   Checks if this address is an IPv6 multicast address. IPv6 multicast address is \c FF00::/8
    ///   as defined in RFC 4291.
    /// \retval true
    ///   This address is an IPv6 multicast address.
    /// \retval false
    ///   This address is not an IPv6 multicast address.
    [[nodiscard]]
    constexpr auto isIpv6Multicast() const noexcept -> bool {
        return isIpv6() && (m_addr.v6.u8[0] == 0xFF);
    }

    /// \brief
    ///   Checks if this address is an IPv4 mapped IPv6 address. IPv4 mapped IPv6 address is
    ///   \c ::FFFF:0:0/96.
    /// \retval true
    ///   This is an IPv4 mapped IPv6 address.
    /// \retval false
    ///   This is not an IPv4 mapped IPv6 address.
    [[nodiscard]]
    constexpr auto isIpv4MappedIpv6() const noexcept -> bool {
        if (!isIpv6())
            return false;

        return m_addr.v6.u16[0] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[1] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[2] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[3] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[4] == detail::toNetworkEndian(std::uint16_t{0}) &&
               m_addr.v6.u16[5] == detail::toNetworkEndian(std::uint16_t{0xFFFF});
    }

    /// \brief
    ///   Converts this IP address to IPv4 address. It is undefined behavior if this is neither an
    ///   IPv4 address nor an IPv4-mapped IPv6 address.
    /// \return
    ///   Return this address if this is an IPv4 or IPv4-mapped IPv6 address.
    [[nodiscard]]
    constexpr auto toIpv4() const noexcept -> IpAddress {
        if (isIpv4())
            return *this;
        return {m_addr.v6.u8[12], m_addr.v6.u8[13], m_addr.v6.u8[14], m_addr.v6.u8[15]};
    }

    /// \brief
    ///   Converts this IP address to IPv6 address.
    /// \return
    ///   Return an IPv4-mapped IPv6 address if this is an IPv4 address. Otherwise, return this IPv6
    ///   address itself.
    [[nodiscard]]
    constexpr auto toIpv6() const noexcept -> IpAddress {
        if (isIpv6())
            return *this;

        IpAddress addr;
        addr.m_isIpv6 = true;

        addr.m_addr.v6.u16[0] = 0;
        addr.m_addr.v6.u16[1] = 0;
        addr.m_addr.v6.u16[2] = 0;
        addr.m_addr.v6.u16[3] = 0;
        addr.m_addr.v6.u16[4] = 0;
        addr.m_addr.v6.u16[5] = 0xFFFF;
        addr.m_addr.v6.u16[6] = m_addr.v4.u16[0];
        addr.m_addr.v6.u16[7] = m_addr.v4.u16[1];

        return addr;
    }

    /// \brief
    ///   Checks if this \c ip_address is the same as another one.
    /// \param other
    ///   The \c ip_address to be compared with.
    /// \retval true
    ///   This \c ip_address is the same as \p other.
    /// \retval false
    ///   This \c ip_address is different from \p other.
    [[nodiscard]]
    constexpr auto operator==(const IpAddress &other) const noexcept -> bool {
        if (m_isIpv6 != other.m_isIpv6)
            return false;

        if (isIpv4())
            return (m_addr.v4.u32[0] == other.m_addr.v4.u32[0]);

        return (m_addr.v6.u32[0] == other.m_addr.v6.u32[0]) &&
               (m_addr.v6.u32[1] == other.m_addr.v6.u32[1]) &&
               (m_addr.v6.u32[2] == other.m_addr.v6.u32[2]) &&
               (m_addr.v6.u32[3] == other.m_addr.v6.u32[3]);
    }

    /// \brief
    ///   Checks if this \c ip_address is different from another one.
    /// \param other
    ///   The \c ip_address to be compared with.
    /// \retval true
    ///   This \c ip_address is different from \p other.
    /// \retval false
    ///   This \c ip_address is the same as \p other.
    [[nodiscard]]
    constexpr auto operator!=(const IpAddress &other) const noexcept -> bool {
        return !(*this == other);
    }

    friend class InetAddress;

private:
    bool m_isIpv6;
    union {
        union {
            std::uint8_t u8[4];
            std::uint16_t u16[2];
            std::uint32_t u32[1];
        } v4;
        union {
            std::uint8_t u8[16];
            std::uint16_t u16[8];
            std::uint32_t u32[4];
        } v6;
    } m_addr;
};

/// \brief
///   IPv4 loopback address.
inline constexpr IpAddress Ipv4Loopback{127, 0, 0, 1};

/// \brief
///   IPv4 any address.
inline constexpr IpAddress Ipv4Any{0, 0, 0, 0};

/// \brief
///   IPv4 broadcast address.
inline constexpr IpAddress Ipv4Broadcast{255, 255, 255, 255};

/// \brief
///   IPv6 loopback address.
inline constexpr IpAddress Ipv6Loopback{0, 0, 0, 0, 0, 0, 0, 1};

/// \brief
///   IPv6 any address.
inline constexpr IpAddress Ipv6Any{0, 0, 0, 0, 0, 0, 0, 0};

/// \class InetAddress
/// \brief
///   Wrapper class for Internet socket address. \c InetAddress is a trivial class. This class
///   could be directly passed as \c sockaddr to system socket API.
class [[nodiscard]] InetAddress {
public:
    /// \brief
    ///   Create an empty Internet socket address. An empty \c InetAddress object is trivially
    ///   initialized with zero and should not be used for network operations.
    constexpr InetAddress() noexcept : m_family{}, m_port{}, m_addr{} {}

    /// \brief
    ///   Create an Internet socket address with IP address and port number.
    /// \param ip
    ///   The IP address of the Internet socket address.
    /// \param port
    ///   The port number of the Internet socket address in host endian.
    constexpr InetAddress(const IpAddress &ip, std::uint16_t port) noexcept
        : m_family{ip.isIpv4() ? detail::SocketAddressFamily::Internet
                               : detail::SocketAddressFamily::Internet6},
          m_port{detail::toNetworkEndian(port)},
          m_addr{} {
        if (ip.isIpv4()) {
            m_addr.v4.address.u32[0] = ip.m_addr.v4.u32[0];
        } else {
            m_addr.v6.address[0] = ip.m_addr.v6.u16[0];
            m_addr.v6.address[1] = ip.m_addr.v6.u16[1];
            m_addr.v6.address[2] = ip.m_addr.v6.u16[2];
            m_addr.v6.address[3] = ip.m_addr.v6.u16[3];
            m_addr.v6.address[4] = ip.m_addr.v6.u16[4];
            m_addr.v6.address[5] = ip.m_addr.v6.u16[5];
            m_addr.v6.address[6] = ip.m_addr.v6.u16[6];
            m_addr.v6.address[7] = ip.m_addr.v6.u16[7];
        }
    }

    /// \brief
    ///   Checks if this is an IPv4 Internet socket address.
    /// \note
    ///   Empty \c InetAddress object may be neither IPv4 nor IPv6.
    /// \retval true
    ///   This is an IPv4 Internet socket address.
    /// \retval false
    ///   This is not an IPv4 Internet socket address.
    [[nodiscard]]
    constexpr auto isIpv4() const noexcept -> bool {
        return m_family == detail::SocketAddressFamily::Internet;
    }

    /// \brief
    ///   Checks if this is an IPv6 Internet socket address.
    /// \note
    ///   Empty \c InetAddress object may be neither IPv4 nor IPv6.
    /// \retval true
    ///   This is an IPv6 Internet socket address.
    /// \retval false
    ///   This is not an IPv6 Internet socket address.
    [[nodiscard]]
    constexpr auto isIpv6() const noexcept -> bool {
        return m_family == detail::SocketAddressFamily::Internet6;
    }

    /// \brief
    ///   Get IP address of this Internet socket address. The return value could be random value if
    ///   this is neither IPv4 nor IPv6.
    /// \return
    ///   The IP address of this Internet socket address.
    [[nodiscard]]
    constexpr auto ip() const noexcept -> IpAddress {
        if (isIpv4()) {
            return {
                m_addr.v4.address.u8[0],
                m_addr.v4.address.u8[1],
                m_addr.v4.address.u8[2],
                m_addr.v4.address.u8[3],
            };
        }

        IpAddress addr;
        addr.m_isIpv6 = true;

        addr.m_addr.v6.u16[0] = m_addr.v6.address[0];
        addr.m_addr.v6.u16[1] = m_addr.v6.address[1];
        addr.m_addr.v6.u16[2] = m_addr.v6.address[2];
        addr.m_addr.v6.u16[3] = m_addr.v6.address[3];
        addr.m_addr.v6.u16[4] = m_addr.v6.address[4];
        addr.m_addr.v6.u16[5] = m_addr.v6.address[5];
        addr.m_addr.v6.u16[6] = m_addr.v6.address[6];
        addr.m_addr.v6.u16[7] = m_addr.v6.address[7];

        return addr;
    }

    /// \brief
    ///   Set IP address of this Internet socket address.
    /// \param ip
    ///   The IP address to be set.
    constexpr auto setIp(const IpAddress &address) noexcept -> void {
        if (address.isIpv4()) {
            m_family                 = detail::SocketAddressFamily::Internet;
            m_addr.v4.address.u32[0] = address.m_addr.v4.u32[0];
        } else {
            m_family             = detail::SocketAddressFamily::Internet6;
            m_addr.v6.address[0] = address.m_addr.v6.u16[0];
            m_addr.v6.address[1] = address.m_addr.v6.u16[1];
            m_addr.v6.address[2] = address.m_addr.v6.u16[2];
            m_addr.v6.address[3] = address.m_addr.v6.u16[3];
            m_addr.v6.address[4] = address.m_addr.v6.u16[4];
            m_addr.v6.address[5] = address.m_addr.v6.u16[5];
            m_addr.v6.address[6] = address.m_addr.v6.u16[6];
            m_addr.v6.address[7] = address.m_addr.v6.u16[7];
        }
    }

    /// \brief
    ///   Get port number of this Internet socket address.
    /// \return
    ///   The port number of this Internet socket address in host endian.
    [[nodiscard]]
    constexpr auto port() const noexcept -> std::uint16_t {
        return detail::toHostEndian(m_port);
    }

    /// \brief
    ///   Set port number of this Internet socket address.
    /// \param port
    ///   The port number to be set in host endian.
    constexpr auto setPort(std::uint16_t port) noexcept -> void {
        m_port = detail::toNetworkEndian(port);
    }

    /// \brief
    ///   Get IPv6 flow information of this Internet socket address. The return value could be
    ///   random value if this is not an IPv6 address.
    /// \return
    ///   The flow information of this Internet socket address in host endian.
    [[nodiscard]]
    constexpr auto flowInfo() const noexcept -> std::uint32_t {
        return m_addr.v6.flowInfo;
    }

    /// \brief
    ///   Set IPv6 flow information of this Internet socket address. Setting flow info for IPv4
    ///   address affects nothing.
    /// \param info
    ///   The flow information to be set in host endian.
    constexpr auto setFlowInfo(std::uint32_t info) noexcept -> void {
        if (!isIpv6())
            return;
        m_addr.v6.flowInfo = info;
    }

    /// \brief
    ///   Get IPv6 scope ID of this Internet socket address. The return value could be random value
    ///   if this is not an IPv6 address.
    /// \return
    ///   The scope ID of this Internet socket address in host endian.
    [[nodiscard]]
    constexpr auto scopeId() const noexcept -> std::uint32_t {
        return m_addr.v6.scopeId;
    }

    /// \brief
    ///   Set IPv6 scope ID of this Internet socket address. Setting scope ID for IPv4 address
    ///   affects nothing.
    /// \param id
    ///   The scope ID to be set in host endian.
    constexpr auto setScopeId(std::uint32_t id) noexcept -> void {
        if (!isIpv6())
            return;
        m_addr.v6.scopeId = id;
    }

    /// \brief
    ///   Checks if this Internet socket address is the same as another one.
    /// \param other
    ///   The Internet socket address to be compared with.
    /// \retval true
    ///   This Internet socket address is the same as \p other.
    /// \retval false
    ///   This Internet socket address is different from \p other.
    [[nodiscard]]
    constexpr auto operator==(const InetAddress &other) const noexcept -> bool {
        if (m_family != other.m_family || m_port != other.m_port)
            return false;

        if (isIpv4())
            return m_addr.v4.address.u32[0] == other.m_addr.v4.address.u32[0];

        return m_addr.v6.address[0] == other.m_addr.v6.address[0] &&
               m_addr.v6.address[1] == other.m_addr.v6.address[1] &&
               m_addr.v6.address[2] == other.m_addr.v6.address[2] &&
               m_addr.v6.address[3] == other.m_addr.v6.address[3] &&
               m_addr.v6.address[4] == other.m_addr.v6.address[4] &&
               m_addr.v6.address[5] == other.m_addr.v6.address[5] &&
               m_addr.v6.address[6] == other.m_addr.v6.address[6] &&
               m_addr.v6.address[7] == other.m_addr.v6.address[7];
    }

    /// \brief
    ///   Checks if this Internet socket address is different from another one.
    /// \param other
    ///   The Internet socket address to be compared with.
    /// \retval true
    ///   This Internet socket address is different from \p other.
    /// \retval false
    ///   This Internet socket address is the same as \p other.
    [[nodiscard]]
    constexpr auto operator!=(const InetAddress &other) const noexcept -> bool {
        return !(*this == other);
    }

private:
    detail::SocketAddressFamily m_family;
    std::uint16_t m_port;
    union {
        struct {
            union {
                std::uint8_t u8[4];
                std::uint16_t u16[2];
                std::uint32_t u32[1];
            } address;
            std::uint8_t zero[8];
        } v4;
        struct {
            std::uint32_t flowInfo;
            std::uint16_t address[8];
            std::uint32_t scopeId;
        } v6;
    } m_addr;
};

} // namespace onion
