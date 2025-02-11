#pragma once

#include "error_code.hpp"
#include "io_context.hpp"

#include <bit>
#include <expected>

namespace onion {
namespace detail {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Windows socket handle type.
using socket_t = std::uintptr_t;
#else
/// \brief
///   Unix socket handle type.
using socket_t = int;
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Invalid socket handle value. This is the same as \c INVALID_SOCKET in WinSock.
inline constexpr socket_t InvalidSocket = static_cast<socket_t>(~0);
#else
/// \brief
///   Invalid socket handle value.
inline constexpr socket_t InvalidSocket = -1;
#endif

} // namespace detail

/// \brief
///   Convert an integer value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
template <typename T>
    requires(std::is_integral_v<T> &&
             (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8))
constexpr auto toNetworkEndian(T value) noexcept -> T {
    if constexpr (std::endian::native == std::endian::little) {
        return std::byteswap(value);
    } else {
        return value;
    }
}

/// \brief
///   Convert an integer value from network endian into host endian.
/// \param value
///   The value to be converted into host endian.
/// \return
///   The value converted into host endian.
template <typename T>
    requires(std::is_integral_v<T> &&
             (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8))
constexpr auto toHostEndian(T value) noexcept -> T {
    return toNetworkEndian(value);
}

/// \enum SocketAddressFamily
/// \brief
///   Socket address family. The enum values are the same as system \c AF_* values.
enum class SocketAddressFamily : std::uint16_t {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    Unspecified = 0,
    Unix        = 1,
    Internet    = 2,
    InternetV6  = 23,
#elif defined(__linux) || defined(__linux__)
    Unspecified = 0,
    Unix        = 1,
    Internet    = 2,
    InternetV6  = 10,
#endif
};

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
          m_addr{.v6{.u16{toNetworkEndian(v0), toNetworkEndian(v1), toNetworkEndian(v2),
                          toNetworkEndian(v3), toNetworkEndian(v4), toNetworkEndian(v5),
                          toNetworkEndian(v6), toNetworkEndian(v7)}}} {}

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

        return m_addr.v6.u16[0] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[1] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[2] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[3] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[4] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[5] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[6] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[7] == toNetworkEndian<std::uint16_t>(1);
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

        return m_addr.v6.u16[0] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[1] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[2] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[3] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[4] == toNetworkEndian<std::uint16_t>(0) &&
               m_addr.v6.u16[5] == toNetworkEndian<std::uint16_t>(0xFFFF);
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
    ///   Get string representation of this IP address.
    /// \return
    ///   The string representation of this IP address.
    [[nodiscard]]
    ONION_API auto toString() const noexcept -> std::string;

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
        : m_family{ip.isIpv4() ? SocketAddressFamily::Internet : SocketAddressFamily::InternetV6},
          m_port{toNetworkEndian(port)},
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
    ///   Get address family of this Internet socket address.
    /// \return
    ///   The address family of this Internet socket address.
    [[nodiscard]]
    constexpr auto family() const noexcept -> SocketAddressFamily {
        return m_family;
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
        return m_family == SocketAddressFamily::Internet;
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
        return m_family == SocketAddressFamily::InternetV6;
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
            m_family                 = SocketAddressFamily::Internet;
            m_addr.v4.address.u32[0] = address.m_addr.v4.u32[0];
        } else {
            m_family             = SocketAddressFamily::InternetV6;
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
        return toHostEndian(m_port);
    }

    /// \brief
    ///   Set port number of this Internet socket address.
    /// \param port
    ///   The port number to be set in host endian.
    constexpr auto setPort(std::uint16_t port) noexcept -> void {
        m_port = toNetworkEndian(port);
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
    ///   Get string representation of this Internet socket address.
    /// \return
    ///   The string representation of this Internet socket address.
    [[nodiscard]]
    ONION_API auto toString() const noexcept -> std::string;

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
    SocketAddressFamily m_family;
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

/// \class SendAwaitable
/// \brief
///   Awaitable object for asynchronous socket data sending.
class [[nodiscard]] SendAwaitable {
public:
    /// \brief
    ///   Create a new \c SendAwaitable object for asynchronous data sending.
    /// \param socket
    ///   The socket to send data.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    SendAwaitable(detail::socket_t socket, const void *data, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_data{data},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async send operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data sending and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is sent or failed.
    /// \retval false
    ///   Data sending succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous send operation.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (m_ovlp.error == 0) [[likely]]
            return m_ovlp.bytes;
        return std::unexpected<SystemErrorCode>{m_ovlp.error};
#elif defined(__linux) || defined(__linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
#endif
    }

private:
    detail::Overlapped m_ovlp;
    detail::socket_t m_socket;
    const void *m_data;
    std::uint32_t m_size;
};

/// \class ReceiveAwaitable
/// \brief
///   Awaitable object for asynchronous socket data receiving.
class [[nodiscard]] ReceiveAwaitable {
public:
    /// \brief
    ///   Create a new \c ReceiveAwaitable object for asynchronous data receiving.
    /// \param socket
    ///   The socket to receive data.
    /// \param[out] buffer
    ///   Pointer to start of data buffer.
    /// \param size
    ///   Size in byte of data buffer.
    ReceiveAwaitable(detail::socket_t socket, void *buffer, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_buffer{buffer},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async receive operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data receiving and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is received or failed.
    /// \retval false
    ///   Data receiving succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous receive operation.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (m_ovlp.error == 0) [[likely]]
            return m_ovlp.bytes;
        return std::unexpected<SystemErrorCode>{m_ovlp.error};
#elif defined(__linux) || defined(__linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected<SystemErrorCode>{-m_ovlp.result};
#endif
    }

private:
    detail::Overlapped m_ovlp;
    detail::socket_t m_socket;
    void *m_buffer;
    std::uint32_t m_size;
};

/// \class TcpStream
/// \brief
///   \c TcpStream represents a TCP connection. This class could only be used in workers.
class TcpStream {
public:
    /// \class ConnectAwaitable
    /// \brief
    ///   Awaitable object for asynchronous connection establishment.
    class [[nodiscard]] ConnectAwaitable {
    public:
        /// \brief
        ///   Create a new \c ConnectAwaitable object for asynchronous connection establishment.
        /// \param[in] stream
        ///   The \c TcpStream object to establish connection.
        /// \param address
        ///   The peer address to connect to.
        ConnectAwaitable(TcpStream &stream, const InetAddress &address) noexcept
            : m_ovlp{},
              m_socket{detail::InvalidSocket},
              m_address{&address},
              m_stream{&stream} {}

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
        [[nodiscard]]
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   Prepare for async connect operation and suspend the coroutine.
        /// \tparam T
        ///   Type of promise of current coroutine.
        /// \param coroutine
        ///   Current coroutine handle.
        /// \retval true
        ///   This coroutine should be suspended and resumed later.
        /// \retval false
        ///   This coroutine should not be suspended and should be resumed immediately.
        template <typename T>
        auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
            return this->await_suspend(coroutine.promise());
        }

        /// \brief
        ///   Prepare for asynchronous connection establishment and suspend this coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when connection is established
        ///   or failed.
        /// \retval false
        ///   Connection establishment succeeded or failed immediately and this coroutine should not
        ///   be suspended.
        [[nodiscard]]
        ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

        /// \brief
        ///   Get the result of the asynchronous connect operation.
        /// \return
        ///   Error code of the asynchronous connect operation. The error code is 0 if success.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> SystemErrorCode;

    private:
        detail::Overlapped m_ovlp;
        detail::socket_t m_socket;
        const InetAddress *m_address;
        TcpStream *m_stream;
    };

public:
    /// \brief
    ///   Create an empty \c TcpStream object. Empty \c TcpStream object is not connected to any TCP
    ///   endpoint.
    TcpStream() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   Wrap a raw TCP socket into a \c TcpStream object.
    /// \param socket
    ///   Raw TCP socket handle of the TCP connection.
    /// \param address
    ///   Peer address of the TCP connection.
    TcpStream(detail::socket_t socket, const InetAddress &address) noexcept
        : m_socket{socket},
          m_address{address} {}

    /// \brief
    ///   \c TcpStream is not copyable.
    TcpStream(const TcpStream &other) = delete;

    /// \brief
    ///   Move constructor of \c TcpStream.
    /// \param[inout] other
    ///   The \c TcpStream object to move. The moved \c TcpStream object will be empty.
    TcpStream(TcpStream &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this TCP connection and release resources.
    ONION_API ~TcpStream() noexcept;

    /// \brief
    ///   \c TcpStream is not copyable.
    auto operator=(const TcpStream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c TcpStream.
    /// \param[inout] other
    ///   The \c TcpStream object to move. The moved \c TcpStream object will be empty.
    /// \return
    ///   Reference to this \c TcpStream object.
    ONION_API auto operator=(TcpStream &&other) noexcept -> TcpStream &;

    /// \brief
    ///   Get remote address of the TCP connection. The return value could be random if this
    ///   \c TcpStream object is empty.
    /// \return
    ///   Remote address of this TCP connection.
    [[nodiscard]]
    auto remoteAddress() const noexcept -> const InetAddress & {
        return m_address;
    }

    /// \brief
    ///   Connect to the specified peer address. This method will block current thread until the
    ///   connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c TcpStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    ONION_API auto connect(const InetAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Connect to the specified peer address asynchronously. This method will suspend this
    ///   coroutine until the connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c TcpStream object if failed to establish new
    ///   connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code
    ///   is 0 if success.
    auto connectAsync(const InetAddress &address) noexcept -> ConnectAwaitable {
        return {*this, address};
    }

    /// \brief
    ///   Send data to the peer TCP endpoint. This method will block current thread until the data
    ///   is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    ONION_API auto send(const void *data, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode>;

    /// \brief
    ///   Send data to the peer TCP endpoint. This method will block current thread until the data
    ///   is sent or any error occurs.
    ///
    ///   This method is just an alias of \c send() so that \c TcpStream object could be used as a
    ///   stream type.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    auto write(const void *data, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode> {
        return this->send(data, size);
    }

    /// \brief
    ///   Send data to the peer TCP endpoint asynchronously. This method will suspend this coroutine
    ///   until the data is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    auto sendAsync(const void *data, std::uint32_t size) noexcept -> SendAwaitable {
        return {m_socket, data, size};
    }

    /// \brief
    ///   Send data to the peer TCP endpoint asynchronously. This method will suspend this coroutine
    ///   until the data is sent or any error occurs.
    ///
    ///   This method is just an alias of \c sendAsync() so that \c TcpStream object could be used
    ///   as a stream type.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    auto writeAsync(const void *data, std::uint32_t size) noexcept -> SendAwaitable {
        return this->sendAsync(data, size);
    }

    /// \brief
    ///   Receive data from the peer TCP endpoint. This method will block current thread until the
    ///   data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    ONION_API auto receive(void *buffer, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode>;

    /// \brief
    ///   Receive data from the peer TCP endpoint. This method will block current thread until the
    ///   data is received or any error occurs.
    ///
    ///   This method is just an alias of \c receive() so that \c TcpStream object could be used as
    ///   a stream type.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    auto read(void *buffer, std::uint32_t size) noexcept
        -> std::expected<std::uint32_t, SystemErrorCode> {
        return this->receive(buffer, size);
    }

    /// \brief
    ///   Receive data from the peer TCP endpoint asynchronously. This method will suspend this
    ///   coroutine until the data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    auto receiveAsync(void *buffer, std::uint32_t size) noexcept -> ReceiveAwaitable {
        return {m_socket, buffer, size};
    }

    /// \brief
    ///   Receive data from the peer TCP endpoint asynchronously. This method will suspend this
    ///   coroutine until the data is received or any error occurs.
    ///
    ///   This method is just an alias of \c receiveAsync() so that \c TcpStream object could be
    ///   used as a stream type.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    auto readAsync(void *buffer, std::uint32_t size) noexcept -> ReceiveAwaitable {
        return this->receiveAsync(buffer, size);
    }

    /// \brief
    ///   Enable or disable keep-alive mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable keep-alive mechanism. \c false to disable keep-alive mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setKeepAlive(bool enable) noexcept -> SystemErrorCode;

    /// \brief
    ///   Enable or disable TCP no-delay mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable TCP no-delay mechanism. \c false to disable TCP no-delay mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setNoDelay(bool enable) noexcept -> SystemErrorCode;

    /// \brief
    ///   Set send timeout of this TCP connection.
    /// \tparam Rep
    ///   Type of the duration representation. See C++ reference for more information.
    /// \tparam Period
    ///   Period of the duration. See C++ reference for more information.
    /// \param timeout
    ///   Timeout duration. Use 0 or negative value for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    template <typename Rep, typename Period>
    auto setSendTimeout(std::chrono::duration<Rep, Period> timeout) noexcept -> SystemErrorCode {
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
        milliseconds      = milliseconds < 0 ? 0 : milliseconds;
        return this->setSendTimeout(static_cast<std::uint32_t>(milliseconds));
    }

    /// \brief
    ///   Set receive timeout of this TCP connection.
    /// \tparam Rep
    ///   Type of the duration representation. See C++ reference for more information.
    /// \tparam Period
    ///   Period of the duration. See C++ reference for more information.
    /// \param timeout
    ///   Timeout duration. Use 0 or negative value for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    template <typename Rep, typename Period>
    auto setReceiveTimeout(std::chrono::duration<Rep, Period> timeout) noexcept -> SystemErrorCode {
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
        milliseconds      = milliseconds < 0 ? 0 : milliseconds;
        return this->setReceiveTimeout(static_cast<std::uint32_t>(milliseconds));
    }

    /// \brief
    ///   Close this TCP connection and release all resources. Closing a \c TcpStream object will
    ///   cause errors for pending IO operations. This method does nothing if this is an empty
    ///   \c TcpStream object.
    ONION_API auto close() noexcept -> void;

private:
    /// \brief
    ///   Set send timeout of this TCP connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setSendTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

    /// \brief
    ///   Set receive timeout of this TCP connection.
    /// \param timeout
    ///   Timeout in milliseconds. Use 0 for never timeout.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if
    ///   success.
    ONION_API auto setReceiveTimeout(std::uint32_t timeout) noexcept -> SystemErrorCode;

private:
    detail::socket_t m_socket;
    InetAddress m_address;
};

/// \class TcpListener
/// \brief
///   \c TcpListener represents a TCP connection listener. This class could only be used in workers.
class TcpListener {
public:
    /// \class AcceptAwaitable
    /// \brief
    ///   Awaitable object for asynchronous connection acceptance.
    class [[nodiscard]] AcceptAwaitable {
    public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        /// \brief
        ///   Create a new \c AcceptAwaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The TCP listener socket to accept new connection.
        explicit AcceptAwaitable(detail::socket_t listener) noexcept
            : m_ovlp{},
              m_server{listener},
              m_connection{detail::InvalidSocket},
              m_address{},
              m_padding{} {}
#elif defined(__linux) || defined(__linux__)
        /// \brief
        ///   Create a new \c AcceptAwaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The TCP listener socket to accept new connection.
        explicit AcceptAwaitable(detail::socket_t listener) noexcept
            : m_ovlp{},
              m_server{listener},
              m_addrlen{},
              m_address{} {}
#endif

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
        [[nodiscard]]
        static constexpr auto await_ready() noexcept -> bool {
            return false;
        }

        /// \brief
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \tparam T
        ///   Type of promise of current coroutine.
        /// \param coroutine
        ///   Current coroutine handle.
        /// \retval true
        ///   This coroutine should be suspended and resumed later.
        /// \retval false
        ///   This coroutine should not be suspended and should be resumed immediately.
        template <typename T>
        auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
            return this->await_suspend(coroutine.promise());
        }

        /// \brief
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when a new connection is
        ///   accepted or failed.
        /// \retval false
        ///   Connection accepting succeeded or failed immediately and this coroutine should not be
        ///   suspended.
        [[nodiscard]]
        ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

        /// \brief
        ///   Get the result of the asynchronous accept operation.
        /// \return
        ///   A \c TcpStream object that represents the new accepted TCP connection. Otherwise,
        ///   return a system error code that represents the IO error.
        [[nodiscard]]
        ONION_API auto await_resume() const noexcept -> std::expected<TcpStream, SystemErrorCode>;

    private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        detail::socket_t m_connection;
        InetAddress m_address;

        [[maybe_unused]]
        std::byte m_padding[16];
#elif defined(__linux) || defined(__linux__)
        detail::Overlapped m_ovlp;
        detail::socket_t m_server;
        unsigned int m_addrlen;
        InetAddress m_address;
#endif
    };

public:
    /// \brief
    ///   Create an empty \c TcpListener object. Empty \c TcpListener object is not bound to any TCP
    ///   address and cannot accept any connection.
    TcpListener() noexcept : m_socket{detail::InvalidSocket}, m_address{} {}

    /// \brief
    ///   \c TcpListener is not copyable.
    TcpListener(const TcpListener &other) = delete;

    /// \brief
    ///   Move constructor of \c TcpListener.
    /// \param[inout] other
    ///   The \c TcpListener object to move. The moved \c TcpListener object will be empty.
    TcpListener(TcpListener &&other) noexcept
        : m_socket{other.m_socket},
          m_address{other.m_address} {
        other.m_socket = detail::InvalidSocket;
    }

    /// \brief
    ///   Destroy this TCP listener and release resources.
    ONION_API ~TcpListener() noexcept;

    /// \brief
    ///   \c TcpListener is not copyable.
    auto operator=(const TcpListener &other) = delete;

    /// \brief
    ///   Move assignment operator of \c TcpListener.
    /// \param[inout] other
    ///   The \c TcpListener object to move. The moved \c TcpListener object will be empty.
    /// \return
    ///   Reference to this \c TcpListener object.
    ONION_API auto operator=(TcpListener &&other) noexcept -> TcpListener &;

    /// \brief
    ///   Get local address of this listener. The return value could be random if this \c
    ///   TcpListener object is empty.
    /// \return
    ///   Local address of this listener.
    [[nodiscard]]
    auto localAddress() const noexcept -> const InetAddress & {
        return m_address;
    }

    /// \brief
    ///   Start listening to the specified address. This \c TcpListener object will not be affected
    ///   if failed to bind to the specified address.
    /// \param[in] address
    ///   The address to bind. The address could be either an IPv4 or IPv6 address.
    /// \return
    ///   A system error code object that represents system error. The error code is 0 if this
    ///   operation is succeeded.
    ONION_API auto listen(const InetAddress &address) noexcept -> SystemErrorCode;

    /// \brief
    ///   Accept a new incoming TCP connection. This method will block current thread until a new
    ///   incoming connection is established or any error occurs.
    /// \return
    ///   A \c TcpStream object that represents the new accepted TCP connection. Otherwise, return a
    ///   system error code that represents the IO error.
    [[nodiscard]]
    ONION_API auto accept() const noexcept -> std::expected<TcpStream, SystemErrorCode>;

    /// \brief
    ///   Accept a new incoming TCP connection asynchronously. This method will suspend this
    ///   coroutine until a new incoming connection is established or any error occurs.
    /// \return
    ///   A \c TcpStream object that represents the new accepted TCP connection.
    /// \throws std::system_error
    ///   Thrown if failed to accept new connection.
    auto acceptAsync() const noexcept -> AcceptAwaitable {
        return AcceptAwaitable{m_socket};
    }

    /// \brief
    ///   Stop listening and release all resources. Closing a \c TcpListener object will cause
    ///   errors for pending accept operations. This method does nothing if this is an empty
    ///   \c TcpListener object.
    ONION_API auto close() noexcept -> void;

private:
    detail::socket_t m_socket;
    InetAddress m_address;
};

} // namespace onion
