#pragma once

#include "io_context.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WS2tcpip.h>
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <netinet/tcp.h>
#    include <sys/un.h>
#endif

#include <algorithm>
#include <bit>
#include <cstring>
#include <expected>
#include <stdexcept>
#include <string>

namespace onion {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Alias type for native socket type on Windows.
using socket_t = SOCKET;

/// \brief
///   Invalid socket value on Windows.
inline constexpr socket_t invalid_socket = INVALID_SOCKET;
#else
/// \brief
///   Alias type for native socket type on *nix.
using socket_t = int;

/// \brief
///   Invalid socket value on *nix.
inline constexpr socket_t invalid_socket = -1;
#endif

/// \brief
///   Convert an integer value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
template <typename T>
    requires(std::is_integral_v<T> && (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8))
constexpr auto to_network_endian(T value) noexcept -> T {
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
    requires(std::is_integral_v<T> && (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8))
constexpr auto to_host_endian(T value) noexcept -> T {
    return to_network_endian(value);
}

/// \class ip_address
/// \brief
///   Represents either an IPv4 or IPv6 address.
class [[nodiscard]] ip_address {
public:
    /// \brief
    ///   Create an empty IP address. An empty IP address is a zero-initialized IPv4 address.
    constexpr ip_address() noexcept = default;

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
    constexpr ip_address(std::uint8_t v0, std::uint8_t v1, std::uint8_t v2, std::uint8_t v3) noexcept
        : m_addr{.u8{v0, v1, v2, v3, 0, 0, 0, 0}} {}

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
    constexpr ip_address(std::uint16_t v0,
                         std::uint16_t v1,
                         std::uint16_t v2,
                         std::uint16_t v3,
                         std::uint16_t v4,
                         std::uint16_t v5,
                         std::uint16_t v6,
                         std::uint16_t v7) noexcept
        : m_ipv6{true},
          m_addr{.u16{to_network_endian(v0), to_network_endian(v1), to_network_endian(v2), to_network_endian(v3),
                      to_network_endian(v4), to_network_endian(v5), to_network_endian(v6), to_network_endian(v7)}} {}

    /// \brief
    ///   Create an IP address from a string.
    /// \param address
    ///   The string representation of the address.
    /// \throws std::invalid_argument
    ///   Thrown if \p address is neither a valid IPv4 nor a valid IPv6 address.
    ip_address(std::string_view address) {
        char buffer[INET6_ADDRSTRLEN + 1];
        if (address.size() >= sizeof(buffer)) [[unlikely]]
            throw std::invalid_argument("Invalid IP address: " + std::string(address));

        // Copy the address into the buffer to make it null-terminated.
        std::ranges::copy(address, buffer);
        buffer[address.size()] = '\0';

        int result = 0;
        if (address.find(':') == std::string_view::npos) {
            result = inet_pton(AF_INET, buffer, &this->m_addr);
        } else {
            result       = inet_pton(AF_INET6, buffer, &this->m_addr);
            this->m_ipv6 = true;
        }

        if (result != 1) [[unlikely]]
            throw std::invalid_argument("Invalid IP address: " + std::string(address));
    }

    /// \brief
    ///   Checks if this is an IPv4 address. An \c ip_address object is either an IPv4 or an IPv6 address.
    /// \retval true
    ///   This is an IPv4 address.
    /// \retval false
    ///   This is an IPv6 address.
    [[nodiscard]] constexpr auto is_ipv4() const noexcept -> bool {
        return !this->m_ipv6;
    }

    /// \brief
    ///   Checks if this is an IPv6 address. An \c ip_address object is either an IPv4 or an IPv6 address.
    /// \retval true
    ///   This is an IPv6 address.
    /// \retval false
    ///   This is an IPv4 address.
    [[nodiscard]] constexpr auto is_ipv6() const noexcept -> bool {
        return this->m_ipv6;
    }

    /// \brief
    ///   Checks if this address is an IPv4 loopback address. IPv4 loopback address is \c 127.0.0.1.
    /// \retval true
    ///   This address is an IPv4 loopback address.
    /// \retval false
    ///   This address is not an IPv4 loopback address.
    [[nodiscard]] constexpr auto is_ipv4_loopback() const noexcept -> bool {
        if (!this->is_ipv4())
            return false;
        return this->m_addr.v4.s_addr == to_network_endian<std::uint32_t>(INADDR_LOOPBACK);
    }

    /// \brief
    ///   Checks if this address is an IPv4 any address. IPv4 any address is \c 0.0.0.0.
    /// \retval true
    ///   This address is an IPv4 any address.
    /// \retval false
    ///   This address is not an IPv4 any address.
    [[nodiscard]] constexpr auto is_ipv4_any() const noexcept -> bool {
        return this->is_ipv4() && (this->m_addr.v4.s_addr == to_network_endian<std::uint32_t>(INADDR_ANY));
    }

    /// \brief
    ///   Checks if this address is an IPv4 broadcast address. IPv4 broadcast address is \c 255.255.255.255.
    /// \retval true
    ///   This address is an IPv4 broadcast address.
    /// \retval false
    ///   This address is not an IPv4 broadcast address.
    [[nodiscard]] constexpr auto is_ipv4_broadcast() const noexcept -> bool {
        return this->is_ipv4() && (this->m_addr.v4.s_addr == to_network_endian<std::uint32_t>(INADDR_BROADCAST));
    }

    /// \brief
    ///   Checks if this address is an IPv4 private address. An IPv4 private network is a network that used for local
    ///   area networks. Private address ranges are defined in RFC 1918 as follows:
    ///   - \c 10.0.0.0/8
    ///   - \c 172.16.0.0/12
    ///   - \c 192.168.0.0/16
    /// \retval true
    ///   This address is an IPv4 private address.
    /// \retval false
    ///   This address is not an IPv4 private address.
    [[nodiscard]] constexpr auto is_ipv4_private() const noexcept -> bool {
        if (!this->is_ipv4())
            return false;

        // 10.0.0.0/8
        if (this->m_addr.u8[0] == 10)
            return true;

        // 172.16.0.0/12
        if (this->m_addr.u8[0] == 172 && (this->m_addr.u8[1] & 0xF0) == 16)
            return true;

        // 192.168.0.0/16
        if (this->m_addr.u8[0] == 192 && this->m_addr.u8[1] == 168)
            return true;

        return false;
    }

    /// \brief
    ///   Checks if this address is an IPv4 link local address. IPv4 link local address is \c 169.254.0.0/16 as defined
    ///   in RFC 3927.
    /// \retval true
    ///   This address is an IPv4 link local address.
    /// \retval false
    ///   This address is not an IPv4 link local address.
    [[nodiscard]] constexpr auto is_ipv4_link_local() const noexcept -> bool {
        return this->is_ipv4() && (this->m_addr.u8[0] == 169) && (this->m_addr.u8[1] == 254);
    }

    /// \brief
    ///   Checks if this address is an IPv4 multicast address. IPv4 multicast address is \c 224.0.0.0/4 as defined in
    ///   RFC 5771.
    /// \retval true
    ///   This address is an IPv4 multicast address.
    /// \retval false
    ///   This address is not an IPv4 multicast address.
    [[nodiscard]] constexpr auto is_ipv4_multicast() const noexcept -> bool {
        return this->is_ipv4() && (this->m_addr.u8[0] & 0xF0) == 224;
    }

    /// \brief
    ///   Checks if this address is an IPv6 loopback address. IPv6 loopback address is \c ::1.
    /// \retval true
    ///   This address is an IPv6 loopback address.
    /// \retval false
    ///   This address is not an IPv6 loopback address.
    [[nodiscard]] constexpr auto is_ipv6_loopback() const noexcept -> bool {
        if (!this->is_ipv6())
            return false;

        return this->m_addr.u16[0] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[1] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[2] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[3] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[4] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[5] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[6] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[7] == to_network_endian<std::uint16_t>(1);
    }

    /// \brief
    ///   Checks if this address is an IPv6 any address. IPv6 any address is \c ::.
    /// \retval true
    ///   This address is an IPv6 any address.
    /// \retval false
    ///   This address is not an IPv6 any address.
    [[nodiscard]] constexpr auto is_ipv6_any() const noexcept -> bool {
        if (!this->is_ipv6())
            return false;

        return (this->m_addr.u32[0] == 0) && (this->m_addr.u32[1] == 0) && (this->m_addr.u32[2] == 0) &&
               (this->m_addr.u32[3] == 0);
    }

    /// \brief
    ///   Checks if this address is an IPv6 multicast address. IPv6 multicast address is \c FF00::/8 as defined in RFC
    ///   4291.
    /// \retval true
    ///   This address is an IPv6 multicast address.
    /// \retval false
    ///   This address is not an IPv6 multicast address.
    [[nodiscard]] constexpr auto is_ipv6_multicast() const noexcept -> bool {
        return this->is_ipv6() && (this->m_addr.u8[0] == 0xFF);
    }

    /// \brief
    ///   Checks if this address is an IPv4 mapped IPv6 address. IPv4 mapped IPv6 address is \c ::FFFF:0:0/96.
    /// \retval true
    ///   This is an IPv4 mapped IPv6 address.
    /// \retval false
    ///   This is not an IPv4 mapped IPv6 address.
    [[nodiscard]] constexpr auto is_ipv4_mapped_ipv6() const noexcept -> bool {
        if (!this->is_ipv6())
            return false;

        return this->m_addr.u16[0] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[1] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[2] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[3] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[4] == to_network_endian<std::uint16_t>(0) &&
               this->m_addr.u16[5] == to_network_endian<std::uint16_t>(0xFFFF);
    }

    /// \brief
    ///   Converts this IP address to IPv4 address. It is undefined behavior if this is neither an IPv4 address nor an
    ///   IPv4-mapped IPv6 address.
    /// \return
    ///   Return this address if this is an IPv4 or IPv4-mapped IPv6 address.
    [[nodiscard]] constexpr auto to_ipv4() const noexcept -> ip_address {
        if (this->is_ipv4())
            return *this;
        return {this->m_addr.u8[12], this->m_addr.u8[13], this->m_addr.u8[14], this->m_addr.u8[15]};
    }

    /// \brief
    ///   Converts this IP address to IPv6 address.
    /// \return
    ///   Return an IPv4-mapped IPv6 address if this is an IPv4 address. Otherwise, return this IPv6 address itself.
    [[nodiscard]] constexpr auto to_ipv6() const noexcept -> ip_address {
        if (this->is_ipv6())
            return *this;

        ip_address address;
        address.m_ipv6 = true;

        address.m_addr.u16[0] = 0;
        address.m_addr.u16[1] = 0;
        address.m_addr.u16[2] = 0;
        address.m_addr.u16[3] = 0;
        address.m_addr.u16[4] = 0;
        address.m_addr.u16[5] = 0xFFFF;
        address.m_addr.u16[6] = m_addr.u16[0];
        address.m_addr.u16[7] = m_addr.u16[1];

        return address;
    }

    /// \brief
    ///   Get string representation of this IP address.
    /// \return
    ///   String representation of this IP address.
    [[nodiscard]] auto to_string() const noexcept -> std::string {
        char buffer[INET6_ADDRSTRLEN + 1]{};
        inet_ntop(this->m_ipv6 ? AF_INET6 : AF_INET, &this->m_addr, buffer, sizeof(buffer));
        return buffer;
    }

    /// \brief
    ///   Checks if this \c ip_address is the same as another one.
    /// \param other
    ///   The \c ip_address to be compared with.
    /// \retval true
    ///   This \c ip_address is the same as \p other.
    /// \retval false
    ///   This \c ip_address is different from \p other.
    [[nodiscard]] constexpr auto operator==(const ip_address &other) const noexcept -> bool {
        if (this->m_ipv6 != other.m_ipv6)
            return false;

        if (!this->m_ipv6)
            return this->m_addr.u32[0] == other.m_addr.u32[0];

        return (this->m_addr.u32[0] == other.m_addr.u32[0]) && (this->m_addr.u32[1] == other.m_addr.u32[1]) &&
               (this->m_addr.u32[2] == other.m_addr.u32[2]) && (this->m_addr.u32[3] == other.m_addr.u32[3]);
    }

    /// \brief
    ///   Checks if this \c ip_address is different from another one.
    /// \param other
    ///   The \c ip_address to be compared with.
    /// \retval true
    ///   This \c ip_address is different from \p other.
    /// \retval false
    ///   This \c ip_address is the same as \p other.
    [[nodiscard]] constexpr auto operator!=(const ip_address &other) const noexcept -> bool {
        return !(*this == other);
    }

    friend class inet_address;

private:
    /// \brief
    ///   A flag that indicates whether this is an IPv6 address.
    bool m_ipv6 = false;

    /// \brief
    ///   IP address storage.
    union {
        in_addr       v4;
        in6_addr      v6;
        std::uint8_t  u8[16];
        std::uint16_t u16[8];
        std::uint32_t u32[4];
    } m_addr{};
};

/// \brief
///   IPv4 loopback address.
inline constexpr ip_address ipv4_loopback{127, 0, 0, 1};

/// \brief
///   IPv4 any address.
inline constexpr ip_address ipv4_any{0, 0, 0, 0};

/// \brief
///   IPv4 broadcast address.
inline constexpr ip_address ipv4_broadcast{255, 255, 255, 255};

/// \brief
///   IPv6 loopback address.
inline constexpr ip_address ipv6_loopback{0, 0, 0, 0, 0, 0, 0, 1};

/// \brief
///   IPv6 any address.
inline constexpr ip_address ipv6_any{0, 0, 0, 0, 0, 0, 0, 0};

/// \class inet_address
/// \brief
///   Wrapper class for Internet socket address. \c inet_address is a trivially-copyable and trivially-destructible
///   class. This class could be directly passed as \c sockaddr to system socket API.
class [[nodiscard]] inet_address {
public:
    /// \brief
    ///   Create an empty Internet socket address. An empty \c inet_address object is trivially initialized with zero
    ///   and should not be used for network operations.
    constexpr inet_address() noexcept = default;

    /// \brief
    ///   Create an Internet socket address with IP address and port number.
    /// \param ip
    ///   The IP address of the Internet socket address.
    /// \param port
    ///   The port number of the Internet socket address in host endian.
    constexpr inet_address(const onion::ip_address &ip, std::uint16_t port) noexcept {
        if (ip.is_ipv4()) {
            this->m_addr.v4.sin_family = AF_INET;
            this->m_addr.v4.sin_port   = to_network_endian(port);
            this->m_addr.v4.sin_addr   = ip.m_addr.v4;
        } else {
            this->m_addr.v6.sin6_family = AF_INET6;
            this->m_addr.v6.sin6_port   = to_network_endian(port);
            this->m_addr.v6.sin6_addr   = ip.m_addr.v6;
        }
    }

    /// \brief
    ///   Get address family of this Internet socket address.
    /// \return
    ///   The address family of this Internet socket address.
    [[nodiscard]] constexpr auto family() const noexcept -> std::uint16_t {
        return this->m_addr.v4.sin_family;
    }

    /// \brief
    ///   Checks if this is an IPv4 Internet socket address.
    /// \note
    ///   Empty \c inet_address object may be neither IPv4 nor IPv6.
    /// \retval true
    ///   This is an IPv4 Internet socket address.
    /// \retval false
    ///   This is not an IPv4 Internet socket address.
    [[nodiscard]] constexpr auto is_ipv4() const noexcept -> bool {
        return this->m_addr.v4.sin_family == AF_INET;
    }

    /// \brief
    ///   Checks if this is an IPv6 Internet socket address.
    /// \note
    ///   Empty \c inet_address object may be neither IPv4 nor IPv6.
    /// \retval true
    ///   This is an IPv6 Internet socket address.
    /// \retval false
    ///   This is not an IPv6 Internet socket address.
    [[nodiscard]] constexpr auto is_ipv6() const noexcept -> bool {
        return this->m_addr.v6.sin6_family == AF_INET6;
    }

    /// \brief
    ///   Get IP address of this Internet socket address. The return value could be random value if this is neither IPv4
    ///   nor IPv6.
    /// \return
    ///   The IP address of this Internet socket address.
    [[nodiscard]] constexpr auto ip_address() const noexcept -> onion::ip_address {
        onion::ip_address address;
        if (this->is_ipv4()) {
            address.m_addr.v4 = this->m_addr.v4.sin_addr;
        } else {
            address.m_ipv6    = true;
            address.m_addr.v6 = this->m_addr.v6.sin6_addr;
        }

        return address;
    }

    /// \brief
    ///   Set IP address of this Internet socket address.
    /// \param ip
    ///   The IP address to be set.
    constexpr auto set_ip_address(const onion::ip_address &address) noexcept -> void {
        if (address.is_ipv4()) {
            this->m_addr.v4.sin_family = AF_INET;
            this->m_addr.v4.sin_addr   = address.m_addr.v4;
            for (auto &byte : this->m_addr.v4.sin_zero)
                byte = 0;
        } else {
            this->m_addr.v6.sin6_family = AF_INET6;
            this->m_addr.v6.sin6_addr   = address.m_addr.v6;
        }
    }

    /// \brief
    ///   Get port number of this Internet socket address.
    /// \return
    ///   The port number of this Internet socket address in host endian.
    [[nodiscard]] constexpr auto port() const noexcept -> std::uint16_t {
        return to_host_endian(this->m_addr.v4.sin_port);
    }

    /// \brief
    ///   Set port number of this Internet socket address.
    /// \param port
    ///   The port number to be set in host endian.
    constexpr auto set_port(std::uint16_t port) noexcept -> void {
        this->m_addr.v4.sin_port = to_network_endian(port);
    }

    /// \brief
    ///   Get IPv6 flow information of this Internet socket address. The return value could be random value if this is
    ///   not an IPv6 address.
    /// \return
    ///   The flow information of this Internet socket address in host endian.
    [[nodiscard]] constexpr auto flowinfo() const noexcept -> std::uint32_t {
        return to_host_endian(this->m_addr.v6.sin6_flowinfo);
    }

    /// \brief
    ///   Set IPv6 flow information of this Internet socket address. Setting flow info for IPv4 address affects nothing.
    /// \param info
    ///   The flow information to be set in host endian.
    constexpr auto set_flowinfo(std::uint32_t info) noexcept -> void {
        if (!this->is_ipv6())
            return;
        this->m_addr.v6.sin6_flowinfo = to_network_endian(info);
    }

    /// \brief
    ///   Get IPv6 scope ID of this Internet socket address. The return value could be random value if this is not an
    ///   IPv6 address.
    /// \return
    ///   The scope ID of this Internet socket address in host endian.
    [[nodiscard]] constexpr auto scope_id() const noexcept -> std::uint32_t {
        return to_host_endian(this->m_addr.v6.sin6_scope_id);
    }

    /// \brief
    ///   Set IPv6 scope ID of this Internet socket address. Setting scope ID for IPv4 address affects nothing.
    /// \param id
    ///   The scope ID to be set in host endian.
    constexpr auto set_scope_id(std::uint32_t id) noexcept -> void {
        if (!this->is_ipv6())
            return;
        this->m_addr.v6.sin6_scope_id = to_network_endian(id);
    }

    /// \brief
    ///   Get string representation of this Internet socket address.
    /// \return
    ///   The string representation of this Internet socket address.
    [[nodiscard]] ONION_API auto to_string() const noexcept -> std::string;

    /// \brief
    ///   Checks if this Internet socket address is the same as another one.
    /// \param other
    ///   The Internet socket address to be compared with.
    /// \retval true
    ///   This Internet socket address is the same as \p other.
    /// \retval false
    ///   This Internet socket address is different from \p other.
    [[nodiscard]] auto operator==(const inet_address &other) const noexcept -> bool {
        if (this->m_addr.v4.sin_family != other.m_addr.v4.sin_family)
            return false;

        if (this->is_ipv4())
            return std::memcmp(&this->m_addr.v4, &other.m_addr.v4, sizeof(sockaddr_in)) == 0;
        return std::memcmp(&this->m_addr.v6, &other.m_addr.v6, sizeof(sockaddr_in6)) == 0;
    }

    /// \brief
    ///   Checks if this Internet socket address is different from another one.
    /// \param other
    ///   The Internet socket address to be compared with.
    /// \retval true
    ///   This Internet socket address is different from \p other.
    /// \retval false
    ///   This Internet socket address is the same as \p other.
    [[nodiscard]] auto operator!=(const inet_address &other) const noexcept -> bool {
        return !(*this == other);
    }

private:
    union {
        sockaddr_in  v4;
        sockaddr_in6 v6;
    } m_addr{};
};

/// \class send_awaitable
/// \brief
///   Awaitable object for asynchronous socket data sending.
class send_awaitable {
public:
    /// \brief
    ///   Create a new \c send_awaitable object for asynchronous data sending.
    /// \param socket
    ///   The socket to send data.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    send_awaitable(socket_t socket, const void *data, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_data{data},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
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
        return this->prepare_overlapped(coroutine.promise());
    }

    /// \brief
    ///   Get the result of the asynchronous send operation.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents the IO error.
    auto await_resume() noexcept -> std::expected<std::uint32_t, std::error_code> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_ovlp.error == ERROR_SUCCESS) [[likely]]
            return this->m_ovlp.bytes;
        return std::unexpected<std::error_code>{std::in_place, this->m_ovlp.error, std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(this->m_ovlp.result);
        return std::unexpected<std::error_code>{std::in_place, -m_ovlp.result, std::system_category()};
#endif
    }

private:
    /// \brief
    ///   Prepare for asynchronous data sending and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is sent or failed.
    /// \retval false
    ///   Data sending succeeded or failed immediately and this coroutine should not be suspended.
    ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

private:
    overlapped_t  m_ovlp;
    socket_t      m_socket;
    const void   *m_data;
    std::uint32_t m_size;
};

/// \class receive_awaitable
/// \brief
///   Awaitable object for asynchronous socket data receiving.
class receive_awaitable {
public:
    /// \brief
    ///   Create a new \c receive_awaitable object for asynchronous data receiving.
    /// \param socket
    ///   The socket to receive data.
    /// \param[out] buffer
    ///   Pointer to start of data buffer.
    /// \param size
    ///   Size in byte of data buffer.
    receive_awaitable(socket_t socket, void *buffer, std::uint32_t size) noexcept
        : m_ovlp{},
          m_socket{socket},
          m_buffer{buffer},
          m_size{size} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
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
        return this->prepare_overlapped(coroutine.promise());
    }

    /// \brief
    ///   Get the result of the asynchronous receive operation.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that represents the IO error.
    auto await_resume() noexcept -> std::expected<std::uint32_t, std::error_code> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_ovlp.error == ERROR_SUCCESS) [[likely]]
            return this->m_ovlp.bytes;
        return std::unexpected<std::error_code>{std::in_place, this->m_ovlp.error, std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(this->m_ovlp.result);
        return std::unexpected<std::error_code>{std::in_place, -m_ovlp.result, std::system_category()};
#endif
    }

private:
    /// \brief
    ///   Prepare for asynchronous data receiving and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when data is received or failed.
    /// \retval false
    ///   Data receiving succeeded or failed immediately and this coroutine should not be suspended.
    ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

private:
    overlapped_t  m_ovlp;
    socket_t      m_socket;
    void         *m_buffer;
    std::uint32_t m_size;
};

/// \enum shutdown_option
/// \brief
///   Shutdown options for connection-oriented socket.
enum class shutdown_option : std::uint8_t {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    receive = SD_RECEIVE,
    send    = SD_SEND,
    both    = SD_BOTH,
#else
    receive = SHUT_RD,
    send    = SHUT_WR,
    both    = SHUT_RDWR,
#endif
};

/// \class tcp_stream
/// \brief
///   \c tcp_stream represents a TCP connection. This class could only be used in \c io_contexts.
class tcp_stream {
public:
    /// \class connect_awaitable
    /// \brief
    ///   Awaitable object for asynchronous connection establishment.
    class connect_awaitable {
    public:
        /// \brief
        ///   Create a new \c connect_awaitable object for asynchronous connection establishment.
        /// \param[in] stream
        ///   The \c tcp_stream object to establish connection.
        /// \param address
        ///   The peer address to connect to.
        connect_awaitable(tcp_stream &stream, const inet_address &address) noexcept
            : m_ovlp{},
              m_socket{invalid_socket},
              m_address{&address},
              m_stream{&stream} {}

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
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
            return this->prepare_overlapped(coroutine.promise());
        }

        /// \brief
        ///   Get the result of the asynchronous connect operation.
        /// \return
        ///   Error code of the asynchronous connect operation. The error code is 0 if success.
        ONION_API auto await_resume() noexcept -> std::error_code;

    private:
        /// \brief
        ///   Prepare for asynchronous connection establishment and suspend this coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when connection is established or failed.
        /// \retval false
        ///   Connection establishment succeeded or failed immediately and this coroutine should not be suspended.
        ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

    private:
        overlapped_t        m_ovlp;
        socket_t            m_socket;
        const inet_address *m_address;
        tcp_stream         *m_stream;
    };

    /// \brief
    ///   Create an empty \c tcp_stream object. Empty \c tcp_stream object is not connected to any TCP endpoint.
    tcp_stream() noexcept = default;

    /// \brief
    ///   For internal usage. Wrap a raw TCP socket into a \c tcp_stream object.
    /// \param socket
    ///   Raw TCP socket handle of the TCP connection.
    /// \param address
    ///   Peer address of the TCP connection.
    tcp_stream(socket_t socket, const inet_address &address) noexcept : m_socket{socket}, m_address{address} {}

    /// \brief
    ///   \c tcp_stream is not copyable.
    tcp_stream(const tcp_stream &other) = delete;

    /// \brief
    ///   Move constructor of \c tcp_stream.
    /// \param[inout] other
    ///   The \c tcp_stream object to move. The moved \c tcp_stream object will be empty.
    tcp_stream(tcp_stream &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = invalid_socket;
    }

    /// \brief
    ///   Destroy this TCP connection and release resources.
    ~tcp_stream() noexcept {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket)
            closesocket(this->m_socket);
#else
        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);
#endif
    }

    /// \brief
    ///   \c tcp_stream is not copyable.
    auto operator=(const tcp_stream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c tcp_stream.
    /// \param[inout] other
    ///   The \c tcp_stream object to move. The moved \c tcp_stream object will be empty.
    /// \return
    ///   Reference to this \c tcp_stream object.
    auto operator=(tcp_stream &&other) noexcept -> tcp_stream & {
        if (this == &other) [[unlikely]]
            return *this;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket)
            closesocket(this->m_socket);
#else
        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);
#endif

        this->m_socket  = other.m_socket;
        this->m_address = other.m_address;
        other.m_socket  = invalid_socket;

        return *this;
    }

    /// \brief
    ///   Get peer address of the TCP connection. The return value could be random if this \c tcp_stream object is
    ///   empty.
    /// \return
    ///   Peer address of this TCP connection.
    [[nodiscard]] auto peer_address() const noexcept -> const inet_address & {
        return this->m_address;
    }

    /// \brief
    ///   Connect to the specified peer address asynchronously. This method will suspend this coroutine until the
    ///   connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c tcp_stream object if failed to establish new connection.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code is 0 if success.
    auto connect(const inet_address &address) noexcept -> connect_awaitable {
        return {*this, address};
    }

    /// \brief
    ///   Send data to the peer TCP endpoint asynchronously. This method will suspend this coroutine until the data is
    ///   sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents the IO error.
    auto send(const void *data, std::uint32_t size) const noexcept -> send_awaitable {
        return {this->m_socket, data, size};
    }

    /// \brief
    ///   Receive data from the peer TCP endpoint asynchronously. This method will suspend this coroutine until the data
    ///   is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that represents the IO error.
    auto receive(void *buffer, std::uint32_t size) const noexcept -> receive_awaitable {
        return {this->m_socket, buffer, size};
    }

    /// \brief
    ///   Enable or disable keep-alive mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable keep-alive mechanism. \c false to disable keep-alive mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if success.
    auto set_keepalive(bool enable) noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        DWORD value  = enable ? 1 : 0;
        auto *optval = reinterpret_cast<const CHAR *>(&value);

        if (setsockopt(this->m_socket, SOL_SOCKET, SO_KEEPALIVE, optval, sizeof(value)) == 0) [[likely]]
            return {};
        return {WSAGetLastError(), std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        const int value = enable ? 1 : 0;
        if (setsockopt(this->m_socket, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) == 0) [[likely]]
            return {};
        return {errno, std::system_category()};
#endif
    }

    /// \brief
    ///   Enable or disable TCP no-delay mechanism of this TCP connection.
    /// \param enable
    ///   \c true to enable TCP no-delay mechanism. \c false to disable TCP no-delay mechanism.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if success.
    auto set_nodelay(bool enable) noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        DWORD value  = enable ? 1 : 0;
        auto *optval = reinterpret_cast<const CHAR *>(&value);

        if (setsockopt(this->m_socket, IPPROTO_TCP, TCP_NODELAY, optval, sizeof(value)) == 0) [[likely]]
            return {};
        return {WSAGetLastError(), std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        const int value = enable ? 1 : 0;
        if (setsockopt(this->m_socket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == 0) [[likely]]
            return {};
        return {errno, std::system_category()};
#endif
    }

    /// \brief
    ///   Shutdown this TCP connection.
    /// \param option
    ///   The shutdown option that specifies how to shutdown this TCP connection. TCP is a full-duplex protocol, so
    ///   it is OK to shutdown send and receive operations separately.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if success.
    auto shutdown(shutdown_option option) noexcept -> std::error_code {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (::shutdown(m_socket, static_cast<int>(option)) == 0) [[likely]]
            return {};
        return {WSAGetLastError(), std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (::shutdown(m_socket, static_cast<int>(option)) == 0) [[likely]]
            return {};
        return {errno, std::system_category()};
#endif
    }

    /// \brief
    ///   Close this TCP connection and release all resources. Closing a \c tcp_stream object will cause errors for
    ///   pending IO operations. This method does nothing if this is an empty \c tcp_stream object.
    auto close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket) {
            closesocket(this->m_socket);
            this->m_socket = invalid_socket;
        }
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (this->m_socket != invalid_socket) {
            ::close(this->m_socket);
            this->m_socket = invalid_socket;
        }
#endif
    }

    /// \brief
    ///   Checks if this \c tcp_stream object is connected to a TCP endpoint.
    /// \retval true
    ///   This \c tcp_stream object is connected to a TCP endpoint.
    /// \retval false
    ///   This \c tcp_stream object is not connected to any TCP endpoint.
    explicit operator bool() const noexcept {
        return this->m_socket != invalid_socket;
    }

private:
    socket_t     m_socket  = invalid_socket;
    inet_address m_address = {};
};

/// \class tcp_listener
/// \brief
///   \c tcp_listener represents a TCP connection listener. This class could only be used in \c io_contexts.
class tcp_listener {
public:
    /// \class accept_awaitable
    /// \brief
    ///   Awaitable object for asynchronous connection acceptance.
    class accept_awaitable {
    public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        /// \brief
        ///   Create a new \c accept_awaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The TCP listener socket to accept new connection.
        explicit accept_awaitable(socket_t listener) noexcept
            : m_ovlp{},
              m_listener{listener},
              m_stream{invalid_socket},
              m_address{} {}
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        /// \brief
        ///   Create a new \c accept_awaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The TCP listener socket to accept new connection.
        explicit accept_awaitable(socket_t listener) noexcept
            : m_ovlp{},
              m_listener{listener},
              m_addrlen{sizeof(inet_address)},
              m_address{} {}
#endif

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
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
            return this->prepare_overlapped(coroutine.promise());
        }

        /// \brief
        ///   Get the result of the asynchronous accept operation.
        /// \return
        ///   A \c tcp_stream object that represents the new accepted TCP connection. Otherwise, return a system error
        ///   code that represents the IO error.
        auto await_resume() noexcept -> std::expected<tcp_stream, std::error_code> {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
            if (this->m_ovlp.error == ERROR_SUCCESS) [[likely]]
                return tcp_stream{this->m_stream, this->m_address};

            if (this->m_stream != invalid_socket)
                closesocket(this->m_stream);
            return std::unexpected<std::error_code>{std::in_place, this->m_ovlp.error, std::system_category()};
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
            if (this->m_ovlp.result >= 0) [[likely]]
                return tcp_stream{this->m_ovlp.result, this->m_address};
            return std::unexpected<std::error_code>{std::in_place, -this->m_ovlp.result, std::system_category()};
#endif
        }

    private:
        /// \brief
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when a new connection is
        ///   accepted or failed.
        /// \retval false
        ///   Connection accepting succeeded or failed immediately and this coroutine should not be suspended.
        ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

    private:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        overlapped_t m_ovlp;
        socket_t     m_listener;
        socket_t     m_stream;
        inet_address m_address;
        std::byte    m_padding[16];
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        overlapped_t m_ovlp;
        socket_t     m_listener;
        socklen_t    m_addrlen;
        inet_address m_address;
#endif
    };

    /// \brief
    ///   Create an empty \c tcp_listener object. Empty \c tcp_listener object is not bound to any TCP address and
    ///   cannot accept any connection.
    tcp_listener() noexcept = default;

    /// \brief
    ///   Create a new \c tcp_listener object and listen to the specified address.
    /// \param address
    ///   The address to bind. The address could be either an IPv4 or IPv6 address.
    /// \throws std::system_error
    ///   Thrown if failed to listen to the specified address.
    ONION_API explicit tcp_listener(const inet_address &address);

    /// \brief
    ///   \c tcp_listener is not copyable.
    tcp_listener(const tcp_listener &other) = delete;

    /// \brief
    ///   Move constructor of \c tcp_listener.
    /// \param[inout] other
    ///   The \c tcp_listener object to move. The moved \c tcp_listener object will be empty.
    tcp_listener(tcp_listener &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = invalid_socket;
    }

    /// \brief
    ///   Destroy this TCP listener and release resources.
    ~tcp_listener() noexcept {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket)
            closesocket(this->m_socket);
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);
#endif
    }

    /// \brief
    ///   \c tcp_listener is not copyable.
    auto operator=(const tcp_listener &other) = delete;

    /// \brief
    ///   Move assignment operator of \c tcp_listener.
    /// \param[inout] other
    ///   The \c tcp_listener object to move. The moved \c tcp_listener object will be empty.
    /// \return
    ///   Reference to this \c tcp_listener object.
    auto operator=(tcp_listener &&other) noexcept -> tcp_listener & {
        if (this == &other) [[unlikely]]
            return *this;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket)
            closesocket(this->m_socket);
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);
#endif

        this->m_socket  = other.m_socket;
        this->m_address = other.m_address;
        other.m_socket  = invalid_socket;

        return *this;
    }

    /// \brief
    ///   Get local address of this listener. The return value could be random if this \c tcp_listener object is empty.
    /// \return
    ///   Local address of this listener.
    [[nodiscard]] auto local_address() const noexcept -> const inet_address & {
        return this->m_address;
    }

    /// \brief
    ///   Start listening to the specified address. This \c tcp_listener object will not be affected if failed to bind
    ///   to the specified address.
    /// \param[in] address
    ///   The address to bind. The address could be either an IPv4 or IPv6 address.
    /// \return
    ///   A system error code object that represents system error. The error code is 0 if this operation is succeeded.
    ONION_API auto listen(const inet_address &address) noexcept -> std::error_code;

    /// \brief
    ///   Accept a new incoming TCP connection asynchronously. This method will suspend this coroutine until a new
    ///   incoming connection is established or any error occurs.
    /// \return
    ///   A \c tcp_listener object that represents the new accepted TCP connection. Otherwise, return a system error
    ///   code that represents system IO error.
    auto accept() const noexcept -> accept_awaitable {
        return accept_awaitable{this->m_socket};
    }

    /// \brief
    ///   Stop listening and release all resources. Closing a \c tcp_listener object will cause errors for pending
    ///   accept operations. This method does nothing if this is an empty \c tcp_listener object.
    auto close() noexcept -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        if (this->m_socket != invalid_socket) {
            closesocket(this->m_socket);
            this->m_socket = invalid_socket;
        }
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        if (this->m_socket != invalid_socket) {
            ::close(m_socket);
            this->m_socket = invalid_socket;
        }
#endif
    }

    /// \brief
    ///   Checks if this \c tcp_listener object is listening to a TCP address.
    /// \retval true
    ///   This \c tcp_listener object is listening to a TCP address.
    /// \retval false
    ///   This \c tcp_listener object is not listening to any TCP address.
    explicit operator bool() const noexcept {
        return m_socket != invalid_socket;
    }

private:
    socket_t     m_socket  = invalid_socket;
    inet_address m_address = {};
};

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
/// \class unix_stream
/// \brief
///   \c unix_stream represents a Unix domain socket connection. This class could only be used in \c io_contexts.
class unix_stream {
public:
    /// \class connect_awaitable
    /// \brief
    ///   Awaitable object for asynchronous connection establishment.
    class connect_awaitable {
    public:
        /// \brief
        ///   Create a new \c connect_awaitable object for asynchronous connection establishment.
        /// \param[in] stream
        ///   The \c unix_stream object to establish connection.
        /// \param address
        ///   The peer address to connect to.
        connect_awaitable(unix_stream &stream, std::string_view address) noexcept
            : m_ovlp{},
              m_socket{invalid_socket},
              m_stream{&stream} {
            // Return invalid argument if address is too long.
            if (address.size() >= sizeof(this->m_address.sun_path)) [[unlikely]]
                this->m_ovlp.result = -EINVAL;

            this->m_address.sun_family = AF_UNIX;
            std::ranges::copy(address, this->m_address.sun_path);
            this->m_address.sun_path[address.size()] = '\0';
        }

        /// \brief
        ///   C++20 coroutine API method. Checks if path is too long.
        /// \return
        ///   Return \c false if the specified unix domain socket path is valid. Otherwise, return \c true.
        [[nodiscard]] auto await_ready() const noexcept -> bool {
            return this->m_ovlp.result != 0;
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
            return this->prepare_overlapped(coroutine.promise());
        }

        /// \brief
        ///   Get the result of the asynchronous connect operation.
        /// \return
        ///   Error code of the asynchronous connect operation. The error code is 0 if success.
        ONION_API auto await_resume() noexcept -> std::error_code;

    private:
        /// \brief
        ///   Prepare for asynchronous connection establishment and suspend this coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when connection is established or failed.
        /// \retval false
        ///   Connection establishment succeeded or failed immediately and this coroutine should not be suspended.
        ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

    private:
        overlapped_t m_ovlp;
        socket_t     m_socket;
        sockaddr_un  m_address;
        unix_stream *m_stream;
    };

    /// \brief
    ///   Create an empty \c unix_stream object. Empty \c unix_stream object is not connected to any Unix domain socket.
    unix_stream() noexcept = default;

    /// \brief
    ///   For internal usage. Wrap a raw Unix domain socket into a \c unix_stream object.
    /// \param socket
    ///   Raw Unix domain socket handle of the Unix domain connection.
    /// \param address
    ///   Peer address of the Unix domain connection.
    unix_stream(socket_t socket, const sockaddr_un &address) noexcept : m_socket{socket}, m_address{address} {}

    /// \brief
    ///   \c unix_stream is not copyable.
    unix_stream(const unix_stream &other) = delete;

    /// \brief
    ///   Move constructor of \c unix_stream.
    /// \param[inout] other
    ///   The \c unix_stream object to move. The moved \c unix_stream object will be empty.
    unix_stream(unix_stream &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = invalid_socket;
    }

    /// \brief
    ///   Destroy this Unix domain connection and release resources.
    ~unix_stream() noexcept {
        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);
    }

    /// \brief
    ///   \c unix_stream is not copyable.
    auto operator=(const unix_stream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c unix_stream.
    /// \param[inout] other
    ///   The \c unix_stream object to move. The moved \c unix_stream object will be empty.
    /// \return
    ///   Reference to this \c unix_stream object.
    auto operator=(unix_stream &&other) noexcept -> unix_stream & {
        if (this == &other) [[unlikely]]
            return *this;

        if (this->m_socket != invalid_socket)
            ::close(this->m_socket);

        this->m_socket  = other.m_socket;
        this->m_address = other.m_address;
        other.m_socket  = invalid_socket;

        return *this;
    }

    /// \brief
    ///   Get peer address of this Unix domain connection. The return value is empty string if this \c unix_stream
    ///   object is empty.
    /// \note
    ///   This method will calculate the string length of the peer address every time it is called which may hurt
    ///   performance if called too frequently.
    /// \return
    ///   Peer address of this Unix domain connection.
    [[nodiscard]] auto peer_address() const noexcept -> std::string_view {
        return this->m_address.sun_path;
    }

    /// \brief
    ///   Connect to the specified peer address asynchronously. This method will suspend this coroutine until the
    ///   connection is established or any error occurs.
    /// \remarks
    ///   This method does not affect this \c unix_stream object if failed to establish new connection. \c EINVAL will
    ///   be returned if \p path is too long.
    /// \param address
    ///   The peer address to connect.
    /// \return
    ///   A system error code that indicates the result of the connection operation. The error code is 0 if success.
    auto connect(std::string_view address) noexcept -> connect_awaitable {
        return {*this, address};
    }

    /// \brief
    ///   Send data to the peer Unix domain socket asynchronously. This method will suspend this coroutine until the
    ///   data is sent or any error occurs.
    /// \param data
    ///   Pointer to start of data to send.
    /// \param size
    ///   Size in byte of data to send.
    /// \return
    ///   Number of bytes sent if succeeded. Otherwise, return a system error code that represents the IO error.
    auto send(const void *data, std::uint32_t size) const noexcept -> send_awaitable {
        return {this->m_socket, data, size};
    }

    /// \brief
    ///   Receive data from the peer Unix domain socket asynchronously. This method will suspend this coroutine until
    ///   the data is received or any error occurs.
    /// \param[out] buffer
    ///   Pointer to start of buffer to receive data.
    /// \param size
    ///   Size in byte of buffer to store the received data.
    /// \return
    ///   Number of bytes received if succeeded. Otherwise, return a system error code that represents the IO error.
    auto receive(void *buffer, std::uint32_t size) const noexcept -> receive_awaitable {
        return {this->m_socket, buffer, size};
    }

    /// \brief
    ///   Shutdown this Unix domain connection.
    /// \param option
    ///   The shutdown option that specifies how to shutdown this Unix domain connection. Unix domain socket is a
    ///   full-duplex protocol, so it is OK to shutdown send and receive operations separately.
    /// \return
    ///   A system error code that indicates the result of the operation. The error code is 0 if success.
    auto shutdown(shutdown_option option) noexcept -> std::error_code {
        if (::shutdown(m_socket, static_cast<int>(option)) == 0) [[likely]]
            return {};
        return {errno, std::system_category()};
    }

    /// \brief
    ///   Close this Unix domain connection and release all resources. Closing a \c unix_stream object will cause errors
    ///   for pending IO operations. This method does nothing if this is an empty \c unix_stream object.
    auto close() noexcept -> void {
        if (this->m_socket != invalid_socket) {
            ::close(this->m_socket);
            this->m_socket = invalid_socket;
        }
    }

    /// \brief
    ///   Checks if this \c unix_stream object is connected to a Unix domain socket.
    /// \retval true
    ///   This \c unix_stream object is connected to a Unix domain socket.
    /// \retval false
    ///   This \c unix_stream object is not connected to any Unix domain socket.
    explicit operator bool() const noexcept {
        return this->m_socket != invalid_socket;
    }

private:
    socket_t    m_socket  = invalid_socket;
    sockaddr_un m_address = {.sun_family = AF_UNIX, .sun_path = {}};
};

/// \class unix_listener
/// \brief
///   \c unix_listener represents a Unix domain socket listener. This class could only be used in \c io_contexts.
class unix_listener {
public:
    /// \class accept_awaitable
    /// \brief
    ///   Awaitable object for asynchronous connection acceptance.
    class accept_awaitable {
    public:
        /// \brief
        ///   Create a new \c accept_awaitable object for asynchronous connection acceptance.
        /// \param listener
        ///   The Unix domain socket listener to accept new connection.
        explicit accept_awaitable(socket_t listener) noexcept
            : m_ovlp{},
              m_listener{listener},
              m_addrlen{sizeof(sockaddr_un)},
              m_address{.sun_family = AF_UNIX, .sun_path = {}} {}

        /// \brief
        ///   C++20 coroutine API method. Always execute \c await_suspend().
        /// \return
        ///   This function always returns \c false.
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
            return this->prepare_overlapped(coroutine.promise());
        }

        /// \brief
        ///   Get the result of the asynchronous accept operation.
        /// \return
        ///   A \c unix_stream object that represents the new accepted Unix domain connection. Otherwise, return a
        ///   system error code that represents the IO error.
        auto await_resume() noexcept -> std::expected<unix_stream, std::error_code> {
            if (this->m_ovlp.result >= 0) [[likely]]
                return unix_stream{this->m_ovlp.result, this->m_address};
            return std::unexpected<std::error_code>{std::in_place, -this->m_ovlp.result, std::system_category()};
        }

    private:
        /// \brief
        ///   Prepare for async accept operation and suspend the coroutine.
        /// \param[in] promise
        ///   Promise of current coroutine.
        /// \retval true
        ///   This coroutine should be suspended and be resumed later when a new connection is
        ///   accepted or failed.
        /// \retval false
        ///   Connection accepting succeeded or failed immediately and this coroutine should not be suspended.
        ONION_API auto prepare_overlapped(promise_base &promise) noexcept -> bool;

    private:
        overlapped_t m_ovlp;
        socket_t     m_listener;
        socklen_t    m_addrlen;
        sockaddr_un  m_address;
    };

    /// \brief
    ///   Create an empty \c unix_listener object. Empty \c unix_listener object is not bound to any Unix domain socket
    ///   address and cannot accept any connection.
    unix_listener() noexcept = default;

    /// \brief
    ///   Create a new \c unix_listener object and listen to the specified address.
    /// \param address
    ///   The address to bind. The address could be either an IPv4 or IPv6 address.
    /// \throws std::system_error
    ///   Thrown if failed to listen to the specified address.
    /// \throws std::invalid_argument
    ///   Thrown if \p path is too long.
    ONION_API explicit unix_listener(std::string_view path);

    /// \brief
    ///   \c unix_listener is not copyable.
    unix_listener(const unix_listener &other) = delete;

    /// \brief
    ///   Move constructor of \c unix_listener.
    /// \param[inout] other
    ///   The \c unix_listener object to move. The moved \c unix_listener object will be empty.
    unix_listener(unix_listener &&other) noexcept : m_socket{other.m_socket}, m_address{other.m_address} {
        other.m_socket = invalid_socket;
    }

    /// \brief
    ///   Destroy this Unix domain listener and release resources.
    ~unix_listener() noexcept {
        if (this->m_socket != invalid_socket) {
            ::close(this->m_socket);
            ::unlink(this->m_address.sun_path);
        }
    }

    /// \brief
    ///   \c unix_listener is not copyable.
    auto operator=(const unix_listener &other) = delete;

    /// \brief
    ///   Move assignment operator of \c unix_listener.
    /// \param[inout] other
    ///   The \c unix_listener object to move. The moved \c unix_listener object will be empty.
    /// \return
    ///   Reference to this \c unix_listener object.
    auto operator=(unix_listener &&other) noexcept -> unix_listener & {
        if (this == &other) [[unlikely]]
            return *this;

        if (this->m_socket != invalid_socket) {
            ::close(this->m_socket);
            ::unlink(this->m_address.sun_path);
        }

        this->m_socket  = other.m_socket;
        this->m_address = other.m_address;
        other.m_socket  = invalid_socket;

        return *this;
    }

    /// \brief
    ///   Get local address of this listener. The return value could be random if this \c unix_listener object is empty.
    /// \note
    ///   This method will calculate the string length of the local address every time it is called which may hurt
    ///   performance if called too frequently.
    /// \return
    ///   Local address of this listener.
    [[nodiscard]] auto local_address() const noexcept -> std::string_view {
        return this->m_address.sun_path;
    }

    /// \brief
    ///   Start listening to the specified address. This \c unix_listener object will not be affected if failed to bind
    ///   to the specified address.
    /// \param[in] address
    ///   The path to bind. The path could be any valid Unix domain socket path.
    /// \return
    ///   A system error code object that represents system error. The error code is 0 if this operation is succeeded.
    ONION_API auto listen(std::string_view address) noexcept -> std::error_code;

    /// \brief
    ///   Accept a new incoming Unix domain connection asynchronously. This method will suspend this coroutine until a
    ///   new incoming connection is established or any error occurs.
    /// \return
    ///   A \c unix_stream object that represents the new accepted Unix domain connection. Otherwise, return a system
    ///   error code that represents system IO error.
    auto accept() const noexcept -> accept_awaitable {
        return accept_awaitable{this->m_socket};
    }

    /// \brief
    ///   Stop listening and release all resources. Closing a \c unix_listener object will cause errors for pending
    ///   accept operations. This method does nothing if this is an empty \c unix_listener object.
    auto close() noexcept -> void {
        if (this->m_socket != invalid_socket) {
            ::close(this->m_socket);
            ::unlink(this->m_address.sun_path);
            this->m_socket = invalid_socket;
        }
    }

    /// \brief
    ///   Checks if this \c unix_listener object is listening to a Unix domain socket address.
    /// \retval true
    ///   This \c unix_listener object is listening to a Unix domain socket address.
    /// \retval false
    ///   This \c unix_listener object is not listening to any Unix domain socket address.
    explicit operator bool() const noexcept {
        return this->m_socket != invalid_socket;
    }

private:
    socket_t    m_socket  = invalid_socket;
    sockaddr_un m_address = {.sun_family = AF_UNIX, .sun_path = {}};
};
#endif

} // namespace onion
