#pragma once

#include <bit>
#include <cstdint>

namespace onion::detail {

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
inline constexpr socket_t InvalidSocket = ~socket_t{0};
#else
/// \brief
///   Invalid socket handle value.
inline constexpr socket_t InvalidSocket = -1;
#endif

/// \brief
///   Convert a 16-bit value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
[[nodiscard]]
constexpr auto toNetworkEndian(std::uint16_t value) noexcept -> std::uint16_t {
    if constexpr (std::endian::native == std::endian::little) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(value);
#else
        return (value >> 8) | (value << 8);
#endif
    } else {
        return value;
    }
}

/// \brief
///   Convert a 16-bit value from network endian into host endian.
/// \param value
///   The value to be converted into host endian.
/// \return
///   The value converted into host endian.
[[nodiscard]]
constexpr auto toHostEndian(std::uint16_t value) noexcept -> std::uint16_t {
    return toNetworkEndian(value);
}

/// \brief
///   Convert a 32-bit value from host endian into network endian.
/// \param value
///   The value to be converted into network endian.
/// \return
///   The value converted into network endian.
[[nodiscard]]
constexpr auto toNetworkEndian(std::uint32_t value) noexcept -> std::uint32_t {
    if constexpr (std::endian::native == std::endian::little) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(value);
#else
        return (value >> 24) | ((value >> 8) & 0xFF00) | ((value << 8) & 0xFF0000) | (value << 24);
#endif
    } else {
        return value;
    }
}

/// \brief
///   Convert a 32-bit value from network endian into host endian.
/// \param value
///   The value to be converted into host endian.
/// \return
///   The value converted into host endian.
[[nodiscard]]
constexpr auto toHostEndian(std::uint32_t value) noexcept -> std::uint32_t {
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
    Internet6   = 23,
#elif defined(__linux) || defined(__linux__)
    Unspecified = 0,
    Unix        = 1,
    Internet    = 2,
    Internet6   = 10,
#endif
};

} // namespace onion::detail
