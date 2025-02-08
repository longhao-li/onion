#include "onion/hash.hpp"

using namespace onion;

/// \brief
///   Read 64-bit integer from \p position.
/// \param position
///   Pointer to read 64-bit integer from.
/// \return
///   64-bit integer read from \p position.
[[nodiscard]]
static constexpr auto read64(const std::uint8_t *position) noexcept -> std::uint64_t {
    return (static_cast<std::uint64_t>(position[0]) << 0) |
           (static_cast<std::uint64_t>(position[1]) << 8) |
           (static_cast<std::uint64_t>(position[2]) << 16) |
           (static_cast<std::uint64_t>(position[3]) << 24) |
           (static_cast<std::uint64_t>(position[4]) << 32) |
           (static_cast<std::uint64_t>(position[5]) << 40) |
           (static_cast<std::uint64_t>(position[6]) << 48) |
           (static_cast<std::uint64_t>(position[7]) << 56);
}

/// \brief
///   Read 32-bit integer from \p position.
/// \param position
///   Pointer to read 32-bit integer from.
/// \return
///   32-bit integer read from \p position.
[[nodiscard]]
static constexpr auto read32(const std::uint8_t *position) noexcept -> std::uint64_t {
    return (static_cast<std::uint64_t>(position[0]) << 0) |
           (static_cast<std::uint64_t>(position[1]) << 8) |
           (static_cast<std::uint64_t>(position[2]) << 16) |
           (static_cast<std::uint64_t>(position[3]) << 24);
}

/// \brief
///   Default hash seed for rapidhash.
inline constexpr std::uint64_t RapidHashSeed = 0xBDD89AA982704029ULL;

/// \brief
///   Default secrets for rapidhash.
inline constexpr std::uint64_t RapidHashSecret[3] = {
    0x2D358DCCAA6C78A5ULL,
    0x8BB84B93962EACC9ULL,
    0x4B33A62ED433D4A3ULL,
};

/// \brief
///   Multiple 64-bit integers using 128-bit multiplication and store the results in \p a and \p b.
/// \param[inout] a
///   First 64-bit integer to multiply.
/// \param[inout] b
///   Second 64-bit integer to multiply.
static constexpr auto rapidHashMultiply(std::uint64_t &a, std::uint64_t &b) noexcept -> void {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    a             = static_cast<std::uint64_t>(r & 0xFFFF'FFFF'FFFF'FFFFULL);
    b             = static_cast<std::uint64_t>(r >> 64);
#else
    std::uint64_t highA = (a >> 32);
    std::uint64_t lowA  = (a & 0xFFFF'FFFFULL);
    std::uint64_t highB = (b >> 32);
    std::uint64_t lowB  = (b & 0xFFFF'FFFFULL);

    std::uint64_t lowR0 = lowA * lowB;
    std::uint64_t lowR1 = lowA * highB; // << 32
    std::uint64_t lowR2 = highA * lowB; // << 32
    std::uint64_t highR = highA * highB;

    std::uint64_t carry = 0;
    if ((lowR0 + (lowR2 << 32)) < lowR0)
        carry += 1;

    std::uint64_t low = lowR0 + (lowR1 << 32) + (lowR2 << 32);
    if (low < (lowR0 + (lowR2 << 32)))
        carry += 1;

    std::uint64_t high = highR + (lowR1 >> 32) + (lowR2 >> 32) + carry;

    a = low;
    b = high;
#endif
}

/// \brief
///   Mix the two 64-bit hash values.
/// \param a
///   First 64-bit hash value.
/// \param b
///   Second 64-bit hash value.
[[nodiscard]]
static constexpr auto rapidHashMix(std::uint64_t a, std::uint64_t b) noexcept -> std::uint64_t {
    rapidHashMultiply(a, b);
    return a ^ b;
}

auto onion::rapidHash(const void *data, std::size_t size) noexcept -> std::uint64_t {
    std::uint64_t seed =
        RapidHashSeed ^ rapidHashMix(RapidHashSeed ^ RapidHashSecret[0], RapidHashSecret[1]) ^ size;

    const auto *p = static_cast<const std::uint8_t *>(data);
    std::uint64_t a, b;

    if (size <= 16) [[likely]] {
        if (size >= 4) [[likely]] {
            const std::uint8_t *last  = p + size - 4;
            const std::uint64_t delta = (size & 24) >> (size >> 3);

            a = (read32(p) << 32) | read32(last);
            b = (read32(p + delta) << 32) | read32(last - delta);
        } else if (size > 0) [[likely]] {
            a = static_cast<std::uint64_t>(p[0]) << 56;
            a |= static_cast<std::uint64_t>(p[size >> 1]) << 32;
            a |= static_cast<std::uint64_t>(p[size - 1]);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        std::size_t i = size;
        if (i > 48) {
            std::uint64_t seed1 = seed;
            std::uint64_t seed2 = seed;

            while (i >= 96) [[likely]] {
                seed  = rapidHashMix(read64(p) ^ RapidHashSecret[0], read64(p + 8) ^ seed);
                seed1 = rapidHashMix(read64(p + 16) ^ RapidHashSecret[1], read64(p + 24) ^ seed1);
                seed2 = rapidHashMix(read64(p + 32) ^ RapidHashSecret[2], read64(p + 40) ^ seed2);
                seed  = rapidHashMix(read64(p + 48) ^ RapidHashSecret[0], read64(p + 56) ^ seed);
                seed1 = rapidHashMix(read64(p + 64) ^ RapidHashSecret[1], read64(p + 72) ^ seed1);
                seed2 = rapidHashMix(read64(p + 80) ^ RapidHashSecret[2], read64(p + 88) ^ seed2);
                p += 96;
                i -= 96;
            }

            if (i >= 48) [[unlikely]] {
                seed  = rapidHashMix(read64(p) ^ RapidHashSecret[0], read64(p + 8) ^ seed);
                seed1 = rapidHashMix(read64(p + 16) ^ RapidHashSecret[1], read64(p + 24) ^ seed1);
                seed2 = rapidHashMix(read64(p + 32) ^ RapidHashSecret[2], read64(p + 40) ^ seed2);

                p += 48;
                i -= 48;
            }

            seed ^= (seed1 ^ seed2);
        }

        if (i > 16) {
            seed = rapidHashMix(read64(p) ^ RapidHashSecret[2],
                                read64(p + 8) ^ seed ^ RapidHashSecret[1]);
            if (i > 32) {
                seed = rapidHashMix(read64(p + 16) ^ RapidHashSecret[2], read64(p + 24) ^ seed);
            }
        }

        a = read64(p + i - 16);
        b = read64(p + i - 8);
    }

    a ^= RapidHashSecret[1];
    b ^= seed;

    rapidHashMultiply(a, b);
    return rapidHashMix(a ^ RapidHashSecret[0] ^ size, b ^ RapidHashSecret[1]);
}
