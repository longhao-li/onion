#include "onion/hash.hpp"

using namespace onion;
using namespace onion::detail;
using namespace onion::detail::hash;

auto onion::hash(const void *data, std::size_t size) noexcept -> std::size_t {
#if defined(SIZE_MAX) && (SIZE_MAX >= UINT64_MAX)
    constexpr std::uint64_t RapidHashSeed = 0xBDD89AA982704029ULL;

    constexpr std::uint64_t RapidHashSecret[3] = {
        0x2D358DCCAA6C78A5ULL,
        0x8BB84B93962EACC9ULL,
        0x4B33A62ED433D4A3ULL,
    };

    std::uint64_t seed = RapidHashSeed ^ 0xCBEB9F1265CEE51FULL ^ size;

    const auto *p = static_cast<const std::uint8_t *>(data);
    std::uint64_t a, b;
    __uint128_t temp, temp1, temp2;

    if (size <= 16) [[likely]] {
        if (size >= 4) [[likely]] {
            const std::uint8_t *last  = p + size - 4;
            const std::uint64_t delta = (size & 24) >> (size >> 3);

            a = (static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t *>(p)) << 32) |
                static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t *>(last));
            b = (static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t *>(p + delta))
                 << 32) |
                static_cast<std::uint64_t>(*reinterpret_cast<const std::uint32_t *>(last - delta));
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
                temp = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p) ^
                                                RapidHashSecret[0]) *
                       static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 8) ^
                                                seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 16) ^
                                                 RapidHashSecret[1]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 24) ^
                                                 seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 32) ^
                                                 RapidHashSecret[2]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 40) ^
                                                 seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                temp = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 48) ^
                                                RapidHashSecret[0]) *
                       static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 56) ^
                                                seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 64) ^
                                                 RapidHashSecret[1]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 72) ^
                                                 seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 80) ^
                                                 RapidHashSecret[2]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 88) ^
                                                 seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                p += 96;
                i -= 96;
            }

            if (i >= 48) [[unlikely]] {
                temp = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p) ^
                                                RapidHashSecret[0]) *
                       static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 8) ^
                                                seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 16) ^
                                                 RapidHashSecret[1]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 24) ^
                                                 seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 32) ^
                                                 RapidHashSecret[2]) *
                        static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 40) ^
                                                 seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                p += 48;
                i -= 48;
            }

            seed ^= (seed1 ^ seed2);
        }

        if (i > 16) {
            temp = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p) ^
                                            RapidHashSecret[2]) *
                   static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 8) ^ seed ^
                                            RapidHashSecret[1]);
            seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));
            if (i > 32) {
                temp = static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 16) ^
                                                RapidHashSecret[2]) *
                       static_cast<__uint128_t>(*reinterpret_cast<const std::uint64_t *>(p + 24) ^
                                                seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));
            }
        }

        a = *reinterpret_cast<const std::uint64_t *>(p + i - 16);
        b = *reinterpret_cast<const std::uint64_t *>(p + i - 8);
    }

    a ^= RapidHashSecret[1];
    b ^= seed;

    temp = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    a    = static_cast<std::uint64_t>(temp & 0xFFFF'FFFF'FFFF'FFFFULL);
    b    = static_cast<std::uint64_t>(temp >> 64);

    temp = static_cast<__uint128_t>(a ^ RapidHashSecret[0] ^ size) *
           static_cast<__uint128_t>(b ^ RapidHashSecret[1]);
    return static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));
#else
#    error "32-bit platform is not supported yet."
#endif
}

alignas(16) constexpr const ControlFlag onion::detail::hash::EmptyGroup[32] = {
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Sentinel, ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
};
