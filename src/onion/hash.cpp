#include "onion/hash.hpp"

auto onion::detail::hash(const void *data, std::size_t size) noexcept -> std::size_t {
#if UINTPTR_MAX >= UINT64_MAX
    constexpr std::uint64_t rapid_seed = 0xBDD89AA982704029ULL;
    constexpr std::uint64_t secrets[3] = {0x2D358DCCAA6C78A5ULL, 0x8BB84B93962EACC9ULL, 0x4B33A62ED433D4A3ULL};

    const auto mul = [](std::uint64_t &a, std::uint64_t &b) -> void {
#    if defined(__clang__) || defined(__GNUC__)
        __uint128_t r = static_cast<__uint128_t>(a) * b;

        a = static_cast<std::uint64_t>(r);
        b = static_cast<std::uint64_t>(r >> 64);
#    else
        std::uint64_t x = (a >> 32);
        std::uint64_t y = (a & 0xFFFFFFFFU);
        std::uint64_t z = (b >> 32);
        std::uint64_t w = (b & 0xFFFFFFFFU);

        std::uint64_t m = y * w;
        std::uint64_t n = x * w;
        std::uint64_t p = y * z;
        std::uint64_t q = x * z;

        std::uint64_t v0 = m & 0xFFFFFFFFU;
        std::uint64_t v1 = (n & 0xFFFFFFFFU) + (p & 0xFFFFFFFFU) + (m >> 32);
        std::uint64_t v2 = (n >> 32) + (p >> 32) + (q & 0xFFFFFFFFU);
        std::uint64_t v3 = (q >> 32);

        v2 += (v1 >> 32);
        v3 += (v2 >> 32);

        a = (v1 << 32) | (v0 & 0xFFFFFFFFU);
        b = (v3 << 32) | (v2 & 0xFFFFFFFFU);
#    endif
    };

    const auto mix = [mul](std::uint64_t a, std::uint64_t b) -> std::uint64_t {
        mul(a, b);
        return a ^ b;
    };

    const auto read64 = [](const std::uint8_t *position) -> std::uint64_t {
        std::uint64_t value = 0;
        value |= static_cast<std::uint64_t>(position[0]) << 0;
        value |= static_cast<std::uint64_t>(position[1]) << 8;
        value |= static_cast<std::uint64_t>(position[2]) << 16;
        value |= static_cast<std::uint64_t>(position[3]) << 24;
        value |= static_cast<std::uint64_t>(position[4]) << 32;
        value |= static_cast<std::uint64_t>(position[5]) << 40;
        value |= static_cast<std::uint64_t>(position[6]) << 48;
        value |= static_cast<std::uint64_t>(position[7]) << 56;
        return value;
    };

    const auto read32 = [](const std::uint8_t *position) -> std::uint64_t {
        std::uint64_t value = 0;
        value |= static_cast<std::uint64_t>(position[0]) << 0;
        value |= static_cast<std::uint64_t>(position[1]) << 8;
        value |= static_cast<std::uint64_t>(position[2]) << 16;
        value |= static_cast<std::uint64_t>(position[3]) << 24;
        return value;
    };

    std::uint64_t seed = rapid_seed ^ mix(rapid_seed ^ secrets[0], secrets[1]) ^ size;
    std::uint64_t a    = 0;
    std::uint64_t b    = 0;

    const auto *position = static_cast<const std::uint8_t *>(data);
    if (size <= 16) [[likely]] {
        if (size >= 4) [[likely]] {
            const std::uint8_t *last  = position + size - 4;
            const std::uint64_t delta = ((size & 24) >> (size >> 3));

            a = (read32(position) << 32) | read32(last);
            b = (read32(position + delta) << 32) | read32(last - delta);
        } else if (size > 0) [[likely]] {
            a = (static_cast<std::uint64_t>(position[0]) << 56) |
                (static_cast<std::uint64_t>(position[size >> 1]) << 32) |
                static_cast<std::uint64_t>(position[size - 1]);
        }
    } else {
        std::size_t i = size;

        if (i > 48) {
            std::uint64_t seed1 = seed;
            std::uint64_t seed2 = seed;

            do {
                seed  = mix(read64(position) ^ secrets[0], read64(position + 8) ^ seed);
                seed1 = mix(read64(position + 16) ^ secrets[1], read64(position + 24) ^ seed1);
                seed2 = mix(read64(position + 32) ^ secrets[2], read64(position + 40) ^ seed2);
                position += 48;
                i -= 48;
            } while (i >= 48);

            seed ^= (seed1 ^ seed2);
        }

        if (i > 16) {
            seed = mix(read64(position) ^ secrets[2], read64(position + 8) ^ seed ^ secrets[1]);
            if (i > 32)
                seed = mix(read64(position + 16) ^ secrets[2], read64(position + 24) ^ seed);
        }

        a = read64(position + i - 16);
        b = read64(position + i - 8);
    }

    a ^= secrets[1];
    b ^= seed;

    mul(a, b);
    return mix(a ^ secrets[0] ^ size, b ^ secrets[1]);
#else
    const auto read32 = [](const std::uint8_t *position) -> std::uint32_t {
        std::uint32_t value = 0;
        value |= static_cast<std::uint32_t>(position[0]) << 0;
        value |= static_cast<std::uint32_t>(position[1]) << 8;
        value |= static_cast<std::uint32_t>(position[2]) << 16;
        value |= static_cast<std::uint32_t>(position[3]) << 24;
        return value;
    };

    const auto mix = [](std::uint32_t &a, std::uint32_t &b) -> void {
        std::uint64_t c = a ^ 0x53C5CA59ULL;
        std::uint64_t d = b ^ 0x74743C1BULL;
        std::uint64_t e = c * d;

        a = static_cast<std::uint32_t>(e & 0xFFFFFFFFU);
        b = static_cast<std::uint32_t>(e >> 32);
    };

    const auto   *position = static_cast<const std::uint8_t *>(data);
    std::uint32_t seed     = 0x89AA9827U;
    std::size_t   i        = size;

    auto seed1 = static_cast<std::uint32_t>(size);
    mix(seed, seed1);

    while (i > 8) {
        seed ^= read32(position);
        seed1 ^= read32(position + 4);
        mix(seed, seed1);

        i -= 8;
        position += 8;
    }

    if (i >= 4) {
        seed ^= read32(position);
        seed1 ^= read32(position + i - 4);
    } else if (i != 0) {
        seed ^= (static_cast<std::uint32_t>(position[0]) << 16) | (static_cast<std::uint32_t>(position[i >> 1]) << 8) |
                static_cast<std::uint32_t>(position[i - 1]);
    }

    mix(seed, seed1);
    mix(seed, seed1);

    return seed ^ seed1;
#endif
}

alignas(16) const onion::detail::hash_table_state onion::detail::hash_table_state_empty_group[16] = {
    hash_table_state::sentinel, hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
};
