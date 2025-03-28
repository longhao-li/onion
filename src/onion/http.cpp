#include "onion/http.hpp"

/// \brief
///   Case insensitive char map. Map upper-case characters to lower-case characters.
static constexpr std::uint8_t case_insensitive_map[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,
    22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,
    44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  97,
    98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
    132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
    154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
    198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
    220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241,
    242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
};

auto onion::detail::case_insensitive_hash::operator()(std::string_view key) const noexcept -> std::size_t {
    const void *data = key.data();
    std::size_t size = key.size();

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
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[0]]) << 0;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[1]]) << 8;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[2]]) << 16;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[3]]) << 24;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[4]]) << 32;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[5]]) << 40;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[6]]) << 48;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[7]]) << 56;
        return value;
    };

    const auto read32 = [](const std::uint8_t *position) -> std::uint64_t {
        std::uint64_t value = 0;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[0]]) << 0;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[1]]) << 8;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[2]]) << 16;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[3]]) << 24;
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
            a = (static_cast<std::uint64_t>(case_insensitive_map[position[0]]) << 56) |
                (static_cast<std::uint64_t>(case_insensitive_map[position[size >> 1]]) << 32) |
                static_cast<std::uint64_t>(case_insensitive_map[position[size - 1]]);
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
    const auto read32 = [](const std::uint8_t *position) -> std::uint64_t {
        std::uint64_t value = 0;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[0]]) << 0;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[1]]) << 8;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[2]]) << 16;
        value |= static_cast<std::uint64_t>(case_insensitive_map[position[3]]) << 24;
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
        seed ^= (static_cast<std::uint32_t>(case_insensitive_map[position[0]]) << 16) |
                (static_cast<std::uint32_t>(case_insensitive_map[position[i >> 1]]) << 8) |
                static_cast<std::uint32_t>(case_insensitive_map[position[i - 1]]);
    }

    mix(seed, seed1);
    mix(seed, seed1);

    return seed ^ seed1;
#endif
}

auto onion::detail::case_insensitive_equal::operator()(std::string_view lhs, std::string_view rhs) const noexcept
    -> bool {
    if (lhs.size() != rhs.size())
        return false;

    for (auto i = lhs.begin(), j = rhs.begin(); i != lhs.end(); ++i, ++j) {
        if (case_insensitive_map[static_cast<std::uint8_t>(*i)] != case_insensitive_map[static_cast<std::uint8_t>(*j)])
            return false;
    }

    return true;
}

auto onion::http_header_map::add(std::string_view name, std::string_view value) noexcept -> void {
    auto result = this->m_headers.try_emplace(name, value);
    if (result.second)
        return;

    auto &existing = result.first->second;
    if (existing.empty()) [[unlikely]] {
        existing = value;
    } else {
        existing.append(", ");
        existing.append(value);
    }
}

auto onion::http_header_map::content_length() const noexcept -> std::optional<std::uint64_t> {
    auto iter = this->m_headers.find("Content-Length");
    if (iter == this->m_headers.end())
        return std::nullopt;

    std::uint64_t value = 0;
    for (char c : iter->second) {
        if (c < '0' || c > '9')
            return std::nullopt;
        value = value * 10 + (c - '0');
    }

    return value;
}

auto onion::http_header_map::set_content_length(std::uint64_t value) noexcept -> void {
    char        buffer[32];
    std::size_t length = 0;

    do {
        buffer[length++] = '0' + (value % 10);
        value /= 10;
    } while (value != 0);
    std::reverse(buffer, buffer + length);

    this->m_headers.insert_or_assign("Content-Length", std::string_view{buffer, length});
}

auto onion::http_header_map::date() const noexcept -> std::optional<std::chrono::system_clock::time_point> {
    auto iter = this->m_headers.find("Date");
    if (iter == this->m_headers.end())
        return std::nullopt;

    std::string_view value = iter->second;
    if (value.size() < 29) [[unlikely]]
        return std::nullopt;

    // Parse day.
    std::uint16_t day = (value[5] - '0') * 10 + (value[6] - '0');
    if (day < 1 || day > 31) [[unlikely]]
        return std::nullopt;

    // Parse month.
    std::uint16_t month = 0;
    switch (value[8]) {
    case 'J':
        switch (value[9]) {
        case 'a': month = 1; break;
        case 'u':
            switch (value[10]) {
            case 'n': month = 6; break;
            case 'l': month = 7; break;
            default:  return std::nullopt;
            }
            break;
        default: return std::nullopt;
        }
        break;
    case 'F': month = 2; break;
    case 'M':
        switch (value[10]) {
        case 'r': month = 3; break;
        case 'y': month = 5; break;
        default:  return std::nullopt;
        }
        break;
    case 'A':
        switch (value[9]) {
        case 'p': month = 4; break;
        case 'u': month = 8; break;
        default:  return std::nullopt;
        }
        break;
    case 'S': month = 9; break;
    case 'O': month = 10; break;
    case 'N': month = 11; break;
    case 'D': month = 12; break;
    default:  return std::nullopt;
    }

    // Parse year.
    std::uint16_t year =
        (value[12] - '0') * 1000 + (value[13] - '0') * 100 + (value[14] - '0') * 10 + (value[15] - '0');
    if (year < 1900) [[unlikely]]
        return std::nullopt;

    // Parse hour.
    std::uint16_t hour = (value[17] - '0') * 10 + (value[18] - '0');
    if (hour > 23) [[unlikely]]
        return std::nullopt;

    // Parse minute.
    std::uint16_t minute = (value[20] - '0') * 10 + (value[21] - '0');
    if (minute > 59) [[unlikely]]
        return std::nullopt;

    // Parse second.
    std::uint16_t second = (value[23] - '0') * 10 + (value[24] - '0');
    if (second > 59) [[unlikely]]
        return std::nullopt;

    // GMT.
    if (value[25] != ' ' || value[26] != 'G' || value[27] != 'M' || value[28] != 'T') [[unlikely]]
        return std::nullopt;

    std::chrono::year_month_day ymd{std::chrono::year{year}, std::chrono::month{month}, std::chrono::day{day}};
    return std::chrono::sys_days{ymd} + std::chrono::hours{hour} + std::chrono::minutes{minute} +
           std::chrono::seconds{second};
}

auto onion::http_header_map::set_date(std::chrono::system_clock::time_point value) noexcept -> void {
    std::time_t time = std::chrono::system_clock::to_time_t(value);
    struct tm   tm;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    ::gmtime_s(&tm, &time);
#else
    ::gmtime_r(&time, &tm);
#endif

    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &tm);

    this->m_headers.insert_or_assign("Date", std::string_view{buffer, 29});
}
