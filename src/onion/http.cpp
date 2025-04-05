#include "onion/http.hpp"

#include <llhttp.h>

#include <array>

using namespace std::string_literals;

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

auto onion::http_header_map::set_authorization(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Authorization", value);
}

auto onion::http_header_map::set_cache_control(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Cache-Control", value);
}

auto onion::http_header_map::set_connection(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Connection", value);
}

auto onion::http_header_map::set_content_encoding(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Content-Encoding", value);
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

auto onion::http_header_map::set_content_type(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Content-Type", value);
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
    constexpr std::string_view weekdays[7] = {
        "Sun,", "Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,",
    };

    constexpr std::string_view months[12] = {
        "Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec ",
    };

    std::time_t time = std::chrono::system_clock::to_time_t(value);
    struct tm   tm;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    ::gmtime_s(&tm, &time);
#else
    ::gmtime_r(&time, &tm);
#endif

    tm.tm_year += 1900;
    char buffer[30];

    buffer[0]  = weekdays[tm.tm_wday][0];
    buffer[1]  = weekdays[tm.tm_wday][1];
    buffer[2]  = weekdays[tm.tm_wday][2];
    buffer[3]  = weekdays[tm.tm_wday][3];
    buffer[4]  = ' ';
    buffer[5]  = '0' + static_cast<char>(tm.tm_mday / 10);
    buffer[6]  = '0' + static_cast<char>(tm.tm_mday % 10);
    buffer[7]  = ' ';
    buffer[8]  = months[tm.tm_mon][0];
    buffer[9]  = months[tm.tm_mon][1];
    buffer[10] = months[tm.tm_mon][2];
    buffer[11] = months[tm.tm_mon][3];
    buffer[12] = '0' + static_cast<char>(tm.tm_year / 1000);
    buffer[13] = '0' + static_cast<char>((tm.tm_year / 100) % 10);
    buffer[14] = '0' + static_cast<char>((tm.tm_year / 10) % 10);
    buffer[15] = '0' + static_cast<char>(tm.tm_year % 10);
    buffer[16] = ' ';
    buffer[17] = '0' + static_cast<char>(tm.tm_hour / 10);
    buffer[18] = '0' + static_cast<char>(tm.tm_hour % 10);
    buffer[19] = ':';
    buffer[20] = '0' + static_cast<char>(tm.tm_min / 10);
    buffer[21] = '0' + static_cast<char>(tm.tm_min % 10);
    buffer[22] = ':';
    buffer[23] = '0' + static_cast<char>(tm.tm_sec / 10);
    buffer[24] = '0' + static_cast<char>(tm.tm_sec % 10);
    buffer[25] = ' ';
    buffer[26] = 'G';
    buffer[27] = 'M';
    buffer[28] = 'T';

    this->m_headers.insert_or_assign("Date", std::string_view{buffer, 29});
}

auto onion::http_header_map::expires() const noexcept -> std::optional<std::chrono::system_clock::time_point> {
    auto iter = this->m_headers.find("Expires");
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

auto onion::http_header_map::set_expires(std::chrono::system_clock::time_point value) noexcept -> void {
    constexpr std::string_view weekdays[7] = {
        "Sun,", "Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,",
    };

    constexpr std::string_view months[12] = {
        "Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec ",
    };

    std::time_t time = std::chrono::system_clock::to_time_t(value);
    struct tm   tm;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    ::gmtime_s(&tm, &time);
#else
    ::gmtime_r(&time, &tm);
#endif

    tm.tm_year += 1900;
    char buffer[30];

    buffer[0]  = weekdays[tm.tm_wday][0];
    buffer[1]  = weekdays[tm.tm_wday][1];
    buffer[2]  = weekdays[tm.tm_wday][2];
    buffer[3]  = weekdays[tm.tm_wday][3];
    buffer[4]  = ' ';
    buffer[5]  = '0' + static_cast<char>(tm.tm_mday / 10);
    buffer[6]  = '0' + static_cast<char>(tm.tm_mday % 10);
    buffer[7]  = ' ';
    buffer[8]  = months[tm.tm_mon][0];
    buffer[9]  = months[tm.tm_mon][1];
    buffer[10] = months[tm.tm_mon][2];
    buffer[11] = months[tm.tm_mon][3];
    buffer[12] = '0' + static_cast<char>(tm.tm_year / 1000);
    buffer[13] = '0' + static_cast<char>((tm.tm_year / 100) % 10);
    buffer[14] = '0' + static_cast<char>((tm.tm_year / 10) % 10);
    buffer[15] = '0' + static_cast<char>(tm.tm_year % 10);
    buffer[16] = ' ';
    buffer[17] = '0' + static_cast<char>(tm.tm_hour / 10);
    buffer[18] = '0' + static_cast<char>(tm.tm_hour % 10);
    buffer[19] = ':';
    buffer[20] = '0' + static_cast<char>(tm.tm_min / 10);
    buffer[21] = '0' + static_cast<char>(tm.tm_min % 10);
    buffer[22] = ':';
    buffer[23] = '0' + static_cast<char>(tm.tm_sec / 10);
    buffer[24] = '0' + static_cast<char>(tm.tm_sec % 10);
    buffer[25] = ' ';
    buffer[26] = 'G';
    buffer[27] = 'M';
    buffer[28] = 'T';

    this->m_headers.insert_or_assign("Expires", std::string_view{buffer, 29});
}

auto onion::http_header_map::set_keep_alive(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Keep-Alive", value);
}

auto onion::http_header_map::set_transfer_encoding(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Transfer-Encoding", value);
}

auto onion::http_header_map::set_host(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Host", value);
}

auto onion::http_header_map::set_user_agent(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("User-Agent", value);
}

auto onion::http_header_map::set_referer(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Referer", value);
}

auto onion::http_header_map::set_upgrade(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Upgrade", value);
}

auto onion::http_header_map::set_location(std::string_view value) noexcept -> void {
    this->m_headers.insert_or_assign("Location", value);
}

namespace {

/// \class http_path_walker
/// \brief
///   Helper class that is used to walk through HTTP path components.
class http_path_walker {
public:
    class iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = std::string_view;
        using reference         = std::string_view;
        using difference_type   = std::ptrdiff_t;

        /// \brief
        ///   Construct a new iterator from a string view.
        /// \param string
        ///   The string view to iterate over.
        explicit iterator(std::string_view string) noexcept
            : m_first{string.begin()},
              m_last{string.begin()},
              m_end{string.end()} {
            while (this->m_last != this->m_end && *this->m_last == '/')
                ++this->m_last;
            this->m_first = this->m_last;

            while (this->m_last != this->m_end && *this->m_last != '/')
                ++this->m_last;
        }

        /// \brief
        ///   Construct a new iterator from iterators.
        /// \param first
        ///   The first iterator.
        /// \param last
        ///   The last iterator.
        /// \param end
        ///   The end iterator.
        iterator(typename std::string_view::const_iterator first,
                 typename std::string_view::const_iterator last,
                 typename std::string_view::const_iterator end) noexcept
            : m_first{first},
              m_last{last},
              m_end{end} {}

        /// \brief
        ///   Dereference this iterator.
        /// \return
        ///   A reference to the current component.
        [[nodiscard]] auto operator*() const noexcept -> reference {
            return {m_first, m_last};
        }

        /// \brief
        ///   Pre-increment this iterator.
        /// \return
        ///   Reference to this iterator.
        auto operator++() noexcept -> iterator & {
            while (this->m_last != this->m_end && *this->m_last == '/')
                ++this->m_last;
            this->m_first = this->m_last;

            while (this->m_last != this->m_end && *this->m_last != '/')
                ++this->m_last;

            return *this;
        }

        /// \brief
        ///   Move to the next path component.
        /// \return
        ///   Copy of this iterator before moving to the next component.
        auto operator++(int) noexcept -> iterator {
            auto temp = *this;
            ++(*this);
            return temp;
        }

        /// \brief
        ///   Checks if the two iterators are equal.
        /// \param lhs
        ///   The left hand side iterator.
        /// \param rhs
        ///   The right hand side iterator.
        /// \retval true
        ///   The two iterators are equal.
        /// \retval false
        ///   The two iterators are not equal.
        [[nodiscard]] friend auto operator==(const iterator &lhs, const iterator &rhs) noexcept -> bool {
            return lhs.m_first == rhs.m_first;
        }

        /// \brief
        ///   Checks if the two iterators are not equal.
        /// \param lhs
        ///   The left hand side iterator.
        /// \param rhs
        ///   The right hand side iterator.
        /// \retval true
        ///   The two iterators are not equal.
        /// \retval false
        ///   The two iterators are equal.
        [[nodiscard]] friend auto operator!=(const iterator &lhs, const iterator &rhs) noexcept -> bool {
            return !(lhs == rhs);
        }

    private:
        typename std::string_view::const_iterator m_first;
        typename std::string_view::const_iterator m_last;
        typename std::string_view::const_iterator m_end;
    };

    using const_iterator = iterator;

    /// \brief
    ///   Create a new path walker from a string view.
    /// \param string
    ///   The string view to walk over.
    explicit http_path_walker(std::string_view string) noexcept : m_string{string} {}

    /// \brief
    ///   Get iterator to the first path component in the string view.
    /// \return
    ///   Iterator to the first path component.
    [[nodiscard]] auto begin() const noexcept -> iterator {
        return iterator{this->m_string};
    }

    /// \brief
    ///   Get iterator to the place after the last path component in the string view.
    /// \return
    ///   Iterator to the place after the last path component.
    [[nodiscard]] auto end() const noexcept -> iterator {
        return iterator{this->m_string.end(), this->m_string.end(), this->m_string.end()};
    }

private:
    std::string_view m_string;
};

} // namespace

auto onion::http_router::map(std::string_view path, std::function<task<>(http_context &)> handler) noexcept -> void {
    radix_node *current = &this->m_root;

    http_path_walker walker{path};
    for (std::string_view component : walker) {
        if (component.starts_with(':')) {
            if (current->match_any == nullptr)
                current->match_any = std::make_unique<radix_node>();
            current = current->match_any.get();
        } else {
            auto result = current->next.try_emplace(component);
            current     = std::addressof(result.first->second);
        }
    }

    current->pattern = path;
    current->handler = std::move(handler);
}

auto onion::http_router::match(http_context &context) const noexcept -> task<> {
    struct recurse_state {
        const radix_node                   *node;
        bool                                match_exact;
        bool                                match_any;
        typename http_path_walker::iterator iterator;
    };

    std::vector<recurse_state> stack;
    stack.reserve(16);

    http_path_walker walker{context.request.path};
    stack.push_back({&this->m_root, false, false, {walker.begin()}});

    for (auto iter = walker.begin(); iter != walker.end() && !stack.empty();) {
        auto &state = stack.back();
        if (!state.match_exact) {
            state.match_exact = true;

            auto &next = state.node->next;
            if (auto result = next.find(*iter); result != next.end()) {
                stack.push_back({
                    .node        = &result->second,
                    .match_exact = false,
                    .match_any   = false,
                    .iterator    = iter,
                });

                ++iter;
                continue;
            }
        }

        if (!state.match_any) {
            state.match_any = true;
            if (state.node->match_any != nullptr) {
                stack.push_back({
                    .node        = state.node->match_any.get(),
                    .match_exact = false,
                    .match_any   = false,
                    .iterator    = iter,
                });

                ++iter;
                continue;
            }
        }

        // Nothing to match.
        iter = stack.back().iterator;
        stack.pop_back();
    }

    if (!stack.empty()) {
        const radix_node *node = stack.back().node;
        if (node->handler == nullptr)
            return nullptr;

        // Clear params before parsing.
        context.request.params.clear();

        // Parse wildcard parameters.
        walker = http_path_walker{node->pattern};
        auto i = walker.begin();
        auto j = stack.begin() + 1;

        for (; i != walker.end() && j != stack.end(); ++i, ++j) {
            std::string_view pattern = *i;
            if (pattern.starts_with(':'))
                context.request.params.try_emplace(pattern.substr(1), *j->iterator);
        }

        return node->handler(context);
    }

    return nullptr;
}

onion::http_server::~http_server() noexcept {
    // Destroy services.
    for (auto &kv : this->m_services)
        kv.second.destroy(kv.second.object);

    // Destroy IO context pool if necessary.
    if (this->m_own_context)
        delete this->m_context;
}

auto onion::http_server::run() -> void {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    if (this->m_context == nullptr) {
        this->m_context     = new io_context_pool;
        this->m_own_context = true;
    }

    const auto acceptor = [this](auto listener) -> task<> {
        while (true) {
            // FIXME: Write a log message if the listener fails to accept a connection.
            auto result = co_await listener.accept();
            if (!result.has_value()) [[unlikely]]
                continue;

            co_await schedule(this->handle_connection(std::move(*result)));
        }
    };

    // FIXME: Pass exception outside thread-pool.
    const auto server = [this, &acceptor]() -> task<> {
        switch (this->m_kind) {
        case stream_kind::tcp_stream: {
            tcp_listener listener;

            std::error_code error = listener.listen(this->m_address.inet);
            if (error) [[unlikely]]
                throw std::system_error{error, "Failed to listen on address " + this->m_address.inet.to_string()};

            co_await schedule(acceptor(std::move(listener)));
            break;
        }

        [[unlikely]] default:
            throw std::runtime_error{"Listening address not set."};
        }

        co_return;
    };

    this->m_context->dispatch(server);
    this->m_context->run();
#elif defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    if (this->m_context == nullptr) {
        this->m_context     = new io_context_pool;
        this->m_own_context = true;
    }

    const auto acceptor = [this](auto &listener) -> task<> {
        while (true) {
            // FIXME: Write a log message if the listener fails to accept a connection.
            auto result = co_await listener.accept();
            if (!result.has_value()) [[unlikely]]
                continue;

            co_await schedule(this->handle_connection(std::move(*result)));
        }
    };

    switch (this->m_kind) {
    case stream_kind::tcp_stream: {
        tcp_listener listener;

        std::error_code error = listener.listen(this->m_address.inet);
        if (error) [[unlikely]]
            throw std::system_error{error, "Failed to listen on address " + this->m_address.inet.to_string()};

        this->m_context->dispatch(acceptor, listener);
        this->m_context->run();
        break;
    }

    case stream_kind::unix_stream: {
        unix_listener   listener;
        std::error_code error = listener.listen(this->m_address.unix_socket.sun_path);
        if (error) [[unlikely]]
            throw std::system_error{error, "Failed to listen on address "s + this->m_address.unix_socket.sun_path};

        this->m_context->dispatch(acceptor, listener);
        this->m_context->run();
        break;
    }

    [[unlikely]] default:
        throw std::runtime_error{"Listening address not set."};
    }
#endif
}

namespace {

/// \enum http_parser_error
/// \brief
///   HTTP parser internal error codes.
enum http_parser_error {
    http_parser_error_ok,
    http_parser_error_done,
    http_parser_error_method_not_allowed,
    http_parser_error_bad_request,
    http_parser_error_version_not_supported,
};

/// \struct http_parser_state
/// \brief
///   State of the HTTP parser.
struct http_parser_state {
    http_parser_error    error;
    std::string          key_buffer;
    std::string          value_buffer;
    onion::http_request &request;
};

/// \brief
///   Callback function for HTTP parser that is called when the parser start to parse a new HTTP request.
/// \param parser
///   The llhttp parser instance.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_message_begin(llhttp_t *parser) noexcept -> int {
    auto *state  = static_cast<http_parser_state *>(parser->data);
    state->error = http_parser_error_ok;
    state->key_buffer.clear();
    state->value_buffer.clear();
    state->request.clear();
    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser.
/// \param parser
///   The llhttp parser instance.
/// \param at
///   The current position in the buffer.
/// \param length
///   The length of the data to parse.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_url(llhttp_t *parser, const char *at, std::size_t length) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);

    std::size_t origin_size = state->value_buffer.size();
    state->value_buffer.resize(origin_size + length);

    char *position = state->value_buffer.data() + origin_size;

    // Convert '+' to ' '.
    const __m128i plus = _mm_set1_epi8('+');
    while (length >= 16) {
        const __m128i value  = _mm_loadu_si128(reinterpret_cast<const __m128i *>(at));
        const __m128i cmp    = _mm_cmpeq_epi8(value, plus);
        const __m128i mask   = _mm_and_si128(cmp, _mm_set1_epi8(0x0B));
        const __m128i result = _mm_xor_si128(mask, value);
        _mm_storeu_si128(reinterpret_cast<__m128i *>(position), result);

        at += 16;
        position += 16;
        length -= 16;
    }

    for (; length != 0; --length) {
        char c      = *at++;
        *position++ = (c == '+' ? ' ' : c);
    }

    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request header field.
/// \param parser
///   The llhttp parser instance.
/// \param at
///   The current position in the buffer.
/// \param length
///   The length of the data to parse.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_header_field(llhttp_t *parser, const char *at, std::size_t length) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);
    state->key_buffer.append(at, length);
    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request header value.
/// \param parser
///   The llhttp parser instance.
/// \param at
///   The current position in the buffer.
/// \param length
///   The length of the data to parse.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_header_value(llhttp_t *parser, const char *at, std::size_t length) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);
    state->value_buffer.append(at, length);
    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request body.
/// \param parser
///   The llhttp parser instance.
/// \param at
///   The current position in the buffer.
/// \param length
///   The length of the data to parse.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_body(llhttp_t *parser, const char *at, std::size_t length) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);
    state->request.body.append(at, length);
    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser that is called when the message is complete.
/// \param parser
///   The llhttp parser instance.
/// \return
///   This function always returns \c HPE_PAUSED to tell the caller to handle current HTTP request.
auto http_parser_on_message_complete(llhttp_t *parser) noexcept -> int {
    auto *state  = static_cast<http_parser_state *>(parser->data);
    state->error = http_parser_error_done;
    return HPE_PAUSED;
}

/// \brief
///   Unescape a hexadecimal character.
/// \param c
///   The hexadecimal character to unescape.
/// \return
///   The unescaped character. If the character is not a hexadecimal character, -1 is returned.
[[nodiscard]] constexpr auto unescape_hex(char c) noexcept -> char {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/// \brief
///   Unescape the specified URL. Please notice that '+' is not unescaped into ' '.
/// \param position
///   The position of the URL to unescape.
/// \param length
///   The length of the URL to unescape.
/// \param dest
///   The destination buffer to store the unescaped URL.
/// \return
///   Position after the last unescaped character in destination buffer. Return nullptr if the URL is invalid.
[[nodiscard]] auto unescape_url(const char *position, std::size_t size, char *dest) noexcept -> char * {
    while (size >= 16) {
        const __m128i input = _mm_loadu_si128(reinterpret_cast<const __m128i *>(position));
        const __m128i mask  = _mm_cmpeq_epi8(input, _mm_set1_epi8('%'));
        const int     count = std::countr_zero(static_cast<std::uint16_t>(_mm_movemask_epi8(mask)));

        if (count == 16) [[likely]] {
            _mm_storeu_si128(reinterpret_cast<__m128i *>(dest), input);

            dest += 16;
            position += 16;
            size -= 16;
            continue;
        }

#if defined(__clang__) || defined(__GNUC__)
        __builtin_memcpy(dest, position, count);
#else
        std::memcpy(dest, position, count);
#endif

        dest += count;
        position += count;
        size -= static_cast<std::size_t>(count);

        // Handle escaped characters.
        while (*position == '%') {
            if (size < 3) [[unlikely]]
                return nullptr;

            char c0 = unescape_hex(*++position);
            char c1 = unescape_hex(*++position);

            if (c0 == -1 || c1 == -1) [[unlikely]]
                return nullptr;

            *dest++ = (c0 << 4) | c1;
            position += 1;
            size -= 3;
        }
    }

    while (size != 0) {
        char c = *position++;
        if (c != '%') [[likely]] {
            *dest++ = c;
            --size;
            continue;
        }

        if (size < 3) [[unlikely]]
            return nullptr;

        char c0 = unescape_hex(*position++);
        char c1 = unescape_hex(*position++);

        if (c0 == -1 || c1 == -1) [[unlikely]]
            return nullptr;

        *dest++ = (c0 << 4) | c1;
        size -= 3;
    }

    return dest;
}

/// \brief
///   Callback function for HTTP parser that is called when the whole HTTP URL is parsed.
/// \param parser
///   The llhttp parser instance.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. -1 will be returned if the URL is
///   not a valid HTTP URL. Otherwise, \c HPE_OK will be returned.
auto http_parser_on_url_complete(llhttp_t *parser) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);

    // For HTTP options only.
    if (state->value_buffer == "*") [[unlikely]] {
        state->request.path.swap(state->value_buffer);
        return HPE_OK;
    }

    // Helper function to find the next specified character in the string.
    const auto find_next = [](const char *position, const char *end, char c) {
        while (position + 16 < end) {
            const __m128i input = _mm_loadu_si128(reinterpret_cast<const __m128i *>(position));
            const __m128i mask  = _mm_cmpeq_epi8(input, _mm_set1_epi8(c));
            const int     count = std::countr_zero(static_cast<std::uint16_t>(_mm_movemask_epi8(mask)));

            if (count == 16) {
                position += 16;
                continue;
            }

            position += count;
            return position;
        }

        while (position != end && *position != c)
            ++position;
        return position;
    };

    const auto find_next_any_of = [](const char *position, const char *end, char c1, char c2) {
        while (position + 16 < end) {
            const __m128i input = _mm_loadu_si128(reinterpret_cast<const __m128i *>(position));
            const __m128i mask1 = _mm_cmpeq_epi8(input, _mm_set1_epi8(c1));
            const __m128i mask2 = _mm_cmpeq_epi8(input, _mm_set1_epi8(c2));
            const __m128i mask  = _mm_or_si128(mask1, mask2);
            const int     count = std::countr_zero(static_cast<std::uint16_t>(_mm_movemask_epi8(mask)));

            if (count == 16) {
                position += 16;
                continue;
            }

            position += count;
            return position;
        }

        while (position != end && *position != c1 && *position != c2)
            ++position;
        return position;
    };

    // Parse path and query strings.
    const char *first = state->value_buffer.data();
    const char *last  = first;
    const char *end   = first + state->value_buffer.size();

    if (state->value_buffer.starts_with("http://")) [[unlikely]]
        first += 7;
    else if (state->value_buffer.starts_with("https://")) [[unlikely]]
        first += 8;

    first = find_next(first, end, '/');
    last  = find_next_any_of(first, end, '?', '#');

    { // Unescape path.
        state->request.path.resize(static_cast<std::size_t>(last - first));
        char *next = unescape_url(first, static_cast<std::size_t>(last - first), state->request.path.data());

        if (next == nullptr) [[unlikely]] {
            state->error = http_parser_error_bad_request;
            return -1;
        }

        state->request.path.resize(static_cast<std::size_t>(next - state->request.path.data()));
    }

    // Parse query string.
    first = find_next(last, end, '?');
    while (first != end && (*first == '?' || *first == '&')) {
        first += 1; // Skip the '?' itself.
        last = find_next(first, end, '=');
        if (last == end) [[unlikely]] {
            // We do not treat this as an error, but we ignore this query string.
            return HPE_OK;
        }

        // Unescape key.
        std::string key;
        key.resize(static_cast<std::size_t>(last - first));
        char *next = unescape_url(first, static_cast<std::size_t>(last - first), key.data());
        if (next == nullptr) [[unlikely]] {
            state->error = http_parser_error_bad_request;
            return -1;
        }
        key.resize(static_cast<std::size_t>(next - key.data()));

        first = last + 1; // Skip the '='.
        last  = find_next_any_of(first, end, '&', '#');

        // Unescape value.
        std::string value;
        value.resize(static_cast<std::size_t>(last - first));
        next = unescape_url(first, static_cast<std::size_t>(last - first), value.data());
        if (next == nullptr) [[unlikely]] {
            state->error = http_parser_error_bad_request;
            return -1;
        }
        value.resize(static_cast<std::size_t>(next - value.data()));

        // Add to request parameters.
        state->request.queries.try_emplace(std::move(key), std::move(value));
        first = last;
    }

    state->value_buffer.clear();
    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request method.
/// \param parser
///   The llhttp parser instance.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function returns -1 if the
///   HTTP method is not supported.
auto http_parser_on_method_complete(llhttp_t *parser) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);

    switch (parser->method) {
    case HTTP_GET:     state->request.method = onion::http_method_get; break;
    case HTTP_HEAD:    state->request.method = onion::http_method_head; break;
    case HTTP_POST:    state->request.method = onion::http_method_post; break;
    case HTTP_PUT:     state->request.method = onion::http_method_put; break;
    case HTTP_DELETE:  state->request.method = onion::http_method_delete; break;
    case HTTP_CONNECT: state->request.method = onion::http_method_connect; break;
    case HTTP_OPTIONS: state->request.method = onion::http_method_options; break;
    case HTTP_TRACE:   state->request.method = onion::http_method_trace; break;
    case HTTP_PATCH:   state->request.method = onion::http_method_patch; break;
    default:           [[unlikely]] state->error = http_parser_error_method_not_allowed; return -1;
    }

    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request version.
/// \param parser
///   The llhttp parser instance.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_version_complete(llhttp_t *parser) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);

    std::uint16_t major = llhttp_get_http_major(parser);
    std::uint16_t minor = llhttp_get_http_minor(parser);

    state->request.version = static_cast<onion::http_version>((major << 8) | minor);
    if (state->request.version != onion::http_version_1_0 && state->request.version != onion::http_version_1_1) {
        state->error = http_parser_error_version_not_supported;
        return -1;
    }

    return HPE_OK;
}

/// \brief
///   Callback function for HTTP parser to acquire HTTP request header field.
/// \param parser
///   The llhttp parser instance.
/// \return
///   An llhttp error code that indicates whether the parser should continue or stop. This function always returns
///   \c HPE_OK.
auto http_parser_on_header_value_complete(llhttp_t *parser) noexcept -> int {
    auto *state = static_cast<http_parser_state *>(parser->data);
    state->request.headers.add(state->key_buffer, state->value_buffer);
    state->key_buffer.clear();
    state->value_buffer.clear();
    return HPE_OK;
}

/// \brief
///   Helper function to convert HTTP response object into HTTP response message string.
/// \param response
///   The HTTP response object to be converted into HTTP response message.
/// \return
///   A string that represents HTTP response message of the corresponding HTTP response object.
[[nodiscard]] auto to_string(const onion::http_response &response) noexcept -> std::string {
    std::string buffer;
    buffer.reserve(4096);

    // HTTP version.
    if (response.version == onion::http_version_1_0)
        buffer.append("HTTP/1.0 ");
    else
        buffer.append("HTTP/1.1 ");

    // HTTP status code.
    buffer.push_back(static_cast<char>(response.status / 100) + '0');
    buffer.push_back(static_cast<char>((response.status / 10) % 10) + '0');
    buffer.push_back(static_cast<char>(response.status % 10) + '0');
    buffer.push_back(' ');

    // HTTP reason phrase.
    buffer.append(onion::http_reason_phrase(response.status));
    buffer.append("\r\n");

    // Append headers.
    for (const auto &kv : response.headers) {
        buffer.append(kv.first);
        buffer.append(": ");
        buffer.append(kv.second);
        buffer.append("\r\n");
    }

    // Start of response body.
    buffer.append("\r\n");
    buffer.append(response.body);

    return buffer;
}

} // namespace

auto onion::http_server::handle_connection(tcp_stream stream) noexcept -> task<> {
    std::array<char, 16384>                       buffer;
    std::expected<std::uint32_t, std::error_code> result;

    http_context context{
        .server   = *this,
        .request  = {},
        .response = {},
    };

    http_parser_state state{
        .error        = http_parser_error_ok,
        .key_buffer   = {},
        .value_buffer = {},
        .request      = context.request,
    };

    llhttp_settings_t callbacks{
        .on_message_begin                  = http_parser_on_message_begin,
        .on_url                            = http_parser_on_url,
        .on_status                         = nullptr,
        .on_method                         = nullptr,
        .on_version                        = nullptr,
        .on_header_field                   = http_parser_on_header_field,
        .on_header_value                   = http_parser_on_header_value,
        .on_chunk_extension_name           = nullptr,
        .on_chunk_extension_value          = nullptr,
        .on_headers_complete               = nullptr,
        .on_body                           = http_parser_on_body,
        .on_message_complete               = http_parser_on_message_complete,
        .on_url_complete                   = http_parser_on_url_complete,
        .on_status_complete                = nullptr,
        .on_method_complete                = http_parser_on_method_complete,
        .on_version_complete               = http_parser_on_version_complete,
        .on_header_field_complete          = nullptr,
        .on_header_value_complete          = http_parser_on_header_value_complete,
        .on_chunk_extension_name_complete  = nullptr,
        .on_chunk_extension_value_complete = nullptr,
        .on_chunk_header                   = nullptr,
        .on_chunk_complete                 = nullptr,
        .on_reset                          = nullptr,
    };

    llhttp_t parser;
    llhttp_init(&parser, HTTP_REQUEST, &callbacks);
    parser.data = &state;

    while (true) {
        result = co_await stream.receive(buffer.data(), static_cast<std::uint32_t>(buffer.size()));

        // FIXME: Maybe write a log here?
        if (!result.has_value() || *result == 0) [[unlikely]]
            co_return;

        const char *end   = buffer.data() + *result;
        int         error = llhttp_execute(&parser, buffer.data(), *result);
        while (error != HPE_OK) {
            if (error == HPE_PAUSED) [[likely]] {
                context.response.clear();
                task<> t = this->m_routers[context.request.method].match(context);

                if (t == nullptr) [[unlikely]]
                    context.response.not_found("404 Not Found");
                else if (this->m_middleware != nullptr)
                    co_await this->m_middleware(context, std::move(t));
                else
                    co_await t;

                // Send response.
                std::string message    = to_string(context.response);
                const char *data       = message.data();
                std::size_t total_sent = 0;

                while (total_sent < message.size()) {
                    auto bytes = static_cast<std::uint32_t>(message.size() - total_sent);
                    result     = co_await stream.send(data + total_sent, bytes);

                    // FIXME: Maybe write a log here?
                    if (!result.has_value()) [[unlikely]]
                        co_return;

                    total_sent += *result;
                }

                // Resume parser.
                const char *parsed = llhttp_get_error_pos(&parser);
                llhttp_resume(&parser);
                error = llhttp_execute(&parser, parsed, static_cast<std::size_t>(end - parsed));
                continue;
            }

            if (error == HPE_PAUSED_UPGRADE) [[unlikely]] {
                const char *parsed = llhttp_get_error_pos(&parser);
                llhttp_resume_after_upgrade(&parser);
                error = llhttp_execute(&parser, parsed, static_cast<std::size_t>(end - parsed));
                continue;
            }

            // Bad request.
            switch (state.error) {
            case http_parser_error_version_not_supported:
                context.response.http_version_not_supported("505 HTTP Version Not Supported");
                break;

            case http_parser_error_method_not_allowed:
                context.response.method_not_allowed("405 Method Not Allowed");
                break;

            default: context.response.bad_request("400 Bad Request"); break;
            }

            // Send response. HTTP version and response date cannot be modified by user.
            context.response.version = context.request.version;
            context.response.set_date();

            std::string message    = to_string(context.response);
            const char *data       = message.data();
            std::size_t total_sent = 0;

            while (total_sent < message.size()) {
                auto bytes = static_cast<std::uint32_t>(message.size() - total_sent);
                result     = co_await stream.send(data + total_sent, bytes);

                // FIXME: Maybe write a log here?
                if (!result.has_value()) [[unlikely]]
                    co_return;

                total_sent += *result;
            }

            co_return;
        }
    }
}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
auto onion::http_server::handle_connection(unix_stream stream) noexcept -> task<> {
    std::array<char, 16384>                       buffer;
    std::expected<std::uint32_t, std::error_code> result;

    http_context context{
        .server   = *this,
        .request  = {},
        .response = {},
    };

    http_parser_state state{
        .error        = http_parser_error_ok,
        .key_buffer   = {},
        .value_buffer = {},
        .request      = context.request,
    };

    llhttp_settings_t callbacks{
        .on_message_begin                  = http_parser_on_message_begin,
        .on_url                            = http_parser_on_url,
        .on_status                         = nullptr,
        .on_method                         = nullptr,
        .on_version                        = nullptr,
        .on_header_field                   = http_parser_on_header_field,
        .on_header_value                   = http_parser_on_header_value,
        .on_chunk_extension_name           = nullptr,
        .on_chunk_extension_value          = nullptr,
        .on_headers_complete               = nullptr,
        .on_body                           = http_parser_on_body,
        .on_message_complete               = http_parser_on_message_complete,
        .on_url_complete                   = http_parser_on_url_complete,
        .on_status_complete                = nullptr,
        .on_method_complete                = http_parser_on_method_complete,
        .on_version_complete               = http_parser_on_version_complete,
        .on_header_field_complete          = nullptr,
        .on_header_value_complete          = http_parser_on_header_value_complete,
        .on_chunk_extension_name_complete  = nullptr,
        .on_chunk_extension_value_complete = nullptr,
        .on_chunk_header                   = nullptr,
        .on_chunk_complete                 = nullptr,
        .on_reset                          = nullptr,
    };

    llhttp_t parser;
    llhttp_init(&parser, HTTP_REQUEST, &callbacks);
    parser.data = &state;

    while (true) {
        result = co_await stream.receive(buffer.data(), static_cast<std::uint32_t>(buffer.size()));

        // FIXME: Maybe write a log here?
        if (!result.has_value() || *result == 0) [[unlikely]]
            co_return;

        const char *end   = buffer.data() + *result;
        int         error = llhttp_execute(&parser, buffer.data(), *result);
        while (error != HPE_OK) {
            if (error == HPE_PAUSED) [[likely]] {
                context.response.clear();
                task<> t = this->m_routers[context.request.method].match(context);

                if (t == nullptr) [[unlikely]]
                    context.response.not_found("404 Not Found");
                else if (this->m_middleware != nullptr)
                    co_await this->m_middleware(context, std::move(t));
                else
                    co_await t;

                // Send response.
                std::string message    = to_string(context.response);
                const char *data       = message.data();
                std::size_t total_sent = 0;

                while (total_sent < message.size()) {
                    auto bytes = static_cast<std::uint32_t>(message.size() - total_sent);
                    result     = co_await stream.send(data + total_sent, bytes);

                    // FIXME: Maybe write a log here?
                    if (!result.has_value()) [[unlikely]]
                        co_return;

                    total_sent += *result;
                }

                // Resume parser.
                const char *parsed = llhttp_get_error_pos(&parser);
                llhttp_resume(&parser);
                error = llhttp_execute(&parser, parsed, static_cast<std::size_t>(end - parsed));
                continue;
            }

            if (error == HPE_PAUSED_UPGRADE) [[unlikely]] {
                const char *parsed = llhttp_get_error_pos(&parser);
                llhttp_resume_after_upgrade(&parser);
                error = llhttp_execute(&parser, parsed, static_cast<std::size_t>(end - parsed));
                continue;
            }

            // Bad request.
            switch (state.error) {
            case http_parser_error_version_not_supported:
                context.response.http_version_not_supported("505 HTTP Version Not Supported");
                break;

            case http_parser_error_method_not_allowed:
                context.response.method_not_allowed("405 Method Not Allowed");
                break;

            default: context.response.bad_request("400 Bad Request"); break;
            }

            // Send response. HTTP version and response date cannot be modified by user.
            context.response.version = context.request.version;
            context.response.set_date();

            std::string message    = to_string(context.response);
            const char *data       = message.data();
            std::size_t total_sent = 0;

            while (total_sent < message.size()) {
                auto bytes = static_cast<std::uint32_t>(message.size() - total_sent);
                result     = co_await stream.send(data + total_sent, bytes);

                // FIXME: Maybe write a log here?
                if (!result.has_value()) [[unlikely]]
                    co_return;

                total_sent += *result;
            }

            co_return;
        }
    }
}
#endif
