#include "onion/http.hpp"

#include <algorithm>

using namespace onion;
using namespace onion::detail;

/// \brief
///   Map upper case characters to lower case.
static constexpr std::uint8_t CaseInsensitiveCharMap[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,
    38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,
    57,  58,  59,  60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107,
    108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91,  92,  93,  94,
    95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
    114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
    133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
    152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170,
    171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
    190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208,
    209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
    228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
    247, 248, 249, 250, 251, 252, 253, 254, 255,
};

/// \brief
///   Read 64-bit integer from \p position.
/// \param position
///   Pointer to read 64-bit integer from.
/// \return
///   64-bit integer read from \p position.
[[nodiscard]]
static constexpr auto caseInsensitiveRead64(const std::uint8_t *position) noexcept
    -> std::uint64_t {
    return (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[0]]) << 0) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[1]]) << 8) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[2]]) << 16) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[3]]) << 24) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[4]]) << 32) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[5]]) << 40) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[6]]) << 48) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[7]]) << 56);
}

/// \brief
///   Read 32-bit integer from \p position.
/// \param position
///   Pointer to read 32-bit integer from.
/// \return
///   32-bit integer read from \p position.
[[nodiscard]]
static constexpr auto caseInsensitiveRead32(const std::uint8_t *position) noexcept
    -> std::uint64_t {
    return (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[0]]) << 0) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[1]]) << 8) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[2]]) << 16) |
           (static_cast<std::uint64_t>(CaseInsensitiveCharMap[position[3]]) << 24);
}

auto CaseInsensitiveStringHash::operator()(argument_type value) const noexcept -> result_type {
#if defined(SIZE_MAX) && (SIZE_MAX >= UINT64_MAX)
    constexpr std::uint64_t RapidHashSeed = 0xBDD89AA982704029ULL;

    constexpr std::uint64_t RapidHashSecret[3] = {
        0x2D358DCCAA6C78A5ULL,
        0x8BB84B93962EACC9ULL,
        0x4B33A62ED433D4A3ULL,
    };

    std::size_t size   = value.size();
    std::uint64_t seed = RapidHashSeed ^ 0xCBEB9F1265CEE51FULL ^ size;

    const auto *p = reinterpret_cast<const std::uint8_t *>(value.data());
    std::uint64_t a, b;
    __uint128_t temp, temp1, temp2;

    if (size <= 16) [[likely]] {
        if (size >= 4) [[likely]] {
            const std::uint8_t *last  = p + size - 4;
            const std::uint64_t delta = (size & 24) >> (size >> 3);

            a = (caseInsensitiveRead32(p) << 32) | caseInsensitiveRead32(last);
            b = (caseInsensitiveRead32(p + delta) << 32) | caseInsensitiveRead32(last - delta);
        } else if (size > 0) [[likely]] {
            a = static_cast<std::uint64_t>(CaseInsensitiveCharMap[p[0]]) << 56;
            a |= static_cast<std::uint64_t>(CaseInsensitiveCharMap[p[size >> 1]]) << 32;
            a |= static_cast<std::uint64_t>(CaseInsensitiveCharMap[p[size - 1]]);
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
                temp = static_cast<__uint128_t>(caseInsensitiveRead64(p) ^ RapidHashSecret[0]) *
                       static_cast<__uint128_t>(caseInsensitiveRead64(p + 8) ^ seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 16) ^ RapidHashSecret[1]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 24) ^ seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 32) ^ RapidHashSecret[2]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 40) ^ seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                temp =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 48) ^ RapidHashSecret[0]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 56) ^ seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 64) ^ RapidHashSecret[1]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 72) ^ seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 80) ^ RapidHashSecret[2]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 88) ^ seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                p += 96;
                i -= 96;
            }

            if (i >= 48) [[unlikely]] {
                temp = static_cast<__uint128_t>(caseInsensitiveRead64(p) ^ RapidHashSecret[0]) *
                       static_cast<__uint128_t>(caseInsensitiveRead64(p + 8) ^ seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));

                temp1 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 16) ^ RapidHashSecret[1]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 24) ^ seed1);
                seed1 =
                    static_cast<std::uint64_t>((temp1 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp1 >> 64));

                temp2 =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 32) ^ RapidHashSecret[2]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 40) ^ seed2);
                seed2 =
                    static_cast<std::uint64_t>((temp2 & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp2 >> 64));

                p += 48;
                i -= 48;
            }

            seed ^= (seed1 ^ seed2);
        }

        if (i > 16) {
            temp =
                static_cast<__uint128_t>(caseInsensitiveRead64(p) ^ RapidHashSecret[2]) *
                static_cast<__uint128_t>(caseInsensitiveRead64(p + 8) ^ seed ^ RapidHashSecret[1]);
            seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));
            if (i > 32) {
                temp =
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 16) ^ RapidHashSecret[2]) *
                    static_cast<__uint128_t>(caseInsensitiveRead64(p + 24) ^ seed);
                seed = static_cast<std::uint64_t>((temp & 0xFFFF'FFFF'FFFF'FFFFULL) ^ (temp >> 64));
            }
        }

        a = caseInsensitiveRead64(p + i - 16);
        b = caseInsensitiveRead64(p + i - 8);
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

auto CaseInsensitiveStringEqual::operator()(argument_type lhs, argument_type rhs) const noexcept
    -> bool {
    if (lhs.size() != rhs.size())
        return false;

    return std::ranges::equal(lhs, rhs, [](char a, char b) {
        return CaseInsensitiveCharMap[static_cast<std::uint8_t>(a)] ==
               CaseInsensitiveCharMap[static_cast<std::uint8_t>(b)];
    });
}

/// \brief
///   Parse HTTP date string into \c std::chrono::sys_clock::time_point.
/// \param first
///   Pointer to the first character of the input string.
/// \param last
///   Pointer to the end of the input string.
/// \param[out] time
///   Used to store the parsed time. This value will not be modified if any error occurs.
/// \return
///   Pointer to the next character after the parsed date and the parsed date. The return value is
///   \c nullptr if the input string is not a valid HTTP date string.
[[nodiscard]]
static auto parseHttpDate(const char *first,
                          const char *last,
                          std::chrono::system_clock::time_point &time) noexcept -> const char * {
    std::chrono::year year;
    std::chrono::month month;
    std::chrono::day day;
    std::chrono::hours hour;
    std::chrono::minutes minute;
    std::chrono::seconds second;
    // Invalid date string.
    if (std::distance(first, last) < 28) [[unlikely]]
        return nullptr;

    // Skip day name. We do not need day name to determine the date.
    while (first != last && *first != ',')
        ++first;

    // Skip the comma.
    if (first != last && *first == ',') [[likely]]
        ++first;
    else
        return nullptr;

    // Skip leading space.
    while (first != last && *first == ' ')
        ++first;

    // There should be at least 24 characters before parsing day.
    if (std::distance(first, last) < 24) [[unlikely]]
        return nullptr;

    { // Parse day.
        char c1 = *first++;
        char c2 = *first++;

        // Invalid day.
        if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9') [[unlikely]]
            return nullptr;

        day = std::chrono::day{static_cast<unsigned>(c1 - '0') * unsigned{10} +
                               static_cast<unsigned>(c2 - '0')};
    }

    // Skip space. We do not strictly require space here.
    while (first != last && *first == ' ')
        ++first;

    // There should be at least 21 characters before parsing month.
    if (std::distance(first, last) < 21) [[unlikely]]
        return nullptr;

    { // Parse month.
        char m1 = *first++;
        char m2 = *first++;
        char m3 = *first++;

        switch (m1) {
        case 'J':
            switch (m2) {
            case 'a': month = std::chrono::January; break;
            case 'u':
                switch (m3) {
                case 'n': month = std::chrono::June; break;
                case 'l': month = std::chrono::July; break;
                default:  return nullptr;
                }
                break;
            default: return nullptr;
            }
            break;
        case 'F': month = std::chrono::February; break;
        case 'M':
            switch (m3) {
            case 'r': month = std::chrono::March; break;
            case 'y': month = std::chrono::May; break;
            default:  return nullptr;
            }
            break;
        case 'A':
            switch (m2) {
            case 'p': month = std::chrono::April; break;
            case 'u': month = std::chrono::August; break;
            default:  return nullptr;
            }
            break;
        case 'S': month = std::chrono::September; break;
        case 'O': month = std::chrono::October; break;
        case 'N': month = std::chrono::November; break;
        case 'D': month = std::chrono::December; break;
        default:  return nullptr;
        }
    }

    // Skip space. We do not strictly require space here.
    while (first != last && *first == ' ')
        ++first;

    // There should be at least 17 characters before parsing year.
    if (std::distance(first, last) < 17) [[unlikely]]
        return nullptr;

    { // Parse year.
        char y1 = *first++;
        char y2 = *first++;
        char y3 = *first++;
        char y4 = *first++;

        // Invalid year.
        if (y1 < '0' || y1 > '9' || y2 < '0' || y2 > '9' || y3 < '0' || y3 > '9' || y4 < '0' ||
            y4 > '9') [[unlikely]]
            return nullptr;

        year =
            std::chrono::year{static_cast<int>(y1 - '0') * 1000 + static_cast<int>(y2 - '0') * 100 +
                              static_cast<int>(y3 - '0') * 10 + static_cast<int>(y4 - '0')};
    }

    // Skip space. We do not strictly require space here.
    while (first != last && *first == ' ')
        ++first;

    // There should be at least 12 characters before parsing hour-minute-second.
    if (std::distance(first, last) < 12) [[unlikely]]
        return nullptr;

    { // Parse hour-minute-second.
        char h1 = *first++;
        char h2 = *first++;
        ++first; // Skip colon.
        char m1 = *first++;
        char m2 = *first++;
        ++first; // Skip colon.
        char s1 = *first++;
        char s2 = *first++;

        // Invalid time.
        if (h1 < '0' || h1 > '9' || h2 < '0' || h2 > '9' || m1 < '0' || m1 > '9' || m2 < '0' ||
            m2 > '9' || s1 < '0' || s1 > '9' || s2 < '0' || s2 > '9') [[unlikely]]
            return nullptr;

        hour   = std::chrono::hours{(h1 - '0') * 10 + (h2 - '0')};
        minute = std::chrono::minutes{(m1 - '0') * 10 + (m2 - '0')};
        second = std::chrono::seconds{(s1 - '0') * 10 + (s2 - '0')};
    }

    // Skip space. We do not strictly require space here.
    while (first != last && *first == ' ')
        ++first;

    // There should be at least 3 characters before parsing timezone.
    if (std::distance(first, last) < 3) [[unlikely]]
        return nullptr;

    // HTTP date is always in UTC time.
    if (*first++ != 'G' || *first++ != 'M' || *first++ != 'T') [[unlikely]]
        return nullptr;

    std::chrono::sys_days sysDays{std::chrono::year_month_day{year, month, day}};
    time = sysDays + hour + minute + second;

    return first;
}

HttpHeaders::HttpHeaders(const HttpHeaders &other) noexcept = default;

HttpHeaders::HttpHeaders(HttpHeaders &&other) noexcept = default;

HttpHeaders::~HttpHeaders() noexcept = default;

auto HttpHeaders::operator=(const HttpHeaders &other) noexcept -> HttpHeaders & = default;

auto HttpHeaders::operator=(HttpHeaders &&other) noexcept -> HttpHeaders & = default;

auto HttpHeaders::add(std::string_view key, std::string_view value) noexcept -> void {
    auto result = m_headers.try_emplace(key, value);
    if (result.second)
        return;

    std::string &mapped = result.first->second;
    if (!mapped.empty())
        mapped.append(", ").append(value);
    else
        mapped.assign(value);
}

auto HttpHeaders::erase(std::string_view key) noexcept -> bool {
    std::size_t count = m_headers.erase(key);
    return count != 0;
}

auto HttpHeaders::clear() noexcept -> void {
    m_headers.clear();
}

auto HttpHeaders::contentLength() const noexcept -> std::optional<std::size_t> {
    auto iter = m_headers.find("Content-Length");
    if (iter == m_headers.end())
        return std::nullopt;

    const std::string &string = iter->second;

    const auto isDigit = [](char c) noexcept -> bool { return c >= '0' && c <= '9'; };
    std::size_t length = 0;

    for (char c : string) {
        if (!isDigit(c))
            return std::nullopt;
        length = (length * 10) + (c - '0');
    }

    return length;
}

auto HttpHeaders::setContentLength(std::size_t length) noexcept -> void {
    std::size_t size = 0;
    char buffer[21];

    while (length != 0) {
        buffer[size++] = length % 10 + '0';
        length /= 10;
    }

    std::ranges::reverse(buffer, buffer + length);
    m_headers["Content-Length"] = std::string_view{buffer, size};
}

auto HttpHeaders::date() const noexcept -> std::optional<std::chrono::system_clock::time_point> {
    auto iter = m_headers.find("Date");
    if (iter == m_headers.end())
        return std::nullopt;

    const std::string &value = iter->second;

    std::chrono::system_clock::time_point time;
    auto next = parseHttpDate(value.data(), value.data() + value.size(), time);
    if (next == nullptr) [[unlikely]]
        return std::nullopt;

    return time;
}

auto HttpHeaders::setDate(std::chrono::system_clock::time_point time) noexcept -> void {
    constexpr const char dayNameList[7][3] = {
        {'S', 'u', 'n'}, {'M', 'o', 'n'}, {'T', 'u', 'e'}, {'W', 'e', 'd'},
        {'T', 'h', 'u'}, {'F', 'r', 'i'}, {'S', 'a', 't'},
    };

    constexpr const char monthNameList[13][3] = {
        {' ', ' ', ' '}, {'J', 'a', 'n'}, {'F', 'e', 'b'}, {'M', 'a', 'r'}, {'A', 'p', 'r'},
        {'M', 'a', 'y'}, {'J', 'u', 'n'}, {'J', 'u', 'l'}, {'A', 'u', 'g'}, {'S', 'e', 'p'},
        {'O', 'c', 't'}, {'N', 'o', 'v'}, {'D', 'e', 'c'},
    };

    auto dayTime{std::chrono::floor<std::chrono::days>(time)};

    std::chrono::weekday weekday{dayTime};
    std::chrono::year_month_day ymd{dayTime};
    std::chrono::hh_mm_ss hms{floor<std::chrono::milliseconds>(time - dayTime)};

    std::chrono::year year   = ymd.year();
    std::chrono::month month = ymd.month();
    std::chrono::day day     = ymd.day();

    std::chrono::hours hour     = hms.hours();
    std::chrono::minutes minute = hms.minutes();
    std::chrono::seconds second = hms.seconds();

    char buffer[29];

    buffer[0]  = dayNameList[weekday.c_encoding()][0];
    buffer[1]  = dayNameList[weekday.c_encoding()][1];
    buffer[2]  = dayNameList[weekday.c_encoding()][2];
    buffer[3]  = ',';
    buffer[4]  = ' ';
    buffer[5]  = ((static_cast<unsigned>(day) / 10) % 10) + '0';
    buffer[6]  = ((static_cast<unsigned>(day) / 1) % 10) + '0';
    buffer[7]  = ' ';
    buffer[8]  = monthNameList[static_cast<unsigned>(month)][0];
    buffer[9]  = monthNameList[static_cast<unsigned>(month)][1];
    buffer[10] = monthNameList[static_cast<unsigned>(month)][2];
    buffer[11] = ' ';
    buffer[12] = ((static_cast<int>(year) / 1000) % 10) + '0';
    buffer[13] = ((static_cast<int>(year) / 100) % 10) + '0';
    buffer[14] = ((static_cast<int>(year) / 10) % 10) + '0';
    buffer[15] = ((static_cast<int>(year) / 1) % 10) + '0';
    buffer[16] = ' ';
    buffer[17] = ((hour.count() / 10) % 10) + '0';
    buffer[18] = ((hour.count() / 1) % 10) + '0';
    buffer[19] = ':';
    buffer[20] = ((minute.count() / 10) % 10) + '0';
    buffer[21] = ((minute.count() / 1) % 10) + '0';
    buffer[22] = ':';
    buffer[23] = ((second.count() / 10) % 10) + '0';
    buffer[24] = ((second.count() / 1) % 10) + '0';
    buffer[25] = ' ';
    buffer[26] = 'G';
    buffer[27] = 'M';
    buffer[28] = 'T';

    std::string_view timeString{buffer, 29};
    m_headers["Date"] = timeString;
}

auto HttpHeaders::isChunked() const noexcept -> bool {
    auto iter = m_headers.find("Transfer-Encoding");
    if (iter == m_headers.end())
        return false;

    const std::string &value = iter->second;
    return value.contains("chunked");
}
