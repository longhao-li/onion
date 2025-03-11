#include "onion/http.hpp"

#include <doctest/doctest.h>

using namespace onion;
using namespace std::chrono_literals;

TEST_CASE("[HttpHeader] Date parser") {
    constexpr std::string_view date1{"Sun, 06 Nov 1994 08:49:37 GMT"};
    constexpr std::string_view date2{"Sat,04 Jan 2025 21:48:00 GMT"};
    constexpr std::string_view date3{"Mon, 30    Sep   2024  14:00:00 GMT"};

    HttpHeader headers;
    headers.add("Date", date1);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == date1);

    auto time1 = headers.date();
    CHECK(time1.has_value());

    auto expected1 = std::chrono::system_clock::time_point{
        std::chrono::sys_days{1994y / std::chrono::November / 6d} + 8h + 49min + 37s};

    CHECK(*time1 == expected1);

    CHECK(headers.erase("Date"));
    CHECK_FALSE(headers.contains("Date"));

    headers.add("Date", date2);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == date2);

    auto time2 = headers.date();
    CHECK(time2.has_value());

    auto expected2 = std::chrono::system_clock::time_point{
        std::chrono::sys_days{2025y / std::chrono::January / 4d} + 21h + 48min};

    CHECK(*time2 == expected2);

    CHECK(headers.erase("Date"));
    CHECK_FALSE(headers.contains("Date"));

    headers.add("Date", date3);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == date3);

    auto time3 = headers.date();
    CHECK(time3.has_value());

    auto expected3 = std::chrono::system_clock::time_point{
        std::chrono::sys_days{2024y / std::chrono::September / 30d} + 14h};

    CHECK(*time3 == expected3);

    CHECK(headers.erase("Date"));
    CHECK_FALSE(headers.contains("Date"));

    constexpr std::string_view badDate1{" "};
    constexpr std::string_view badDate2{"Sat  04 Jan 2025 21:48:00 GMT"};
    constexpr std::string_view badDate3{"Sat          ,               "};
    constexpr std::string_view badDate4{"Sat, 04                      "};
    constexpr std::string_view badDate5{"Sat, 04 Jue 2025 21:48:00 GMT"};
    constexpr std::string_view badDate6{"Sat, 04 Jan               GMT"};
    constexpr std::string_view badDate7{"Sat, 04 Jan 202A 21:48:00 GMT"};

    headers.add("Date", badDate1);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == badDate1);
    CHECK(headers.date().has_value() == false);
    CHECK(headers.erase("Date"));

    headers.add("Date", badDate2);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == badDate2);
    CHECK(headers.date().has_value() == false);
    CHECK(headers.erase("Date"));

    headers.add("Date", badDate3);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == badDate3);
    CHECK(headers.date().has_value() == false);
    CHECK(headers.erase("Date"));

    headers.add("Date", badDate4);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == badDate4);
    CHECK(headers.date().has_value() == false);
    CHECK(headers.erase("Date"));

    headers.add("Date", badDate5);
    CHECK(headers.contains("Date"));
    CHECK(headers.find("Date")->second == badDate5);
    CHECK(headers.date().has_value() == false);
    CHECK(headers.erase("Date"));
}
