#include "onion/http.hpp"

#include <doctest/doctest.h>

#include <chrono>

using namespace onion;

TEST_CASE("[http_header_map] date parser") {
    constexpr std::string_view date = "Thu, 27 Mar 2025 12:34:56 GMT";

    http_header_map headers;
    headers["Date"] = date;
    CHECK(headers.contains("Date"));

    auto time = headers.date();
    CHECK(time.has_value());

    headers.set_date(*time);
    CHECK(headers["Date"] == date);
}
