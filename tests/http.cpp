#include "onion/http.hpp"

#include <gtest/gtest.h>

using namespace onion;

TEST(http_header_map, date_parser) {
    constexpr std::string_view date = "Thu, 27 Mar 2025 12:34:56 GMT";

    http_header_map headers;
    headers["Date"] = date;
    ASSERT_TRUE(headers.contains("Date"));

    auto time = headers.date();
    ASSERT_TRUE(time.has_value());

    headers.set_date(*time);
    ASSERT_EQ(headers["Date"], date);
}

TEST(http_router, path_matcher) {
    const auto dummy_task = [](http_context &context) -> task<> { co_return; };

    http_server  server;
    http_context context{.server = server};
    http_router  router;

    context.request.path = "/";
    ASSERT_EQ(router.match(context), nullptr);

    context.request.path = "/hello/world";
    ASSERT_EQ(router.match(context), nullptr);

    router.map("/", dummy_task);
    context.request.path = "/";
    ASSERT_NE(router.match(context), nullptr);
    ASSERT_TRUE(context.request.params.empty());

    router.map("/hello", dummy_task);
    context.request.path = "/hello";
    ASSERT_NE(router.match(context), nullptr);
    ASSERT_TRUE(context.request.params.empty());

    router.map("/hello/world", dummy_task);
    context.request.path = "/hello/world";
    ASSERT_NE(router.match(context), nullptr);
    ASSERT_TRUE(context.request.params.empty());

    router.map("/hello/:name", dummy_task);
    context.request.path = "/hello/Li Hua";
    ASSERT_NE(router.match(context), nullptr);
    ASSERT_TRUE(context.request.params.contains("name"));
    ASSERT_EQ(context.request.params.at("name"), "Li Hua");

    context.request.path = "/api/abc";
    ASSERT_EQ(router.match(context), nullptr);

    context.request.path = "/hello/world/Li Hua";
    ASSERT_EQ(router.match(context), nullptr);

    router.map("/:first/:second/:third/forth", dummy_task);
    context.request.path = "/hello/world/Li Hua/forth";
    ASSERT_NE(router.match(context), nullptr);
    ASSERT_TRUE(context.request.params.contains("first"));
    ASSERT_EQ(context.request.params.at("first"), "hello");
    ASSERT_TRUE(context.request.params.contains("second"));
    ASSERT_EQ(context.request.params.at("second"), "world");
    ASSERT_TRUE(context.request.params.contains("third"));
    ASSERT_EQ(context.request.params.at("third"), "Li Hua");
}
