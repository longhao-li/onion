#include "onion/hash.hpp"

#include <doctest/doctest.h>

#include <set>
#include <vector>

using namespace onion;

TEST_CASE("[unordered_flat_set] find, insert and erase string") {
    // This unit test is used to check if all resources are correctly managed.
    constexpr std::string_view str1 = "The quick brown fox jumps over the lazy dog";
    const std::string          str2{str1};

    unordered_flat_set<std::string> set;
    CHECK(set.begin() == set.end());
    CHECK(set.cbegin() == set.cend());
    CHECK(set.empty());
    CHECK(set.size() == 0);
    CHECK(set.erase(str1) == 0);
    CHECK(set.erase(str2) == 0);
    CHECK(set.count(str1) == 0);
    CHECK(set.count(str2) == 0);
    CHECK(set.find(str1) == set.end());
    CHECK(set.find(str2) == set.end());

    auto result = set.insert(str1);
    CHECK(result.second);
    CHECK(result.first != set.end());
    CHECK((*result.first == str1));
    CHECK(set.begin() == result.first);
    CHECK(set.begin() != set.end());
    CHECK(set.cbegin() != set.cend());
    CHECK(!set.empty());
    CHECK(set.size() == 1);
    CHECK(set.count(str1) == 1);
    CHECK(set.count(str2) == 1);
    CHECK(set.erase(str1) == 1);
    CHECK(set.erase(str2) == 0);
    CHECK(set.count(str1) == 0);
    CHECK(set.count(str2) == 0);

    result = set.insert(str1);
    CHECK(result.second);
    for (std::size_t i = 0; i < 2000; ++i) {
        result = set.insert(str1);
        CHECK(!result.second);
    }

    set.clear();
    CHECK(set.empty());

    for (std::size_t i = 0; i < 100000; ++i) {
        auto result = set.insert(str2 + std::to_string(i));
        CHECK(result.second);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        std::string temp = str2 + std::to_string(i);
        CHECK(set.count(temp) == 1);
        CHECK(set.count(std::string_view(temp)) == 1);
        CHECK(set.contains(temp));
        CHECK(set.contains(std::string_view(temp)));
        CHECK(set.erase(temp) == 1);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        auto result = set.insert(str2 + std::to_string(i));
        CHECK(result.second);
    }

    for (std::size_t i = 0; i < 100000; ++i) {
        std::string temp = str2 + std::to_string(i);
        CHECK(set.count(temp) == 1);
        CHECK(set.count(std::string_view(temp)) == 1);
        CHECK(set.contains(temp));
        CHECK(set.contains(std::string_view(temp)));
        CHECK(set.erase(static_cast<const std::string &>(temp)) == 1);
    }

    set.erase(set.begin(), set.end());
    CHECK(set.empty());
}

TEST_CASE("[unordered_flat_set] constructors and assignments") {
    constexpr std::size_t total_count = 20000;

    const auto insert = [total_count](unordered_flat_set<int> &set) -> void {
        for (int i = 0; i < total_count; ++i) {
            auto result = set.insert(i);
            CHECK(result.second);
            CHECK(*result.first == i);
        }
    };

    const auto check = [total_count](unordered_flat_set<int> &set) -> void {
        for (int i = 0; i < total_count; ++i) {
            CHECK(set.count(i) == 1);
            CHECK(set.contains(i));
            CHECK(set.erase(i) == 1);
        }

        CHECK(set.empty());
    };

    std::vector<int> vec;
    for (int i = 0; i < total_count; ++i)
        vec.push_back(i);

    { // unordered_flat_set with iterators.
        unordered_flat_set<int> set{vec.begin(), vec.end()};
        check(set);
    }

    { // copy constructor.
        unordered_flat_set<int> set;
        insert(set);
        unordered_flat_set<int> set2{set};

        check(set);
        check(set2);
    }

    { // copy constructor for empty set.
        unordered_flat_set<int> set;
        unordered_flat_set<int> set2{set};
        CHECK(set.empty());
        CHECK(set2.empty());
    }

    { // move constructor.
        unordered_flat_set<int> set;
        set.insert_range(vec);

        unordered_flat_set<int> set2{std::move(set)};
        check(set2);
    }

    { // move constructor with another allocator.
        unordered_flat_set<int> set;
        set.insert_range(vec);

        std::allocator<int>     allocator;
        unordered_flat_set<int> set2{std::move(set), allocator};
        check(set2);
    }

    { // copy assignment.
        unordered_flat_set<int> set;
        insert(set);
        unordered_flat_set<int> set2;
        set2 = set;
        check(set);
        check(set2);
    }

    { // copy assignment.
        unordered_flat_set<int> set;
        insert(set);
        unordered_flat_set<int> set2{1, 2, 3, 4, 5};
        set2 = set;
        check(set);
        check(set2);
    }

    { // move assignment.
        unordered_flat_set<int> set;
        set.insert_range(vec);
        unordered_flat_set<int> set2;
        set2 = std::move(set);
        check(set2);
    }

    { // move assignment.
        unordered_flat_set<int> set;
        set.insert_range(vec);
        unordered_flat_set<int> set2{1, 2, 3, 4, 5};
        set2 = std::move(set);
        check(set2);
    }
}

TEST_CASE("[unordered_flat_set] iterate over unordered flat set") {
    unordered_flat_set<int> set{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::set<int>           flags{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    for (auto &value : set) {
        CHECK(flags.count(value) == 1);
        flags.erase(value);
    }

    CHECK(flags.empty());

    flags = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    for (int it : static_cast<const unordered_flat_set<int> &>(set)) {
        CHECK(flags.count(it) == 1);
        flags.erase(it);
    }

    CHECK(flags.empty());
}

TEST_CASE("[unordered_flat_map] find, insert and erase string") {
    // This unit test is used to check if all resources are correctly managed.
    constexpr std::string_view str1 = "The quick brown fox jumps over the lazy dog";
    const std::string          str2{str1};

    unordered_flat_map<std::string, int> map;
    CHECK(map.begin() == map.end());
    CHECK(map.cbegin() == map.cend());
    CHECK(map.empty());
    CHECK(map.size() == 0);
    CHECK(map.erase(str1) == 0);
    CHECK(map.erase(str2) == 0);
    CHECK(map.count(str1) == 0);
    CHECK(map.count(str2) == 0);
    CHECK(map.find(str1) == map.end());
    CHECK(map.find(str2) == map.end());

    auto result = map.insert(std::make_pair<std::string, int>(std::string(str1), 1));
    CHECK(result.second);
    CHECK(result.first != map.end());
    CHECK(((*result.first).first == str1));
    CHECK(((*result.first).second == 1));
    CHECK(map.begin() == result.first);
    CHECK(map.begin() != map.end());
    CHECK(map.cbegin() != map.cend());
    CHECK(!map.empty());
    CHECK(map.size() == 1);
    CHECK(map.count(str1) == 1);
    CHECK(map.count(str2) == 1);
    CHECK(map.erase(str1) == 1);
    CHECK(map.erase(str2) == 0);
    CHECK(map.count(str1) == 0);
    CHECK(map.count(str2) == 0);

    result = map.try_emplace(str1, 1);
    CHECK(result.second);
    for (std::size_t i = 0; i < 2000; ++i) {
        result = map.try_emplace(str2, 1);
        CHECK(!result.second);
    }

    map.clear();
    CHECK(map.empty());

    for (std::size_t i = 0; i < 100000; ++i) {
        auto result = map.emplace(str2 + std::to_string(i), static_cast<int>(i));
        CHECK(result.second);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        std::string temp = str2 + std::to_string(i);
        CHECK(map.count(temp) == 1);
        CHECK(map.count(std::string_view(temp)) == 1);
        CHECK(map.contains(temp));
        CHECK(map.contains(std::string_view(temp)));
        CHECK_NOTHROW(std::ignore = map.at(temp));
        CHECK_NOTHROW(std::ignore = map.at(std::string_view(temp)));
        CHECK(map.erase(temp) == 1);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        auto result = map.emplace(str2 + std::to_string(i), static_cast<int>(i));
        CHECK(result.second);
    }

    for (std::size_t i = 0; i < 100000; ++i) {
        std::string temp = str2 + std::to_string(i);
        CHECK(map.count(temp) == 1);
        CHECK(map.count(std::string_view(temp)) == 1);
        CHECK(map.contains(temp));
        CHECK(map.contains(std::string_view(temp)));
        CHECK_NOTHROW(std::ignore = map.at(temp));
        CHECK_NOTHROW(std::ignore = map.at(std::string_view(temp)));
        CHECK(map.erase(static_cast<const std::string &>(temp)) == 1);
    }

    map.erase(map.begin(), map.end());
    CHECK(map.empty());
}

TEST_CASE("[unordered_flat_map] constructors and assignments") {
    constexpr std::size_t total_count = 20000;

    const auto insert = [total_count](unordered_flat_map<int, int> &map) -> void {
        for (int i = 0; i < total_count; ++i) {
            auto result = map.insert({i, i});
            CHECK(result.second);
            CHECK(*result.first == std::pair<int, int>{i, i});
        }
    };

    const auto check = [total_count](unordered_flat_map<int, int> &map) -> void {
        for (int i = 0; i < total_count; ++i) {
            CHECK(map.count(i) == 1);
            CHECK(map.contains(i));
            CHECK_NOTHROW(std::ignore = map.at(i));
            CHECK(map.at(i) == i);
            CHECK(map.contains(i));
            CHECK(!map.insert({i, i}).second);
            CHECK(map[i] == i);
            CHECK(map.erase(i) == 1);
        }

        CHECK(map.empty());
    };

    std::vector<std::pair<int, int>> vec;
    for (int i = 0; i < total_count; ++i)
        vec.emplace_back(i, i);

    { // unordered_flat_map with iterators.
        unordered_flat_map<int, int> map{vec.begin(), vec.end()};
        check(map);
    }

    { // copy constructor.
        unordered_flat_map<int, int> map;
        insert(map);
        unordered_flat_map<int, int> map2{map};

        check(map);
        check(map2);
    }

    { // copy constructor for empty map.
        unordered_flat_map<int, int> map;
        unordered_flat_map<int, int> map2{map};
        CHECK(map.empty());
        CHECK(map2.empty());
    }

    { // move constructor.
        unordered_flat_map<int, int> map;
        map.insert_range(vec);

        unordered_flat_map<int, int> map2{std::move(map)};
        check(map2);
    }

    { // move constructor with another allocator.
        unordered_flat_map<int, int> map;
        map.insert_range(vec);

        std::allocator<std::pair<int, int>> allocator;
        unordered_flat_map<int, int>        map2{std::move(map), allocator};
        check(map2);
    }

    { // copy assignment.
        unordered_flat_map<int, int> map;
        insert(map);
        unordered_flat_map<int, int> map2;
        map2 = map;
        check(map);
        check(map2);
    }

    { // copy assignment.
        unordered_flat_map<int, int> map;
        insert(map);
        unordered_flat_map<int, int> map2{{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}};
        map2 = map;
        check(map);
        check(map2);
    }

    { // move assignment.
        unordered_flat_map<int, int> map;
        map.insert_range(vec);
        unordered_flat_map<int, int> map2;
        map2 = std::move(map);
        check(map2);
    }

    { // move assignment.
        unordered_flat_map<int, int> map;
        map.insert_range(vec);
        unordered_flat_map<int, int> map2{{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}};
        map2 = std::move(map);
        check(map2);
    }
}
