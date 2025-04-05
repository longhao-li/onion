#include "onion/hash.hpp"

#include <gtest/gtest.h>

#include <set>
#include <vector>

using namespace onion;

TEST(unordered_flat_set, find_insert_and_erase_string) {
    // This unit test is used to check if all resources are correctly managed.
    constexpr std::string_view str1 = "The quick brown fox jumps over the lazy dog";
    const std::string          str2{str1};

    unordered_flat_set<std::string> set;
    ASSERT_EQ(set.begin(), set.end());
    ASSERT_EQ(set.cbegin(), set.cend());
    ASSERT_TRUE(set.empty());
    ASSERT_EQ(set.size(), 0);
    ASSERT_EQ(set.erase(str1), 0);
    ASSERT_EQ(set.erase(str2), 0);
    ASSERT_EQ(set.count(str1), 0);
    ASSERT_EQ(set.count(str2), 0);
    ASSERT_EQ(set.find(str1), set.end());
    ASSERT_EQ(set.find(str2), set.end());

    auto result = set.insert(str1);
    ASSERT_TRUE(result.second);
    ASSERT_NE(result.first, set.end());
    ASSERT_EQ(*result.first, str1);
    ASSERT_EQ(set.begin(), result.first);
    ASSERT_NE(set.begin(), set.end());
    ASSERT_NE(set.cbegin(), set.cend());
    ASSERT_FALSE(set.empty());
    ASSERT_EQ(set.size(), 1);
    ASSERT_EQ(set.count(str1), 1);
    ASSERT_EQ(set.count(str2), 1);
    ASSERT_EQ(set.erase(str1), 1);
    ASSERT_EQ(set.erase(str2), 0);
    ASSERT_EQ(set.count(str1), 0);
    ASSERT_EQ(set.count(str2), 0);

    result = set.insert(str1);
    ASSERT_TRUE(result.second);
    for (std::size_t i = 0; i < 2000; ++i) {
        result = set.insert(str1);
        ASSERT_FALSE(result.second);
    }

    set.clear();
    ASSERT_TRUE(set.empty());

    for (std::size_t i = 0; i < 100000; ++i) {
        auto result = set.insert(str2 + std::to_string(i));
        ASSERT_TRUE(result.second);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        std::string temp = str2 + std::to_string(i);
        ASSERT_EQ(set.count(temp), 1);
        ASSERT_EQ(set.count(std::string_view(temp)), 1);
        ASSERT_TRUE(set.contains(temp));
        ASSERT_TRUE(set.contains(std::string_view(temp)));
        ASSERT_EQ(set.erase(temp), 1);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        auto result = set.insert(str2 + std::to_string(i));
        ASSERT_TRUE(result.second);
    }

    for (std::size_t i = 0; i < 100000; ++i) {
        std::string temp = str2 + std::to_string(i);
        ASSERT_EQ(set.count(temp), 1);
        ASSERT_EQ(set.count(std::string_view(temp)), 1);
        ASSERT_TRUE(set.contains(temp));
        ASSERT_TRUE(set.contains(std::string_view(temp)));
        ASSERT_EQ(set.erase(temp), 1);
    }

    set.erase(set.begin(), set.end());
    ASSERT_TRUE(set.empty());
}

TEST(unordered_flat_set, constructors_and_assignments) {
    constexpr std::size_t total_count = 20000;

    const auto insert = [total_count](unordered_flat_set<int> &set) -> void {
        for (int i = 0; i < total_count; ++i) {
            auto result = set.insert(i);
            ASSERT_TRUE(result.second);
            ASSERT_EQ(*result.first, i);
        }
    };

    const auto check = [total_count](unordered_flat_set<int> &set) -> void {
        for (int i = 0; i < total_count; ++i) {
            ASSERT_EQ(set.count(i), 1);
            ASSERT_TRUE(set.contains(i));
            ASSERT_EQ(set.erase(i), 1);
        }

        ASSERT_TRUE(set.empty());
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
        ASSERT_TRUE(set.empty());
        ASSERT_TRUE(set2.empty());
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

TEST(unordered_flat_set, iterate_over_unordered_flat_set) {
    unordered_flat_set<int> set{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::set<int>           flags{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    for (auto &value : set) {
        ASSERT_EQ(flags.count(value), 1);
        flags.erase(value);
    }

    ASSERT_TRUE(flags.empty());

    flags = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    for (int it : static_cast<const unordered_flat_set<int> &>(set)) {
        ASSERT_EQ(flags.count(it), 1);
        flags.erase(it);
    }

    ASSERT_TRUE(flags.empty());
}

TEST(unordered_flat_map, find_insert_and_erase_string) {
    // This unit test is used to check if all resources are correctly managed.
    constexpr std::string_view str1 = "The quick brown fox jumps over the lazy dog";
    const std::string          str2{str1};

    unordered_flat_map<std::string, int> map;
    ASSERT_EQ(map.begin(), map.end());
    ASSERT_EQ(map.cbegin(), map.cend());
    ASSERT_TRUE(map.empty());
    ASSERT_EQ(map.size(), 0);
    ASSERT_EQ(map.erase(str1), 0);
    ASSERT_EQ(map.erase(str2), 0);
    ASSERT_EQ(map.count(str1), 0);
    ASSERT_EQ(map.count(str2), 0);
    ASSERT_EQ(map.find(str1), map.end());
    ASSERT_EQ(map.find(str2), map.end());

    auto result = map.insert(std::make_pair<std::string, int>(std::string(str1), 1));
    ASSERT_TRUE(result.second);
    ASSERT_NE(result.first, map.end());
    ASSERT_EQ((*result.first).first, str1);
    ASSERT_EQ((*result.first).second, 1);
    ASSERT_EQ(map.begin(), result.first);
    ASSERT_NE(map.begin(), map.end());
    ASSERT_NE(map.cbegin(), map.cend());
    ASSERT_FALSE(map.empty());
    ASSERT_EQ(map.size(), 1);
    ASSERT_EQ(map.count(str1), 1);
    ASSERT_EQ(map.count(str2), 1);
    ASSERT_EQ(map.erase(str1), 1);
    ASSERT_EQ(map.erase(str2), 0);
    ASSERT_EQ(map.count(str1), 0);
    ASSERT_EQ(map.count(str2), 0);

    result = map.try_emplace(str1, 1);
    ASSERT_TRUE(result.second);
    for (std::size_t i = 0; i < 2000; ++i) {
        result = map.try_emplace(str2, 1);
        ASSERT_FALSE(result.second);
    }

    map.clear();
    ASSERT_TRUE(map.empty());

    for (std::size_t i = 0; i < 100000; ++i) {
        auto result = map.emplace(str2 + std::to_string(i), static_cast<int>(i));
        ASSERT_TRUE(result.second);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        std::string temp = str2 + std::to_string(i);
        ASSERT_EQ(map.count(temp), 1);
        ASSERT_EQ(map.count(std::string_view(temp)), 1);
        ASSERT_TRUE(map.contains(temp));
        ASSERT_TRUE(map.contains(std::string_view(temp)));
        ASSERT_NO_THROW(std::ignore = map.at(temp));
        ASSERT_NO_THROW(std::ignore = map.at(std::string_view(temp)));
        ASSERT_EQ(map.erase(temp), 1);
    }

    for (std::size_t i = 0; i < 10000; ++i) {
        auto result = map.emplace(str2 + std::to_string(i), static_cast<int>(i));
        ASSERT_TRUE(result.second);
    }

    for (std::size_t i = 0; i < 100000; ++i) {
        std::string temp = str2 + std::to_string(i);
        ASSERT_EQ(map.count(temp), 1);
        ASSERT_EQ(map.count(std::string_view(temp)), 1);
        ASSERT_TRUE(map.contains(temp));
        ASSERT_TRUE(map.contains(std::string_view(temp)));
        ASSERT_NO_THROW(std::ignore = map.at(temp));
        ASSERT_NO_THROW(std::ignore = map.at(std::string_view(temp)));
        ASSERT_EQ(map.erase(static_cast<const std::string &>(temp)), 1);
    }

    map.erase(map.begin(), map.end());
    ASSERT_TRUE(map.empty());
}

TEST(unordered_flat_map, constructors_and_assignments) {
    constexpr std::size_t total_count = 20000;

    const auto insert = [total_count](unordered_flat_map<int, int> &map) -> void {
        for (int i = 0; i < total_count; ++i) {
            auto result = map.insert({i, i});
            ASSERT_TRUE(result.second);
            ASSERT_EQ(*result.first, std::make_pair(i, i));
        }
    };

    const auto check = [total_count](unordered_flat_map<int, int> &map) -> void {
        for (int i = 0; i < total_count; ++i) {
            ASSERT_EQ(map.count(i), 1);
            ASSERT_TRUE(map.contains(i));
            ASSERT_NO_THROW(std::ignore = map.at(i));
            ASSERT_EQ(map.at(i), i);
            ASSERT_TRUE(map.contains(i));
            ASSERT_FALSE(map.insert({i, i}).second);
            ASSERT_EQ(map[i], i);
            ASSERT_EQ(map.erase(i), 1);
        }

        ASSERT_TRUE(map.empty());
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
        ASSERT_TRUE(map.empty());
        ASSERT_TRUE(map2.empty());
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
