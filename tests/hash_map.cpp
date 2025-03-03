#include "onion/hash.hpp"

#include <doctest/doctest.h>

#include <string>
#include <vector>

using namespace onion;

TEST_CASE("[HashMap] Empty hash map") {
    HashMap<std::string, int> map;

    CHECK(map.begin() == map.end());
    CHECK(map.empty());
    CHECK(map.size() == 0);
    CHECK(map.capacity() == 0);
}

TEST_CASE("[HashMap] Construct with initial capacity") {
    HashMap<std::string, std::string> smallMap{12};
    auto first = smallMap.begin();
    auto last  = smallMap.end();
    CHECK(first == last);
    CHECK(smallMap.empty());
    CHECK(smallMap.size() == 0);
    CHECK(smallMap.capacity() >= 12);

    HashMap<std::string, std::string> largeMap{1048576};
    CHECK(largeMap.begin() == largeMap.end());
    CHECK(largeMap.empty());
    CHECK(largeMap.size() == 0);
    CHECK(largeMap.capacity() >= 1048576);

    Hash<std::string> stringHasher;
    HashMap<std::string, std::string> mapWithHasher{2333, stringHasher};
    CHECK(mapWithHasher.begin() == largeMap.end());
    CHECK(mapWithHasher.empty());
    CHECK(mapWithHasher.size() == 0);
    CHECK(mapWithHasher.capacity() >= 2333);

    std::equal_to<std::string> stringEqual;
    HashMap<std::string, std::string> mapWithHasherAndEqual{2333, stringHasher, stringEqual};
    CHECK(mapWithHasherAndEqual.begin() == largeMap.end());
    CHECK(mapWithHasherAndEqual.empty());
    CHECK(mapWithHasherAndEqual.size() == 0);
    CHECK(mapWithHasherAndEqual.capacity() >= 2333);

    std::allocator<char> allocator;
    HashMap<std::string, std::string> mapWithAllocator{2333, stringHasher, stringEqual, allocator};
    CHECK(mapWithAllocator.begin() == largeMap.end());
    CHECK(mapWithAllocator.empty());
    CHECK(mapWithAllocator.size() == 0);
    CHECK(mapWithAllocator.capacity() >= 2333);
}

TEST_CASE("[HashMap] Construct with iterator") {
    std::vector<std::pair<std::string, std::string>> container{
        {"short key 1", "short value 1"},
        {"short key 2", "short value 2"},
        {"short key 3", "short value 3"},
        {"short key 4", "short value 4"},
        {"short key 5", "short value 5"},
        {"short key 6", "short value 6"},
        {"loooooooooooooooooooog key 1", "loooooooooooooooooooog value 1"},
        {"loooooooooooooooooooog key 2", "loooooooooooooooooooog value 2"},
        {"loooooooooooooooooooog key 3", "loooooooooooooooooooog value 3"},
        {"loooooooooooooooooooog key 4", "loooooooooooooooooooog value 4"},
        {"loooooooooooooooooooog key 5", "loooooooooooooooooooog value 5"},
        {"loooooooooooooooooooog key 6", "loooooooooooooooooooog value 6"},
    };

    HashMap<std::string, std::string, Hash<std::string>, std::equal_to<>> map{container.begin(),
                                                                              container.end()};

    CHECK(map.size() == container.size());

    std::string stringKey          = "short key 1";
    std::string_view stringViewKey = "short key 1";

    CHECK(map.contains(stringKey));
    CHECK(map.contains(stringViewKey));
    CHECK(map.contains("short key 4"));
    CHECK(map.contains("loooooooooooooooooooog key 3"));
    CHECK(!map.contains("short key 7"));

    auto result = map.insert(container.front());
    CHECK(!result.second);

    result = map.try_emplace("short key 4", "Hello, world!");
    CHECK(!result.second);

    result = map.try_emplace(std::string("short key 4"), "Hello, world!");
    CHECK(!result.second);

    result = map.try_emplace("short key 233", "Hello, world!");
    CHECK(result.second);
    CHECK(map.size() == container.size() + 1);

    result = map.try_emplace(std::string("short key 2333"), "Hello, world!");
    CHECK(result.second);
    CHECK(map.size() == container.size() + 2);
}

TEST_CASE("[HashMap] Construct with initializer list") {
    HashMap<std::string, std::string, Hash<std::string>, std::equal_to<>> map{
        {"short key 1", "short value 1"},
        {"short key 2", "short value 2"},
        {"short key 3", "short value 3"},
        {"short key 4", "short value 4"},
        {"short key 5", "short value 5"},
        {"short key 6", "short value 6"},
        {"loooooooooooooooooooog key 1", "loooooooooooooooooooog value 1"},
        {"loooooooooooooooooooog key 2", "loooooooooooooooooooog value 2"},
        {"loooooooooooooooooooog key 3", "loooooooooooooooooooog value 3"},
        {"loooooooooooooooooooog key 4", "loooooooooooooooooooog value 4"},
        {"loooooooooooooooooooog key 5", "loooooooooooooooooooog value 5"},
        {"loooooooooooooooooooog key 6", "loooooooooooooooooooog value 6"},
    };

    std::string stringKey          = "short key 1";
    std::string_view stringViewKey = "short key 1";

    CHECK(map.contains(stringKey));
    CHECK(map.contains(stringViewKey));
    CHECK(map.contains("short key 4"));
    CHECK(map.contains("loooooooooooooooooooog key 3"));
    CHECK(!map.contains("short key 7"));
    CHECK(map.count(stringKey) == 1);
    CHECK(map.count(stringViewKey) == 1);
    CHECK(map.count("short key 4") == 1);
    CHECK(map.count("loooooooooooooooooooog key 3") == 1);
    CHECK(map.count("short key 7") == 0);
}

TEST_CASE("[HashMap] Insert and erase") {
    HashMap<std::size_t, std::size_t> map;
    constexpr std::size_t total = 65536;

    // Insert elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.insert({i, i});
        CHECK(result.second);
    }

    CHECK(map.size() == total);
    for (auto i : map)
        CHECK(i.first == i.second);

    // Erase all elements.
    for (std::size_t i = 0; i < total; ++i) {
        CHECK_NOTHROW(std::ignore = map.at(i));
        CHECK(map[i] == i);

        auto result = map.erase(i);
        CHECK(result == 1);
    }

    CHECK(map.empty());

    CHECK_THROWS_AS(std::ignore = map.at(1919810), std::out_of_range);
    CHECK(map[1919810] == 0);
    CHECK(map.erase(1919810) == 1);

    // Insert again.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.insert({i, i});
        CHECK(result.second);
    }

    CHECK(map.size() == total);
    for (auto i : map)
        CHECK(i.first == i.second);

    // Clear the map.
    map.clear();
    CHECK(map.empty());

    constexpr std::size_t smallTotal = 32;

    // Insert small.
    for (std::size_t i = 0; i < smallTotal; ++i) {
        auto result = map.try_emplace(i, i);
        CHECK(result.second);
    }

    CHECK(map.size() == smallTotal);
    for (auto i : map)
        CHECK(i.first == i.second);

    // Clear the map.
    map.erase(map.begin(), map.end());
    CHECK(map.empty());

    // Insert single element.
    std::pair<std::size_t, std::size_t> value{42, 42};
    auto result = map.insert(value);
    CHECK(result.second);
    CHECK(map.size() == 1);
    CHECK(map.erase(114514) == 0);
}

TEST_CASE("[HashMap] Bad hash") {
    HashMap<std::size_t, std::size_t, std::hash<std::size_t>> map;
    constexpr std::size_t total = 65536;

    // Insert elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.insert({i, i});
        CHECK(result.second);
    }

    CHECK(map.size() == total);
    for (auto i : map)
        CHECK(i.first == i.second);

    // Erase all elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.erase(i);
        CHECK(result == 1);
    }

    CHECK(map.empty());
}

TEST_CASE("[HashMap] Copy and move") {
    HashMap<std::string, std::string> empty;
    empty.clear();

    HashMap<std::string, std::string> map0{
        {"short key 1", "short value 1"},
        {"short key 2", "short value 2"},
        {"short key 3", "short value 3"},
        {"short key 4", "short value 4"},
        {"short key 5", "short value 5"},
        {"short key 6", "short value 6"},
        {"loooooooooooooooooooog key 1", "loooooooooooooooooooog value 1"},
        {"loooooooooooooooooooog key 2", "loooooooooooooooooooog value 2"},
        {"loooooooooooooooooooog key 3", "loooooooooooooooooooog value 3"},
        {"loooooooooooooooooooog key 4", "loooooooooooooooooooog value 4"},
        {"loooooooooooooooooooog key 5", "loooooooooooooooooooog value 5"},
        {"loooooooooooooooooooog key 6", "loooooooooooooooooooog value 6"},
    };

    CHECK(map0.size() == 12);
    CHECK(map0.contains("short key 4"));
    CHECK(map0.contains("loooooooooooooooooooog key 3"));
    CHECK(!map0.contains("short key 7"));

    // Copy constructor.
    HashMap<std::string, std::string> map1{map0};
    CHECK(map1.size() == 12);
    CHECK(map1.contains("short key 4"));
    CHECK(map1.contains("loooooooooooooooooooog key 3"));
    CHECK(!map1.contains("short key 7"));

    // Move constructor.
    HashMap<std::string, std::string> map2{std::move(map1)};
    CHECK(map2.size() == 12);
    CHECK(map2.contains("short key 4"));
    CHECK(map2.contains("loooooooooooooooooooog key 3"));
    CHECK(!map2.contains("short key 7"));

    CHECK(map1.empty());
    CHECK(!map1.contains("short key 4"));

    // Copy empty map.
    HashMap<std::string, std::string> map3{empty};
    CHECK(map3.empty());
    CHECK(map3.cbegin() == map3.cend());
    CHECK(map3.capacity() == 0);

    // Move empty map.
    HashMap<std::string, std::string> map4{std::move(map3)};
    CHECK(map4.empty());
    CHECK(map4.cbegin() == map4.cend());
    CHECK(map4.capacity() == 0);

    // Copy assignment.
    HashMap<std::string, std::string> map5{10};
    map5 = map0;
    CHECK(map5.size() == 12);
    CHECK(map5.contains("short key 4"));
    CHECK(map5.contains("loooooooooooooooooooog key 3"));
    CHECK(!map5.contains("short key 7"));

    // Self assignment.
    map5 = map5;
    CHECK(map5.size() == 12);
    CHECK(map5.contains("short key 4"));
    CHECK(map5.contains("loooooooooooooooooooog key 3"));
    CHECK(!map5.contains("short key 7"));

    // Move assignment.
    HashMap<std::string, std::string> map6{10};
    map6 = std::move(map5);
    CHECK(map6.size() == 12);
    CHECK(map6.contains("short key 4"));
    CHECK(map6.contains("loooooooooooooooooooog key 3"));
    CHECK(!map6.contains("short key 7"));

    map6 = std::move(map6);
    CHECK(map6.size() == 12);
    CHECK(map6.contains("short key 4"));
    CHECK(map6.contains("loooooooooooooooooooog key 3"));
    CHECK(!map6.contains("short key 7"));
}

TEST_CASE("[HashMap] Erase range") {
    HashMap<std::size_t, std::size_t> map;
    constexpr std::size_t total = 65536;

    // Insert elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.insert({i, i});
        CHECK(result.second);
    }

    auto first = map.cbegin();
    auto last  = first;

    constexpr std::size_t numToErase = 1024;
    CHECK(map.size() > numToErase);
    for (std::size_t i = 0; i < numToErase; ++i)
        last++;

    map.erase(first, last);
    CHECK(map.size() == total - numToErase);

    // Erase an empty map.
    map.clear();
    CHECK(map.empty());
    map.erase(map.begin(), map.end());
    CHECK(map.empty());
}

TEST_CASE("[HashMap] Rehash and reserve") {
    HashMap<std::size_t, std::size_t> map;
    constexpr std::size_t total = 65536;

    // Do nothing.
    map.rehash(0);
    CHECK(map.capacity() == 0);
    CHECK(map.empty());

    // Do nothing.
    map.reserve(0);
    CHECK(map.capacity() == 0);
    CHECK(map.empty());

    // Insert elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map.insert({i, i});
        CHECK(result.second);
    }

    // Rehash.
    map.rehash(total * 2);
    CHECK(map.size() == total);
    CHECK(map.capacity() >= total * 2);

    // Reserve.
    map.reserve(total * 3);
    CHECK(map.size() == total);
    CHECK(map.capacity() >= total * 3);
}

TEST_CASE("[HashMap] Swap") {
    HashMap<std::size_t, std::size_t> map1;
    HashMap<std::size_t, std::size_t> map2;
    constexpr std::size_t total = 65536;

    // Insert elements.
    for (std::size_t i = 0; i < total; ++i) {
        auto result = map1.insert({i, i});
        CHECK(result.second);
    }

    CHECK(map1.size() == total);
    CHECK(map2.empty());

    for (auto i : map1)
        CHECK(i.first == i.second);

    map1.swap(map2);
    CHECK(map1.empty());
    CHECK(map2.size() == total);

    for (auto i : map2)
        CHECK(i.first == i.second);
}
