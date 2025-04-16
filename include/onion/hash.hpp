#pragma once

#include "export.hpp"
#include "task.hpp"

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
#    include <emmintrin.h>
#endif

#include <bit>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <typeindex>

namespace onion {
namespace detail {

/// \brief
///   Hash data using a custom hash function. We use rapidhash for 64-bit systems and wyhash32 for 32-bit systems.
/// \param data
///   Pointer to start of data to be hashed.
/// \param size
///   Size in byte of data to be hashed.
[[nodiscard]] inline auto hash(const void *data, std::size_t size) noexcept -> std::size_t {
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
#    if defined(__clang__) || defined(__GNUC__)
        __builtin_memcpy(&value, position, sizeof(value));
#    else
        value |= static_cast<std::uint64_t>(position[0]) << 0;
        value |= static_cast<std::uint64_t>(position[1]) << 8;
        value |= static_cast<std::uint64_t>(position[2]) << 16;
        value |= static_cast<std::uint64_t>(position[3]) << 24;
        value |= static_cast<std::uint64_t>(position[4]) << 32;
        value |= static_cast<std::uint64_t>(position[5]) << 40;
        value |= static_cast<std::uint64_t>(position[6]) << 48;
        value |= static_cast<std::uint64_t>(position[7]) << 56;
#    endif
        return value;
    };

    const auto read32 = [](const std::uint8_t *position) -> std::uint64_t {
        std::uint32_t value = 0;
#    if defined(__clang__) || defined(__GNUC__)
        __builtin_memcpy(&value, position, sizeof(value));
#    else
        value |= static_cast<std::uint32_t>(position[0]) << 0;
        value |= static_cast<std::uint32_t>(position[1]) << 8;
        value |= static_cast<std::uint32_t>(position[2]) << 16;
        value |= static_cast<std::uint32_t>(position[3]) << 24;
#    endif
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
#    if defined(__clang__) || defined(__GNUC__)
        __builtin_memcpy(&value, position, sizeof(value));
#    else
        value |= static_cast<std::uint32_t>(position[0]) << 0;
        value |= static_cast<std::uint32_t>(position[1]) << 8;
        value |= static_cast<std::uint32_t>(position[2]) << 16;
        value |= static_cast<std::uint32_t>(position[3]) << 24;
#    endif
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

} // namespace detail

/// \struct equal_to
/// \brief
///   Generic equality comparator for type T.
template <typename T = void>
struct equal_to {
    using is_transparent = void;

    template <typename T1, typename T2>
    constexpr auto operator()(T1 &&lhs, T2 &&rhs) const
        noexcept(noexcept(std::forward<T1>(lhs) == std::forward<T2>(rhs)))
            -> decltype(std::forward<T1>(lhs) == std::forward<T2>(rhs)) {
        return std::forward<T1>(lhs) == std::forward<T2>(rhs);
    }
};

/// \struct hash
/// \brief
///   Generic hasher for type T.
template <typename T, typename = void>
struct hash;

/// \struct hash
/// \brief
///   Hasher for arithmetic types.
template <typename T>
struct hash<T, std::enable_if_t<std::is_arithmetic_v<T>>> {
    using is_transparent = void;

    auto operator()(T value) const noexcept -> std::size_t {
        static_assert(sizeof(T) <= 16, "Arithmetic type is too large.");
        return detail::hash(&value, sizeof(value));
    }

    template <typename U>
        requires(std::is_convertible_v<U, T>)
    auto operator()(U value) const noexcept -> std::size_t {
        static_assert(sizeof(T) <= 16, "Arithmetic type is too large.");
        T temp = static_cast<T>(value);
        return detail::hash(&temp, sizeof(temp));
    }
};

/// \struct hash
/// \brief
///   Hasher for enumeration types.
template <typename T>
struct hash<T, std::enable_if_t<std::is_enum_v<T>>> {
    auto operator()(T value) const noexcept -> std::size_t {
        static_assert(sizeof(T) <= 16, "Arithmetic type is too large.");
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for pointer types.
template <typename T>
struct hash<T *> {
    using is_transparent = void;

    auto operator()(void *value) const noexcept -> std::size_t {
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c nullptr_t.
template <>
struct hash<std::nullptr_t> {
    auto operator()(std::nullptr_t value) const noexcept -> std::size_t {
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::coroutine_handle types.
template <typename T>
struct hash<std::coroutine_handle<T>> {
    using is_transparent = void;

    template <typename U>
    auto operator()(std::coroutine_handle<U> value) const noexcept -> std::size_t {
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::error_code.
template <>
struct hash<std::error_code> {
    auto operator()(const std::error_code &value) const noexcept -> std::size_t {
        static_assert(sizeof(std::error_code) <= 16);
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::error_condition.
template <>
struct hash<std::error_condition> {
    auto operator()(const std::error_condition &value) const noexcept -> std::size_t {
        static_assert(sizeof(std::error_condition) <= 16);
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::optional types.
template <typename T>
struct hash<std::optional<T>> {
    using is_transparent = void;

    auto operator()(const std::optional<T> &value) const noexcept -> std::size_t {
        if (value.has_value()) {
            return hash<std::remove_const_t<T>>{}(value.value());
        } else {
            std::nullptr_t null = nullptr;
            return detail::hash(&null, sizeof(null));
        }
    }

    auto operator()(const std::remove_const_t<T> &value) const noexcept -> std::size_t {
        return hash<std::remove_const_t<T>>{}(value);
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::bitset types.
template <std::size_t Size>
struct hash<std::bitset<Size>> {
    auto operator()(const std::bitset<Size> &value) const noexcept -> std::size_t {
        if constexpr (sizeof(value) <= 16) {
            return detail::hash(&value, sizeof(value));
        } else if constexpr (sizeof(value) > 16) {
            return detail::hash(&value, sizeof(value));
        }
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::unique_ptr.
template <typename T, typename D>
struct hash<std::unique_ptr<T, D>> {
    using is_transparent = void;

    auto operator()(const std::unique_ptr<T, D> &value) const noexcept -> std::size_t {
        auto *pointer = value.get();
        return detail::hash(&pointer, sizeof(pointer));
    }

    auto operator()(const void *value) const noexcept -> std::size_t {
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::shared_ptr.
template <typename T>
struct hash<std::shared_ptr<T>> {
    using is_transparent = void;

    auto operator()(const std::shared_ptr<T> &value) const noexcept -> std::size_t {
        auto *pointer = value.get();
        return detail::hash(&pointer, sizeof(pointer));
    }

    auto operator()(const void *value) const noexcept -> std::size_t {
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::basic_string.
template <typename Char, typename Traits, typename Allocator>
struct hash<std::basic_string<Char, Traits, Allocator>> {
    using is_transparent = void;

    auto operator()(const std::basic_string<Char, Traits, Allocator> &value) const noexcept -> std::size_t {
        return detail::hash(value.data(), value.size() * sizeof(Char));
    }

    auto operator()(std::basic_string_view<Char, Traits> value) const noexcept -> std::size_t {
        return detail::hash(value.data(), value.size() * sizeof(Char));
    }

    auto operator()(const Char *value) const noexcept -> std::size_t {
        return detail::hash(value, Traits::length(value) * sizeof(Char));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::basic_string_view.
template <typename Char, typename Traits>
struct hash<std::basic_string_view<Char, Traits>> {
    using is_transparent = void;

    auto operator()(std::basic_string_view<Char, Traits> value) const noexcept -> std::size_t {
        return detail::hash(value.data(), value.size() * sizeof(Char));
    }
};

/// \struct hash
/// \brief
///   Hasher for task types.
template <typename T>
struct hash<task<T>> {
    auto operator()(const task<T> &value) const noexcept -> std::size_t {
        void *address = value.coroutine().address();
        return detail::hash(&address, sizeof(address));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::thread::id.
template <>
struct hash<std::thread::id> {
    auto operator()(const std::thread::id &value) const noexcept -> std::size_t {
        static_assert(sizeof(std::thread::id) <= 16);
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::type_info.
template <>
struct hash<std::type_info> {
    using is_transparent = void;

    auto operator()(const std::type_info &value) const noexcept -> std::size_t {
        return detail::hash(value.name(), std::char_traits<char>::length(value.name()));
    }

    auto operator()(const std::type_index &value) const noexcept -> std::size_t {
        return detail::hash(value.name(), std::char_traits<char>::length(value.name()));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::type_index.
template <>
struct hash<std::type_index> {
    using is_transparent = void;

    auto operator()(const std::type_index &value) const noexcept -> std::size_t {
        return detail::hash(value.name(), std::char_traits<char>::length(value.name()));
    }

    auto operator()(const std::type_info &value) const noexcept -> std::size_t {
        return detail::hash(value.name(), std::char_traits<char>::length(value.name()));
    }
};

} // namespace onion

namespace onion::detail {

/// \struct is_transparent
/// \brief
///   Helper struct to determine if a hasher is transparent.
template <typename T, typename = void>
struct is_transparent : std::false_type {};

/// \struct is_transparent
/// \brief
///   Helper struct to determine if a hasher is transparent.
template <typename T>
struct is_transparent<T, typename T::is_transparent> : std::true_type {};

/// \brief
///   Helper variable template to determine if a hasher is transparent.
template <typename T>
inline constexpr bool is_transparent_v = is_transparent<T>::value;

/// \struct aligned_memory
/// \brief
///   Helper struct to create aligned memory.
template <std::size_t Align>
struct alignas(Align) aligned_memory {
    std::byte padding[Align];
};

/// \brief
///   Helper type to get type at the specified index.
template <std::size_t Index, typename... Ts>
struct type_at {};

/// \brief
///   Helper type to get type at the specified index.
template <std::size_t Index, typename T, typename... Ts>
struct type_at<Index, T, Ts...> : type_at<Index - 1, Ts...> {
    static_assert(Index < sizeof...(Ts) + 1, "Index out of range.");
};

/// \brief
///   Helper type to get type at the specified index.
template <typename T, typename... Ts>
struct type_at<0, T, Ts...> {
    using type = T;
};

/// \brief
///   Alias template to get type at the specified index.
template <std::size_t Index, typename... Ts>
using type_at_t = typename type_at<Index, Ts...>::type;

/// \class compressed_tuple_element
/// \brief
///    Base class for compressed tuple.
template <std::size_t Index,
          typename T,
          bool CouldEBO = std::is_empty_v<T> && !std::is_final_v<T> && std::is_class_v<T>>
class compressed_tuple_element {
public:
    /// \brief
    ///   Constructor of this element.
    template <typename... Args>
        requires(std::is_constructible_v<T, Args && ...>)
    constexpr compressed_tuple_element(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args &&...>)
        : m_value{std::forward<Args>(args)...} {}

    /// \brief
    ///   Get value of this element.
    /// \return
    ///   Reference to value of this element.
    [[nodiscard]] constexpr auto value() noexcept -> T & {
        return this->m_value;
    }

    /// \brief
    ///   Get value of this element.
    /// \return
    ///   Reference to value of this element.
    [[nodiscard]] constexpr auto value() const noexcept -> const T & {
        return this->m_value;
    }

private:
    T m_value;
};

/// \class compressed_tuple_element
/// \brief
///    Base class for EBO compressed tuple.
template <std::size_t Index, typename T>
class compressed_tuple_element<Index, T, true> : public T {
public:
    /// \brief
    ///   Constructor of this element.
    template <typename... Args>
        requires(std::is_constructible_v<T, Args && ...>)
    constexpr compressed_tuple_element(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args &&...>)
        : T{std::forward<Args>(args)...} {}

    /// \brief
    ///   Get value of this element.
    /// \return
    ///   Reference to value of this element.
    [[nodiscard]] constexpr auto value() noexcept -> T & {
        return *this;
    }

    /// \brief
    ///   Get value of this element.
    /// \return
    ///   Reference to value of this element.
    [[nodiscard]] constexpr auto value() const noexcept -> const T & {
        return *this;
    }
};

/// \brief
///   Helper type to create compressed tuple elements.
template <std::size_t Index, typename T, typename... Ts>
class compressed_tuple_elements : public compressed_tuple_element<Index, T>,
                                  public compressed_tuple_elements<Index + 1, Ts...> {
public:
    /// \brief
    ///   Default constructor of compressed tuple elements.
    constexpr compressed_tuple_elements() noexcept = default;

    /// \brief
    ///   Constructor of compressed tuple elements.
    /// \param arg
    ///   The first argument to construct the compressed tuple elements.
    /// \param args
    ///   The rest of the arguments to construct the compressed tuple elements.
    template <typename Arg, typename... Args>
        requires(std::conjunction_v<std::is_constructible<T, Arg &&>, std::is_constructible<Ts, Args &&>...>)
    constexpr compressed_tuple_elements(Arg &&arg, Args &&...args) noexcept(
        std::conjunction_v<std::is_nothrow_constructible<T, Arg &&>, std::is_nothrow_constructible<Ts, Args &&>...>)
        : compressed_tuple_element<Index, T>{std::forward<Arg>(arg)},
          compressed_tuple_elements<Index + 1, Ts...>{std::forward<Args>(args)...} {}
};

/// \brief
///   Helper type to create compressed tuple elements.
template <std::size_t Index, typename T>
class compressed_tuple_elements<Index, T> : public compressed_tuple_element<Index, T> {
public:
    /// \brief
    ///   Default constructor of compressed tuple elements.
    constexpr compressed_tuple_elements() noexcept = default;

    /// \brief
    ///   Constructor of compressed tuple elements.
    /// \param arg
    ///   The argument to construct the compressed tuple elements.
    template <typename Arg>
        requires(std::is_constructible_v<T, Arg &&>)
    constexpr compressed_tuple_elements(Arg &&arg) noexcept(std::is_nothrow_constructible_v<T, Arg &&>)
        : compressed_tuple_element<Index, T>{std::forward<Arg>(arg)} {}
};

/// \class compressed_tuple
/// \brief
///   Compression tuple with empty base optimization.
template <typename... Ts>
    requires(sizeof...(Ts) > 0)
class compressed_tuple : private compressed_tuple_elements<0, Ts...> {
public:
    /// \brief
    ///   Default constructor of compressed tuple.
    constexpr compressed_tuple() noexcept = default;

    /// \brief
    ///   Constructor of compressed tuple.
    /// \param args
    ///   Arguments to construct the compressed tuple.
    template <typename... Args>
        requires(sizeof...(Args) == sizeof...(Ts) && std::conjunction_v<std::is_constructible<Ts, Args &&>...>)
    constexpr compressed_tuple(Args &&...args) noexcept(
        std::conjunction_v<std::is_nothrow_constructible<Ts, Args &&>...>)
        : compressed_tuple_elements<0, Ts...>{std::forward<Args>(args)...} {}

    /// \brief
    ///   Get value at the specified index.
    /// \tparam Index
    ///   Index of the value to get.
    /// \return
    ///   Reference to value at the specified index.
    template <std::size_t Index>
        requires(Index < sizeof...(Ts))
    [[nodiscard]] constexpr auto get() noexcept -> type_at_t<Index, Ts...> & {
        using super = compressed_tuple_element<Index, type_at_t<Index, Ts...>>;
        return static_cast<super *>(this)->value();
    }

    /// \brief
    ///   Get value at the specified index.
    /// \tparam Index
    ///   Index of the value to get.
    /// \return
    ///   Reference to value at the specified index.
    template <std::size_t Index>
        requires(Index < sizeof...(Ts))
    [[nodiscard]] constexpr auto get() const noexcept -> const type_at_t<Index, Ts...> & {
        using super = compressed_tuple_element<Index, type_at_t<Index, Ts...>>;
        return static_cast<const super *>(this)->value();
    }
};

/// \enum hash_table_state
/// \brief
///   State of a hash table slot.
enum class hash_table_state : std::int8_t {
    empty    = -128,
    deleted  = -2,
    sentinel = -1,
};

/// \brief
///   Empty group of hash table states.
ONION_API extern const hash_table_state hash_table_state_empty_group[16];

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Byte width of each hash table group.
inline constexpr std::size_t hash_table_group_width = 16;
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Load hash table states into a 128-bit SSE register.
/// \param states
///   Pointer to the states of the hash table group.
/// \return
///   A 128-bit SSE register that contains the states of the hash table group.
[[nodiscard]] inline auto hash_table_load_states(const hash_table_state *states) noexcept -> __m128i {
    return _mm_loadu_si128(reinterpret_cast<const __m128i *>(states));
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Store the 128-bit SSE register into the hash table group of states.
/// \param states
///   The 128-bit SSE register that contains the states of the hash table group to be stored.
/// \param[out] where
///   Pointer to the states of the hash table group.
/// \return
///   A 128-bit SSE register that contains the states of the hash table group.
inline auto hash_table_store_states(__m128i states, hash_table_state *where) noexcept -> void {
    _mm_storeu_si128(reinterpret_cast<__m128i *>(where), states);
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Get a bitmask that represents positions of slots that matches the specified H2 hash value.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \param hash
///   The H2 hash value to match.
/// \return
///   A 16-bit mask that represents positions of slots that matches the specified H2 hash value.
[[nodiscard]] inline auto hash_table_match_h2(__m128i states, std::uint8_t hash) noexcept -> std::uint16_t {
    __m128i match  = _mm_set1_epi8(static_cast<char>(hash));
    __m128i result = _mm_cmpeq_epi8(match, states);
    int     mask   = _mm_movemask_epi8(result);
    return static_cast<std::uint16_t>(mask);
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Get a bitmask that represents positions of slots that are empty in a hash table group.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   A 16-bit mask that represents positions of empty slots in the hash table group.
[[nodiscard]] inline auto hash_table_mask_empty_slots(__m128i states) noexcept -> std::uint16_t {
    __m128i empty  = _mm_set1_epi8(static_cast<char>(hash_table_state::empty));
    __m128i result = _mm_cmpeq_epi8(states, empty);
    int     mask   = _mm_movemask_epi8(result);
    return static_cast<std::uint16_t>(mask);
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Mask full slots for a hash table group of states.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   A 16-bit mask that represents state of each slot in the hash table group.
[[nodiscard]] inline auto hash_table_mask_full_slots(__m128i states) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(_mm_movemask_epi8(states) ^ 0xFFFF);
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Mask non-full slots for a hash table group of states.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   A 16-bit mask that represents state of each slot in the hash table group.
[[nodiscard]] inline auto hash_table_mask_non_full_slots(__m128i states) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(_mm_movemask_epi8(states));
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Mask empty or deleted slots for a hash table group of states.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   A 16-bit mask that represents state of each slot in the hash table group.
[[nodiscard]] inline auto hash_table_mask_empty_or_deleted_slots(__m128i states) noexcept -> std::uint16_t {
    __m128i sentinel   = _mm_set1_epi8(static_cast<char>(hash_table_state::sentinel));
    __m128i non_filled = _mm_cmpgt_epi8(sentinel, states);
    int     mask       = _mm_movemask_epi8(non_filled);
    return static_cast<std::uint16_t>(mask);
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Count the number of leading empty or deleted slots in a hash table group of states.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   Number of leading empty or deleted slots in the hash table group.
[[nodiscard]] inline auto hash_table_count_leading_empty_or_deleted_slots(__m128i states) noexcept -> std::uint8_t {
    __m128i sentinel   = _mm_set1_epi8(static_cast<char>(hash_table_state::sentinel));
    __m128i non_filled = _mm_cmpgt_epi8(sentinel, states);
    auto    mask       = static_cast<std::uint32_t>(_mm_movemask_epi8(non_filled) + 1);
    return static_cast<std::uint8_t>(std::countr_zero(mask));
}
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/// \brief
///   Convert full states to deleted states and other states into empty states.
/// \param states
///   The states of the hash table group represented as a 128-bit SSE register.
/// \return
///   A 128-bit SSE register that contains the states of the hash table group.
[[nodiscard]] inline auto hash_table_empty_states_and_convert_full_to_deleted(__m128i states) noexcept -> __m128i {
    __m128i mask     = _mm_set1_epi8(static_cast<char>(-128));
    __m128i x126     = _mm_set1_epi8(126);
    __m128i zero     = _mm_setzero_si128();
    __m128i special  = _mm_cmpgt_epi8(zero, states);
    __m128i non_full = _mm_andnot_si128(special, x126);
    __m128i result   = _mm_or_si128(mask, non_full);
    return result;
}
#endif

/// \class hash_table_probe_sequence
/// \brief
///   Probe sequence is used to generate a sequence of indices to probe in a hash table.
class hash_table_probe_sequence {
public:
    /// \brief
    ///   Create a new \c probe_sequence with the given hash value and mask.
    /// \param hash
    ///   The hash value to use for probing. This constructor will mask the hash value with the given mask.
    /// \param mask
    ///   The mask to use for probing. This mask should be the size of the hash table capacity minus one.
    hash_table_probe_sequence(std::size_t hash, std::size_t mask) noexcept : m_mask{mask}, m_offset{hash & mask} {}

    /// \brief
    ///   Get current offset in the probe sequence.
    /// \return
    ///   The current offset in the probe sequence.
    [[nodiscard]] auto offset() const noexcept -> std::size_t {
        return this->m_offset;
    }

    /// \brief
    ///   Get the next offset in the probe sequence.
    /// \param extra
    ///   Extra offset to add to the current offset.
    /// \return
    ///   The next offset in the probe sequence.
    [[nodiscard]] auto offset(std::size_t extra) const noexcept -> std::size_t {
        return (this->m_offset + extra) & this->m_mask;
    }

    /// \brief
    ///   Go to the next offset in the probe sequence.
    auto next() noexcept -> void {
        this->m_index += hash_table_group_width;
        this->m_offset += this->m_index;
        this->m_offset &= this->m_mask;
    }

    /// \brief
    ///   Get the current index in the probe sequence.
    /// \return
    ///   The current index in the probe sequence.
    [[nodiscard]] auto index() const noexcept -> std::size_t {
        return this->m_index;
    }

private:
    std::size_t m_mask;
    std::size_t m_offset;
    std::size_t m_index = 0;
};

/// \brief
///   Get next capacity for hash table.
/// \param n
///   Current capacity of hash table. Must be 2^N - 1.
/// \return
///   Next capacity for hash table.
[[nodiscard]] constexpr auto hash_table_next_capacity(std::size_t n) noexcept -> std::size_t {
    return (n < 0xF) ? 0xF : (n << 1) + 1;
}

/// \brief
///   Convert the specified capacity into next 2^N - 1 capacity.
/// \param n
///   Capacity to normalize.
/// \return
///   Next 2^N - 1 capacity.
[[nodiscard]] constexpr auto hash_table_normalize_capacity(std::size_t n) noexcept -> std::size_t {
    return n ? (~std::size_t{} >> std::countl_zero(n)) : 1;
}

/// \class hash_table_layout
/// \brief
///   Helper class to calculate layout of hash table.
template <typename T>
struct hash_table_layout {
    /// \brief
    ///   Create a new \c hash_table_layout with the specified capacity and calculate the layout.
    /// \param capacity
    ///   Capacity of the hash table.
    hash_table_layout(std::size_t capacity)
        : value_offset{(capacity + hash_table_group_width + alignof(T) - 1) & ~(alignof(T) - 1)},
          allocate_size{value_offset + capacity * sizeof(T)} {}

    std::size_t value_offset;
    std::size_t allocate_size;
};

/// \class hash_table
/// \brief
///   General purpose swiss-table implementation for both set and map.
/// \tparam Key
///   Key type of the hash table.
/// \tparam Mapped
///   Mapped type of the hash table.
/// \tparam Hash
///   Hasher type for the key type.
/// \tparam KeyEqual
///   Key equality comparison type.
/// \tparam Allocator
///   Allocator type for the hash table.
template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
class hash_table {
private:
    using allocator_traits      = std::allocator_traits<Allocator>;
    using char_allocator        = typename allocator_traits::template rebind_alloc<char>;
    using char_allocator_traits = std::allocator_traits<char_allocator>;

public:
    using key_type        = Key;
    using mapped_type     = Mapped;
    using value_type      = std::conditional_t<std::is_void_v<Mapped>, Key, std::pair<Key, Mapped>>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using hasher          = Hash;
    using key_equal       = KeyEqual;
    using allocator_type  = Allocator;
    using reference       = value_type &;
    using const_reference = const value_type &;
    using pointer         = typename std::allocator_traits<Allocator>::pointer;
    using const_pointer   = typename std::allocator_traits<Allocator>::const_pointer;

    /// \class iterator
    /// \brief
    ///   Iterator type for \c hash_table.
    class iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = typename hash_table::value_type;
        using reference         = typename hash_table::reference;
        using pointer           = typename hash_table::pointer;
        using difference_type   = typename hash_table::difference_type;

        /// \brief
        ///   Create an empty iterator.
        iterator() noexcept = default;

        /// \brief
        ///   For internal usage. Create an iterator with the specified state array and value array.
        /// \param state
        ///   Pointer to current position in the state array.
        /// \param value
        ///   Pointer to current position in the value array.
        iterator(hash_table_state *state, value_type *value) noexcept : m_state{state}, m_value{value} {}

        /// \brief
        ///   Dereference this iterator.
        /// \return
        ///   Reference to the value of this iterator.
        [[nodiscard]] auto operator*() const noexcept -> reference {
            return *this->m_value;
        }

        /// \brief
        ///   Get the pointer to the value of this iterator.
        /// \return
        ///   Pointer to the value of this iterator.
        [[nodiscard]] auto operator->() const noexcept -> pointer {
            return this->m_value;
        }

        /// \brief
        ///   Move to the next element in the hash table.
        /// \return
        ///   Reference to this iterator.
        auto operator++() noexcept -> iterator & {
            this->m_state += 1;
            this->m_value += 1;
            this->skip_empty_or_deleted();
            return *this;
        }

        /// \brief
        ///   Move to the next element in the hash table.
        /// \return
        ///   Copy of this iterator before moving to the next element.
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
            return lhs.m_state == rhs.m_state;
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
            return lhs.m_state != rhs.m_state;
        }

        friend class hash_table;
        friend class const_iterator;

    private:
        /// \brief
        ///   Skip empty and deleted elements in the hash table.
        auto skip_empty_or_deleted() noexcept -> void {
            for (auto states = hash_table_load_states(this->m_state); *this->m_state < hash_table_state::sentinel;
                 states      = hash_table_load_states(this->m_state)) {
                std::uint8_t shift = hash_table_count_leading_empty_or_deleted_slots(states);
                this->m_state += shift;
                this->m_value += shift;
            }

            if (*this->m_state == hash_table_state::sentinel) {
                this->m_state = nullptr;
                this->m_value = nullptr;
            }
        }

    private:
        hash_table_state *m_state = const_cast<hash_table_state *>(hash_table_state_empty_group);
        value_type       *m_value = nullptr;
    };

    /// \class const_iterator
    /// \brief
    ///   Const iterator type for \c hash_table.
    class const_iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = typename hash_table::value_type;
        using reference         = typename hash_table::const_reference;
        using pointer           = typename hash_table::const_pointer;
        using difference_type   = typename hash_table::difference_type;

        /// \brief
        ///   Create an empty iterator.
        const_iterator() noexcept = default;

        /// \brief
        ///   Allow implicit conversion from \c iterator to \c const_iterator.
        /// \param iter
        ///   The iterator to convert.
        const_iterator(iterator iter) noexcept : m_state{iter.m_state}, m_value{iter.m_value} {}

        /// \brief
        ///   For internal usage. Create an iterator with the specified state array and value array.
        /// \param state
        ///   Pointer to current position in the state array.
        /// \param value
        ///   Pointer to current position in the value array.
        const_iterator(hash_table_state *state, value_type *value) noexcept : m_state{state}, m_value{value} {}

        /// \brief
        ///   Dereference this iterator.
        /// \return
        ///   Reference to the value of this iterator.
        [[nodiscard]] auto operator*() const noexcept -> reference {
            return *this->m_value;
        }

        /// \brief
        ///   Get the pointer to the value of this iterator.
        /// \return
        ///   Pointer to the value of this iterator.
        [[nodiscard]] auto operator->() const noexcept -> pointer {
            return this->m_value;
        }

        /// \brief
        ///   Move to the next element in the hash table.
        /// \return
        ///   Reference to this iterator.
        auto operator++() noexcept -> const_iterator & {
            this->m_state += 1;
            this->m_value += 1;
            this->skip_empty_or_deleted();
            return *this;
        }

        /// \brief
        ///   Move to the next element in the hash table.
        /// \return
        ///   Copy of this iterator before moving to the next element.
        auto operator++(int) noexcept -> const_iterator {
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
        [[nodiscard]] friend auto operator==(const const_iterator &lhs, const const_iterator &rhs) noexcept -> bool {
            return lhs.m_state == rhs.m_state;
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
        [[nodiscard]] friend auto operator!=(const const_iterator &lhs, const const_iterator &rhs) noexcept -> bool {
            return lhs.m_state != rhs.m_state;
        }

        friend class hash_table;

    private:
        /// \brief
        ///   Skip empty and deleted elements in the hash table.
        auto skip_empty_or_deleted() noexcept -> void {
            for (auto states = hash_table_load_states(this->m_state); *this->m_state < hash_table_state::sentinel;
                 states      = hash_table_load_states(this->m_state)) {
                std::uint8_t shift = hash_table_count_leading_empty_or_deleted_slots(states);
                this->m_state += shift;
                this->m_value += shift;
            }

            if (*this->m_state == hash_table_state::sentinel) {
                this->m_state = nullptr;
                this->m_value = nullptr;
            }
        }

    private:
        hash_table_state *m_state = const_cast<hash_table_state *>(hash_table_state_empty_group);
        value_type       *m_value = nullptr;
    };

private:
    /// \struct storage_t
    /// \brief
    ///   Storage of the hash table.
    struct storage_t {
        size_type capacity                         = 0;
        size_type has_deleted : 1                  = 0;
        size_type size : sizeof(size_type) * 8 - 1 = 0;

        hash_table_state *states = const_cast<hash_table_state *>(hash_table_state_empty_group);
        value_type       *values = nullptr;

        /// \brief
        ///   Get start of the backing array. The backing array layout looks like the following:
        ///
        /// \code{.cpp}
        /// struct backing_array {
        ///     // States of the hash table.
        ///     hash_table_state states[capacity];
        ///     // Always hash_table_state::sentinel.
        ///     hash_table_state sentinel;
        ///     // Padding hash_table_state to make SIMD operations always get valid values.
        ///     hash_table_state padding[15];
        ///     // Values of the hash table.
        ///     value_type values[capacity];
        /// };
        /// \endcode
        [[nodiscard]] auto backing_array() const noexcept -> void * {
            return states;
        }

        /// \brief
        ///   Set state at the given position.
        /// \param offset
        ///   Offset to set the state.
        /// \param h2
        ///   H2 hash value to be set.
        auto set_state(size_type offset, std::uint8_t h2) noexcept -> void {
            this->states[offset] = static_cast<hash_table_state>(h2);
            // Set wrap-around state. This operation must not be ignored because probing sequence may wrap around.
            this->states[((offset - (hash_table_group_width - 1)) & this->capacity) +
                         ((hash_table_group_width - 1) & this->capacity)] = static_cast<hash_table_state>(h2);
        }

        /// \brief
        ///   Set state at the given position.
        /// \param offset
        ///   Offset to set the state.
        /// \param s
        ///   The new state to be set.
        auto set_state(size_type offset, hash_table_state s) noexcept -> void {
            this->states[offset] = s;
            // Set wrap-around state. This operation must not be ignored because probing sequence may wrap around.
            this->states[((offset - (hash_table_group_width - 1)) & this->capacity) +
                         ((hash_table_group_width - 1) & this->capacity)] = s;
        }

        /// \brief
        ///   Calculate total allocated memory size.
        /// \return
        ///   Total allocated memory size for backing array.
        [[nodiscard]] auto allocated_size() const noexcept -> std::size_t {
            hash_table_layout<value_type> layout{this->capacity};
            return layout.allocate_size;
        }

        /// \brief
        ///   Find first empty position to insert an element with the specified hash value.
        /// \param hash
        ///   Hash value of the element to be inserted.
        /// \return
        ///   A pair that contains offset and sequence probe length.
        [[nodiscard]] auto find_first_non_full(std::size_t hash) const noexcept -> std::size_t {
            hash_table_probe_sequence seq{hash >> 7, this->capacity};
            if (this->states[seq.offset()] < hash_table_state::sentinel)
                return seq.offset();

            while (true) {
                auto group = hash_table_load_states(this->states + seq.offset());
                auto mask  = hash_table_mask_empty_or_deleted_slots(group);
                if (mask != 0)
                    return seq.offset(std::countr_zero(mask));
                seq.next();
            }
        }

        /// \brief
        ///   Destroy all elements in this hash table.
        /// \param allocator
        ///   Allocator that is used to destroy elements.
        auto destroy_elements(allocator_type &allocator) noexcept -> void {
            hash_table_state *state_array = this->states;
            value_type       *value_array = this->values;
            for (size_type remaining = this->size; remaining != 0;) {
                auto group = hash_table_load_states(state_array);
                for (auto mask = hash_table_mask_full_slots(group); mask != 0; mask &= mask - 1) {
                    int index = std::countr_zero(mask);
                    allocator_traits::destroy(allocator, value_array + index);
                    remaining -= 1;
                }

                state_array += hash_table_group_width;
                value_array += hash_table_group_width;
            }
        }

        /// \brief
        ///   Deallocate memory of this hash table.
        /// \param allocator
        ///   Allocator that is used to deallocate memory.
        auto deallocate(char_allocator &allocator) noexcept -> void {
            char_allocator_traits::deallocate(allocator, static_cast<char *>(backing_array()), this->allocated_size());
        }
    };

public:
    /// \brief
    ///   Default constructor of the hash table. Create an empty hash table.
    hash_table() noexcept(std::conjunction_v<std::is_nothrow_default_constructible<allocator_type>,
                                             std::is_nothrow_default_constructible<hasher>,
                                             std::is_nothrow_default_constructible<key_equal>>) = default;

    /// \brief
    ///   Create a new hash table with the specified bucket count, hasher, key equality comparison, and allocator.
    /// \param bucket_count
    ///   Initial number of buckets in the hash table.
    /// \param hash
    ///   Hasher to use for the hash table.
    /// \param equal
    ///   Key equality comparison to use for the hash table.
    /// \param allocator
    ///   Allocator to use for the hash table.
    hash_table(size_type             bucket_count,
               const hasher         &hash      = hasher{},
               const key_equal      &equal     = key_equal{},
               const allocator_type &allocator = allocator_type{});

    /// \brief
    ///   Create a new hash table with a range of elements, bucket count, hasher, key equality comparison, and
    ///   allocator.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range.
    /// \param bucket_count
    ///   Initial number of buckets in the hash table.
    /// \param hash
    ///   Hasher to use for the hash table.
    /// \param equal
    ///   Key equality comparison to use for the hash table.
    /// \param allocator
    ///   Allocator to use for the hash table.
    template <std::input_iterator InputIt>
    hash_table(InputIt               first,
               InputIt               last,
               size_type             bucket_count = 0,
               const hasher         &hash         = hasher{},
               const key_equal      &equal        = key_equal{},
               const allocator_type &allocator    = allocator_type{})
        : hash_table{bucket_count, hash, equal, allocator} {
        this->insert(first, last);
    }

    /// \brief
    ///   Copy constructor of \c hash_table.
    /// \param other
    ///   The \c hash_table to copy from.
    hash_table(const hash_table &other);

    /// \brief
    ///   Copy constructor of hash table with the specified allocator.
    /// \param other
    ///   The hash table to copy from.
    /// \param allocator
    ///   Allocator to use for this hash table.
    hash_table(const hash_table &other, const allocator_type &allocator);

    /// \brief
    ///   Move constructor of \c hash_table.
    /// \param[inout] other
    ///   The \c hash_table to move from. The moved \c hash_table will be empty after this operation.
    hash_table(hash_table &&other) noexcept : m_internal{std::move(other.m_internal)} {
        other.m_internal.template get<3>() = storage_t{};
    }

    /// \brief
    ///   Move constructor of hash table with the specified allocator.
    /// \param[inout] other
    ///   The hash table to move from. The moved hash table will be in a valid but unspecified state after this
    ///   operation.
    /// \param allocator
    ///   Allocator to use for this hash table.
    hash_table(hash_table &&other, const allocator_type &allocator);

    /// \brief
    ///   Destroy this hash table.
    ~hash_table() {
        storage_t &storage = this->m_internal.template get<3>();
        if (storage.capacity == 0)
            return;

        allocator_type origin_alloc{this->m_internal.template get<0>()};
        storage.destroy_elements(origin_alloc);
        storage.deallocate(this->m_internal.template get<0>());
    }

    /// \brief
    ///   Copy assignment of hash table.
    /// \param other
    ///   The hash table to be copied from.
    /// \return
    ///   Reference to this hash table.
    auto operator=(const hash_table &other) -> hash_table &;

    /// \brief
    ///   Move assignment of hash table.
    /// \param[inout] other
    ///   The hash table to be moved from. The moved hash table will be in a valid but unspecified state after this
    ///   operation.
    /// \return
    ///   Reference to this hash table.
    auto operator=(hash_table &&other) noexcept -> hash_table &;

    /// \brief
    ///   Get the allocator associated with this hash table.
    /// \return
    ///   Allocator associated with this hash table.
    [[nodiscard]] auto get_allocator() const noexcept -> allocator_type {
        return allocator_type{this->m_internal.template get<0>()};
    }

    /// \brief
    ///   Get iterator to the first element in this hash table.
    /// \return
    ///   Iterator to the first element in this hash table.
    [[nodiscard]] auto begin() noexcept -> iterator {
        storage_t &storage = this->m_internal.template get<3>();
        if (storage.size == 0)
            return {nullptr, nullptr};

        iterator iter{storage.states, storage.values};
        iter.skip_empty_or_deleted();
        return iter;
    }

    /// \brief
    ///   Get iterator to the first element in this hash table.
    /// \return
    ///   Iterator to the first element in this hash table.
    [[nodiscard]] auto begin() const noexcept -> const_iterator {
        const storage_t &storage = this->m_internal.template get<3>();
        if (storage.size == 0)
            return {nullptr, nullptr};

        const_iterator iter{storage.states, storage.values};
        iter.skip_empty_or_deleted();
        return iter;
    }

    /// \brief
    ///   Get iterator to the first element in this hash table.
    /// \return
    ///   Iterator to the first element in this hash table.
    [[nodiscard]] auto cbegin() const noexcept -> const_iterator {
        return this->begin();
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this hash table.
    /// \return
    ///   Iterator to the placeholder after the last element in this hash table.
    [[nodiscard]] auto end() noexcept -> iterator {
        return {nullptr, nullptr};
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this hash table.
    /// \return
    ///   Iterator to the placeholder after the last element in this hash table.
    [[nodiscard]] auto end() const noexcept -> const_iterator {
        return {nullptr, nullptr};
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this hash table.
    /// \return
    ///   Iterator to the placeholder after the last element in this hash table.
    [[nodiscard]] auto cend() const noexcept -> const_iterator {
        return this->end();
    }

    /// \brief
    ///   Checks if this hash table is empty.
    /// \retval true
    ///   This hash table is empty.
    /// \retval false
    ///   This hash table is not empty.
    [[nodiscard]] auto empty() const noexcept -> bool {
        const storage_t &storage = this->m_internal.template get<3>();
        return storage.size == 0;
    }

    /// \brief
    ///   Get number of elements in this hash table.
    /// \return
    ///   Number of elements in this hash table.
    [[nodiscard]] auto size() const noexcept -> size_type {
        return this->m_internal.template get<3>().size;
    }

    /// \brief
    ///   Erases all elements from this hash table.
    auto clear() noexcept -> void;

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(const value_type &value) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(value_type &&value) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a range of elements into this hash table if the keys do not exist.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be inserted.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be inserted.
    template <std::input_iterator InputIt>
    auto insert(InputIt first, InputIt last) -> void;

    /// \brief
    ///   Try to insert a range of elements into this hash table if the keys do not exist.
    /// \param list
    ///   Initializer list of elements to be inserted.
    auto insert(std::initializer_list<value_type> list) -> void;

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist.
    /// \tparam K
    ///   Type of the new value to insert.
    /// \param value
    ///   The new value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    auto insert(K &&value) -> std::pair<iterator, bool> {
        auto result = this->prepare_insertion(key_reference(value));
        if (result.second) {
            allocator_type origin_alloc{this->m_internal.template get<0>()};
            allocator_traits::construct(origin_alloc, result.first.m_value, std::forward<K>(value));
        }

        return result;
    }

    /// \brief
    ///   Try to insert a range of elements into this hash table if the keys do not exist.
    /// \tparam R
    ///   Type of input range.
    /// \param range
    ///   Range of elements to be inserted.
    template <std::ranges::input_range R>
    auto insert_range(R &&range) -> void {
        this->insert(std::ranges::begin(range), std::ranges::end(range));
    }

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist. Otherwise, replace the existing
    ///   element with the new one.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The key of the new element.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename M>
    auto insert_or_assign(const key_type &key, M &&value) -> std::pair<iterator, bool> {
        auto           result = this->prepare_insertion(key);
        allocator_type origin_alloc{this->m_internal.template get<0>()};

        if (!result.second)
            allocator_traits::destroy(origin_alloc, result.first.m_value);
        allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                    std::forward_as_tuple(key), std::forward_as_tuple(std::forward<M>(value)));

        return result;
    }

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist. Otherwise, replace the existing
    ///   element with the new one.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The key of the new element.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename M>
    auto insert_or_assign(key_type &&key, M &&value) -> std::pair<iterator, bool> {
        auto           result = this->prepare_insertion(key);
        allocator_type origin_alloc{this->m_internal.template get<0>()};

        if (!result.second)
            allocator_traits::destroy(origin_alloc, result.first.m_value);
        allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                    std::forward_as_tuple(std::move(key)),
                                    std::forward_as_tuple(std::forward<M>(value)));

        return result;
    }

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist. Otherwise, replace the existing
    ///   element with the new one.
    /// \tparam K
    ///   Type of the key of the new element.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The key of the new element.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K, typename M>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    auto insert_or_assign(K &&key, M &&value) -> std::pair<iterator, bool> {
        auto           result = this->prepare_insertion(key);
        allocator_type origin_alloc{this->m_internal.template get<0>()};

        if (!result.second)
            allocator_traits::destroy(origin_alloc, result.first.m_value);
        allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                    std::forward_as_tuple(std::forward<K>(key)),
                                    std::forward_as_tuple(std::forward<M>(value)));

        return result;
    }

    /// \brief
    ///   Try to insert a new element into this hash table if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
        requires(std::is_constructible_v<value_type, Args && ...>)
    auto emplace(Args &&...args) noexcept(std::is_nothrow_constructible_v<value_type, Args &&...>)
        -> std::pair<iterator, bool> {
        value_type value{std::forward<Args>(args)...};
        auto       result = this->prepare_insertion(key_reference(value));

        if (result.second) {
            allocator_type origin_alloc{this->m_internal.template get<0>()};
            allocator_traits::construct(origin_alloc, result.first.m_value, std::move(value));
        }

        return result;
    }

    /// \brief
    ///   For map only. Try to insert a new element into this hash table if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   The key of the new element.
    /// \param args
    ///   Arguments to construct the mapped value of the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
    auto try_emplace(const key_type &key, Args &&...args) -> std::pair<iterator, bool> {
        auto result = this->prepare_insertion(key);

        if (result.second) {
            allocator_type origin_alloc{this->m_internal.template get<0>()};
            allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                        std::forward_as_tuple(key), std::forward_as_tuple(std::forward<Args>(args)...));
        }

        return result;
    }

    /// \brief
    ///   For map only. Try to insert a new element into this hash table if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   The key of the new element.
    /// \param args
    ///   Arguments to construct the mapped value of the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
    auto try_emplace(key_type &&key, Args &&...args) -> std::pair<iterator, bool> {
        auto result = this->prepare_insertion(key);

        if (result.second) {
            allocator_type origin_alloc{this->m_internal.template get<0>()};
            allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                        std::forward_as_tuple(std::move(key)),
                                        std::forward_as_tuple(std::forward<Args>(args)...));
        }

        return result;
    }

    /// \brief
    ///   For map only. Try to insert a new element into this hash table if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   The key of the new element.
    /// \param args
    ///   Arguments to construct the mapped value of the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K, typename... Args>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal> && std::is_constructible_v<key_type, K &&> &&
                 std::is_constructible_v<mapped_type, Args && ...>)
    auto try_emplace(K &&key, Args &&...args) -> std::pair<iterator, bool> {
        auto result = this->prepare_insertion(std::forward<K>(key));

        if (result.second) {
            allocator_type origin_alloc{this->m_internal.template get<0>()};
            allocator_traits::construct(origin_alloc, result.first.m_value, std::piecewise_construct,
                                        std::forward_as_tuple(std::forward<K>(key)),
                                        std::forward_as_tuple(std::forward<Args>(args)...));
        }

        return result;
    }

    /// \brief
    ///   Remove specified elements from this hash table. We do not return iterator to the next element because it is
    ///   slow to find the next element.
    /// \param position
    ///   Iterator to the element to be removed.
    auto erase(const_iterator position) noexcept -> void {
        allocator_type origin_alloc{this->m_internal.template get<0>()};
        allocator_traits::destroy(origin_alloc, position.m_value);

        storage_t &storage = this->m_internal.template get<3>();
        auto       index   = static_cast<size_type>(position.m_state - storage.states);

        const auto group_never_full = [&storage, index]() -> bool {
            if (storage.capacity <= hash_table_group_width)
                return true;

            const size_type before = (index - hash_table_group_width) & storage.capacity;

            const auto empty_after  = hash_table_mask_empty_slots(hash_table_load_states(storage.states + index));
            const auto empty_before = hash_table_mask_empty_slots(hash_table_load_states(storage.states + before));

            return (empty_before != 0 && empty_after != 0 &&
                    std::countr_zero(empty_after) + std::countl_zero(empty_before) <
                        static_cast<int>(hash_table_group_width));
        };

        if (group_never_full()) {
            storage.set_state(index, hash_table_state::empty);
            storage.size -= 1;
            return;
        }

        storage.set_state(index, hash_table_state::deleted);
        storage.has_deleted = 1;
        storage.size -= 1;
    }

    /// \brief
    ///   Remove elements between the specified range from this hash table.
    /// \param first
    ///   Iterator to the first element to be removed.
    /// \param last
    ///   Iterator to the placeholder after the last element to be removed.
    /// \return
    ///   Iterator to the element after the last removed element.
    auto erase(const_iterator first, const_iterator last) noexcept -> iterator {
        if (first == this->begin() && last == this->end()) {
            this->clear();
            return this->end();
        }

        while (first != last)
            this->erase(first++);

        return {last.m_state, last.m_value};
    }

    /// \brief
    ///   Remove all elements with the specified key from this hash table.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    auto erase(const key_type &key) noexcept -> size_type {
        auto iter = this->find(key);
        if (iter == this->end())
            return 0;

        this->erase(const_iterator{iter});
        return 1;
    }

    /// \brief
    ///   Remove all elements with the specified key from this hash table.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    auto erase(K &&key) noexcept -> size_type {
        auto iter = this->find(std::forward<K>(key));
        if (iter == this->end())
            return 0;

        this->erase(const_iterator{iter});
        return 1;
    }

    /// \brief
    ///   Get number of elements with the specified key.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    [[nodiscard]] auto count(const key_type &key) const noexcept -> size_type {
        return this->find(key) == this->end() ? 0 : 1;
    }

    /// \brief
    ///   Get number of elements with the specified key.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    [[nodiscard]] auto count(K &&key) const noexcept -> size_type {
        return this->find(std::forward<K>(key)) == this->end() ? 0 : 1;
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) noexcept -> iterator {
        return this->find_key(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) const noexcept -> const_iterator {
        return this->find_key(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    [[nodiscard]] auto find(const K &key) noexcept -> iterator {
        return this->find_key(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    [[nodiscard]] auto find(const K &key) const noexcept -> const_iterator {
        return this->find_key(key);
    }

    /// \brief
    ///   Check if this hash table contains the element with the specified key.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This hash table contains the element with the specified key.
    /// \retval false
    ///   This hash table does not contain the element with the specified key.
    [[nodiscard]] auto contains(const key_type &key) const noexcept -> bool {
        return this->find(key) != this->end();
    }

    /// \brief
    ///   Check if this hash table contains the element with the specified key.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This hash table contains the element with the specified key.
    /// \retval false
    ///   This hash table does not contain the element with the specified key.
    template <typename K>
        requires(is_transparent_v<hasher> && is_transparent_v<key_equal>)
    [[nodiscard]] auto contains(const K &key) const noexcept -> bool {
        return this->find(key) != this->end();
    }

    /// \brief
    ///   Get number of buckets in this hash table.
    /// \return
    ///   Number of buckets in this hash table.
    [[nodiscard]] auto bucket_count() const noexcept -> size_type {
        return this->m_internal.template get<3>().capacity;
    }

    /// \brief
    ///   Get load factor of this hash table.
    /// \return
    ///   Load factor of this hash table.
    [[nodiscard]] auto load_factor() const noexcept -> float {
        return static_cast<float>(this->size()) / static_cast<float>(this->bucket_count());
    }

    /// \brief
    ///   Get maximum load factor of this hash table.
    /// \return
    ///   Maximum load factor of this hash table.
    [[nodiscard]] constexpr static auto max_load_factor() noexcept -> float {
        return 0.875f;
    }

    /// \brief
    ///   Rehash the hash table with the specified bucket count.
    /// \param bucket_count
    ///   New number of buckets in the hash table. This method will do nothing if the new bucket count is less than or
    ///   equal to the current bucket count.
    auto rehash(size_type bucket_count) noexcept -> void;

    /// \brief
    ///   Rehash the hash table to hold at least the specified number of elements.
    /// \param count
    ///   Number of elements that this hash table should hold.
    auto reserve(size_type count) noexcept -> void {
        this->rehash((count + 2) / 3);
    }

    /// \brief
    ///   Get hasher of this hash table.
    /// \return
    ///   Hasher of this hash table.
    [[nodiscard]] auto hash_function() const noexcept -> hasher {
        return hasher{this->m_internal.template get<1>()};
    }

    /// \brief
    ///   Get key equality comparison of this hash table.
    /// \return
    ///   Key equality comparison of this hash table.
    [[nodiscard]] auto key_eq() const noexcept -> key_equal {
        return this->m_internal.template get<2>();
    }

private:
    /// \brief
    ///   Get reference to key from the underlying value.
    /// \param value
    ///   The underlying value to get key from.
    /// \return
    ///   Key reference from the underlying value.
    template <typename K>
    static auto key_reference(K &&value) noexcept -> decltype(auto) {
        return std::forward<K>(value);
    }

    /// \brief
    ///   Get reference to key from the underlying value.
    /// \param value
    ///   The underlying value to get key from.
    /// \return
    ///   Key reference from the underlying value.
    static auto key_reference(value_type &value) noexcept -> key_type & {
        if constexpr (std::is_void_v<mapped_type>) {
            return value;
        } else if constexpr (!std::is_void_v<mapped_type>) {
            return value.first;
        }
    }

    /// \brief
    ///   Get reference to key from the underlying value.
    /// \param value
    ///   The underlying value to get key from.
    /// \return
    ///   Key reference from the underlying value.
    static auto key_reference(const value_type &value) noexcept -> const key_type & {
        if constexpr (std::is_void_v<mapped_type>) {
            return value;
        } else if constexpr (!std::is_void_v<mapped_type>) {
            return value.first;
        }
    }

    /// \brief
    ///   Prepare for insertion of a new element with the specified key.
    /// \tparam Key
    ///   Type of the new key to insert.
    /// \param key
    ///   The new key to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element will be
    ///   inserted. The boolean value indicates if the new element could be inserted.
    template <typename K>
    auto prepare_insertion(const K &key) -> std::pair<iterator, bool>;

    /// \brief
    ///   Find the element with the specified key.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
    auto find_key(K &&key) const noexcept -> iterator;

    /// \brief
    ///   Drop all deleted elements from this hash table without resizing buckets. All elements will be rehashed.
    auto drop_deleted() noexcept -> void;

private:
    /// \brief
    ///   Internal storage of the hash table.
    compressed_tuple<char_allocator, hasher, key_equal, storage_t> m_internal;
};

} // namespace onion::detail

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::hash_table(size_type             bucket_count,
                                                                              const hasher         &hash,
                                                                              const key_equal      &equal,
                                                                              const allocator_type &allocator)
    : m_internal{allocator, hash, equal, storage_t{}} {
    if (bucket_count == 0) [[unlikely]]
        return;

    size_type new_capacity = hash_table_normalize_capacity(bucket_count);
    new_capacity           = (std::max)(new_capacity, hash_table_next_capacity(0));

    char_allocator &alloc   = this->m_internal.template get<0>();
    storage_t      &storage = this->m_internal.template get<3>();

    hash_table_layout<value_type> layout{new_capacity};

    char *memory = char_allocator_traits::allocate(alloc, layout.allocate_size);

    storage.capacity = new_capacity;
    storage.states   = reinterpret_cast<hash_table_state *>(memory);
    storage.values   = reinterpret_cast<value_type *>(memory + layout.value_offset);

    std::memset(storage.states, static_cast<int>(hash_table_state::empty), new_capacity + hash_table_group_width);
    storage.states[new_capacity] = hash_table_state::sentinel;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::hash_table(const hash_table &other)
    : hash_table{other, other.m_internal.template get<0>()} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::hash_table(const hash_table     &other,
                                                                              const allocator_type &allocator)
    : hash_table{other.bucket_count(), other.m_internal.template get<1>(), other.m_internal.template get<2>(),
                 allocator} {
    const storage_t &other_storage = other.m_internal.template get<3>();
    if (other_storage.size == 0)
        return;

    allocator_type origin_alloc{this->m_internal.template get<0>()};
    hasher        &hash    = this->m_internal.template get<1>();
    storage_t     &storage = this->m_internal.template get<3>();

    const auto copy_element = [&](value_type *value) -> void {
        std::size_t hash_value = hash(key_reference(*value));
        std::size_t offset     = storage.find_first_non_full(hash_value);

        storage.set_state(offset, static_cast<std::uint8_t>(hash_value & 0x7F));
        allocator_traits::construct(origin_alloc, storage.values + offset, *value);
    };

    { // Copy elements.
        hash_table_state *states = other_storage.states;
        value_type       *values = other_storage.values;
        for (size_type remaining = other_storage.size; remaining != 0;) {
            auto group = hash_table_load_states(states);
            for (auto mask = hash_table_mask_full_slots(group); mask != 0; mask &= mask - 1) {
                int index = std::countr_zero(mask);
                copy_element(values + index);
                remaining -= 1;
            }

            states += hash_table_group_width;
            values += hash_table_group_width;
        }
    }

    storage.size = other_storage.size;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::hash_table(hash_table          &&other,
                                                                              const allocator_type &allocator)
    : hash_table{0, hasher{}, key_equal{}, allocator} {
    if constexpr (allocator_traits::is_always_equal::value) {
        this->m_internal.template get<3>() = std::move(other.m_internal.template get<3>());
        other.m_internal.template get<3>() = storage_t{};
    } else if (this->m_internal.template get<0>() == other.m_internal.template get<0>()) {
        this->m_internal.template get<3>() = std::move(other.m_internal.template get<3>());
        other.m_internal.template get<3>() = storage_t{};
    } else {
        storage_t &other_storage = other.m_internal.template get<3>();
        if (other_storage.size == 0)
            return;

        char_allocator &alloc   = this->m_internal.template get<0>();
        hasher         &hash    = this->m_internal.template get<1>();
        key_equal      &equal   = this->m_internal.template get<2>();
        storage_t      &storage = this->m_internal.template get<3>();

        hash_table_layout<value_type> layout{other_storage.capacity};

        char *memory = char_allocator_traits::allocate(alloc, layout.allocate_size);

        storage.capacity = other_storage.capacity;
        storage.size     = other_storage.size;
        storage.states   = reinterpret_cast<hash_table_state *>(memory);
        storage.values   = reinterpret_cast<value_type *>(memory + layout.value_offset);

        const auto move_element = [&](value_type *value) -> void {
            std::size_t hash_value = hash(key_reference(*value));
            std::size_t offset     = storage.find_first_non_full(hash_value);

            storage.set_state(offset, static_cast<std::uint8_t>(hash_value & 0x7F));
            allocator_traits::construct(allocator, storage.values + offset, std::move(*value));
        };

        { // Move elements.
            hash_table_state *states = other_storage.states;
            value_type       *values = other_storage.values;
            for (size_type remaining = other_storage.size; remaining != 0;) {
                auto group = hash_table_load_states(states);
                for (auto mask = hash_table_mask_full_slots(group); mask != 0; mask &= mask - 1) {
                    int index = std::countr_zero(mask);
                    move_element(values + index);
                    remaining -= 1;
                }

                states += hash_table_group_width;
                values += hash_table_group_width;
            }
        }
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::operator=(const hash_table &other)
    -> hash_table & {
    if (this == &other) [[unlikely]]
        return *this;

    allocator_type origin_alloc{this->m_internal.template get<0>()};
    storage_t     &storage = this->m_internal.template get<3>();
    if (storage.capacity != 0) {
        storage.destroy_elements(origin_alloc);
        storage.deallocate(this->m_internal.template get<0>());
        storage = storage_t{};
    }

    if constexpr (char_allocator_traits::propagate_on_container_copy_assignment::value) {
        this->m_internal.template get<0>() =
            char_allocator_traits::select_on_container_copy_construction(other.m_internal.template get<0>());
    }

    const storage_t &other_storage = other.m_internal.template get<3>();
    if (other_storage.size == 0)
        return *this;

    char_allocator &alloc = this->m_internal.template get<0>();
    hasher         &hash  = this->m_internal.template get<1>();

    hash_table_layout<value_type> layout{other_storage.capacity};

    char *memory = char_allocator_traits::allocate(alloc, layout.allocate_size);

    storage.capacity = other_storage.capacity;
    storage.size     = other_storage.size;
    storage.states   = reinterpret_cast<hash_table_state *>(memory);
    storage.values   = reinterpret_cast<value_type *>(memory + layout.value_offset);

    // Initialize states.
    std::memset(storage.states, static_cast<int>(hash_table_state::empty),
                other_storage.capacity + hash_table_group_width);
    storage.states[other_storage.capacity] = hash_table_state::sentinel;

    const auto copy_element = [&](value_type *value) -> void {
        std::size_t hash_value = hash(key_reference(*value));
        std::size_t offset     = storage.find_first_non_full(hash_value);

        storage.set_state(offset, static_cast<std::uint8_t>(hash_value & 0x7F));
        allocator_traits::construct(origin_alloc, storage.values + offset, *value);
    };

    { // Copy elements.
        hash_table_state *states = other_storage.states;
        value_type       *values = other_storage.values;
        for (size_type remaining = other_storage.size; remaining != 0;) {
            auto group = hash_table_load_states(states);
            for (auto mask = hash_table_mask_full_slots(group); mask != 0; mask &= mask - 1) {
                int index = std::countr_zero(mask);
                copy_element(values + index);
                remaining -= 1;
            }

            states += hash_table_group_width;
            values += hash_table_group_width;
        }
    }

    return *this;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::operator=(hash_table &&other) noexcept
    -> hash_table & {
    if (this == &other) [[unlikely]]
        return *this;

    storage_t &storage = this->m_internal.template get<3>();
    if (storage.capacity != 0) {
        allocator_type origin_alloc{this->m_internal.template get<0>()};
        storage.destroy_elements(origin_alloc);
        storage.deallocate(this->m_internal.template get<0>());
        storage = storage_t{};
    }

    this->m_internal                   = std::move(other.m_internal);
    other.m_internal.template get<3>() = storage_t{};

    return *this;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::clear() noexcept -> void {
    storage_t &storage = this->m_internal.template get<3>();
    if (storage.size == 0)
        return;

    // Destroy elements.
    allocator_type origin_alloc{this->m_internal.template get<0>()};
    storage.destroy_elements(origin_alloc);

    // Reset states to empty.
    std::memset(storage.states, static_cast<int>(hash_table_state::empty), storage.capacity + hash_table_group_width);
    storage.states[storage.capacity] = hash_table_state::sentinel;

    // Reset size.
    storage.has_deleted = 0;
    storage.size        = 0;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::insert(const value_type &value)
    -> std::pair<iterator, bool> {
    auto result = this->prepare_insertion(key_reference(value));

    if (result.second) {
        allocator_type origin_alloc{this->m_internal.template get<0>()};
        allocator_traits::construct(origin_alloc, result.first.m_value, value);
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::insert(value_type &&value)
    -> std::pair<iterator, bool> {
    auto result = this->prepare_insertion(key_reference(value));

    if (result.second) {
        allocator_type origin_alloc{this->m_internal.template get<0>()};
        allocator_traits::construct(origin_alloc, result.first.m_value, value);
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::insert(InputIt first, InputIt last) -> void {
    if constexpr (std::forward_iterator<InputIt>) {
        auto count = static_cast<size_type>(std::distance(first, last)) + this->size();
        this->rehash(count + (count + 2) / 3);
    }

    for (; first != last; ++first)
        this->emplace(*first);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::insert(std::initializer_list<value_type> list)
    -> void {
    this->insert(list.begin(), list.end());
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::rehash(size_type bucket_count) noexcept
    -> void {
    std::size_t new_capacity = hash_table_normalize_capacity(bucket_count);
    storage_t  &storage      = this->m_internal.template get<3>();

    // Do nothing if current capacity is greater.
    if (new_capacity <= storage.capacity) [[unlikely]]
        return;

    new_capacity = (std::max)(new_capacity, hash_table_next_capacity(storage.capacity));

    char_allocator &alloc = this->m_internal.template get<0>();
    hasher         &hash  = this->m_internal.template get<1>();

    allocator_type origin_alloc{alloc};

    const auto move_element = [&](value_type *value) -> void {
        std::size_t hash_value = hash(key_reference(*value));
        std::size_t offset     = storage.find_first_non_full(hash_value);

        storage.set_state(offset, static_cast<std::uint8_t>(hash_value & 0x7F));
        allocator_traits::construct(origin_alloc, storage.values + offset, std::move(*value));
        allocator_traits::destroy(origin_alloc, value);
    };

    size_type         old_capacity   = storage.capacity;
    auto             *old_array      = static_cast<char *>(storage.backing_array());
    hash_table_state *old_states     = storage.states;
    value_type       *old_values     = storage.values;
    size_type         old_alloc_size = storage.allocated_size();

    hash_table_layout<value_type> layout{new_capacity};

    char *memory     = char_allocator_traits::allocate(alloc, layout.allocate_size);
    auto *new_states = reinterpret_cast<hash_table_state *>(memory);
    auto *new_values = reinterpret_cast<value_type *>(memory + layout.value_offset);

    storage.capacity    = new_capacity;
    storage.has_deleted = 0;
    storage.states      = new_states;
    storage.values      = new_values;

    // Reset states.
    std::memset(storage.states, static_cast<int>(hash_table_state::empty), new_capacity + hash_table_group_width);
    storage.states[new_capacity] = hash_table_state::sentinel;

    { // Move elements.
        hash_table_state *states = old_states;
        value_type       *values = old_values;
        for (size_type remaining = storage.size; remaining != 0;) {
            auto group = hash_table_load_states(states);
            for (auto mask = hash_table_mask_full_slots(group); mask != 0; mask &= mask - 1) {
                int index = std::countr_zero(mask);
                move_element(values + index);
                remaining -= 1;
            }

            states += hash_table_group_width;
            values += hash_table_group_width;
        }
    }

    // Deallocate old memory.
    if (old_capacity != 0)
        char_allocator_traits::deallocate(alloc, old_array, old_alloc_size);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::prepare_insertion(const K &key)
    -> std::pair<iterator, bool> {
    hasher    &hash    = this->m_internal.template get<1>();
    key_equal &equal   = this->m_internal.template get<2>();
    storage_t &storage = this->m_internal.template get<3>();

    std::size_t h  = hash(key);
    std::size_t h1 = h >> 7;
    std::size_t h2 = h & 0x7F;

#if (defined(__clang__) || defined(__GNUC__))
    __builtin_prefetch(storage.states, 0, 1);
#endif

    auto seq = hash_table_probe_sequence{h1, storage.capacity};
    while (true) {
        // It is safe to do this for empty hash table.
        auto states = hash_table_load_states(storage.states + seq.offset());
        for (auto mask = hash_table_match_h2(states, static_cast<std::uint8_t>(h2)); mask != 0; mask &= (mask - 1)) {
            std::size_t index = seq.offset(std::countr_zero(mask));
            if (equal(key_reference(storage.values[index]), key)) [[likely]]
                return {iterator{storage.states + index, storage.values + index}, false};
        }

        std::uint16_t empty_mask = hash_table_mask_empty_slots(states);
        if (empty_mask != 0) [[likely]] {
            // No available space for new element. Reserve memory.
            if (storage.size + 1 > storage.capacity - (storage.capacity / 8)) [[unlikely]] {
                this->rehash(hash_table_next_capacity(storage.capacity));

                std::size_t offset = storage.find_first_non_full(h);
                storage.set_state(offset, static_cast<std::uint8_t>(h2));
                storage.size += 1;

                return {iterator{storage.states + offset, storage.values + offset}, true};
            } else if (storage.has_deleted != 0) [[unlikely]] { // Drop deleted elements.
                if (storage.size + 1 < storage.capacity - (storage.capacity / 4))
                    this->drop_deleted();
                else
                    this->rehash(hash_table_next_capacity(storage.capacity));

                std::size_t offset = storage.find_first_non_full(h);
                storage.set_state(offset, static_cast<std::uint8_t>(h2));
                storage.size += 1;

                return {iterator{storage.states + offset, storage.values + offset}, true};
            }

            std::size_t offset = seq.offset(std::countr_zero(empty_mask));
            storage.set_state(offset, static_cast<std::uint8_t>(h2));
            storage.size += 1;

            return {iterator{storage.states + offset, storage.values + offset}, true};
        }

        seq.next();
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::find_key(K &&key) const noexcept -> iterator {
    const hasher    &hash    = this->m_internal.template get<1>();
    const key_equal &equal   = this->m_internal.template get<2>();
    const storage_t &storage = this->m_internal.template get<3>();

    std::size_t h  = hash(key);
    std::size_t h1 = h >> 7;
    std::size_t h2 = h & 0x7F;

#if (defined(__clang__) || defined(__GNUC__))
    __builtin_prefetch(storage.states, 0, 1);
#endif

    hash_table_probe_sequence seq{h1, storage.capacity};
    while (true) {
        // It is safe to do this for empty hash table.
        auto states = hash_table_load_states(storage.states + seq.offset());
        for (auto mask = hash_table_match_h2(states, static_cast<std::uint8_t>(h2)); mask != 0; mask &= (mask - 1)) {
            std::size_t index = seq.offset(std::countr_zero(mask));
            if (equal(key_reference(storage.values[index]), key)) [[likely]]
                return {storage.states + index, storage.values + index};
        }

        if (hash_table_mask_empty_slots(states) != 0) [[likely]]
            return {nullptr, nullptr};

        seq.next();
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto onion::detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>::drop_deleted() noexcept -> void {
    hasher    &hash    = this->m_internal.template get<1>();
    storage_t &storage = this->m_internal.template get<3>();

    // Marks that there is no deleted node any more.
    storage.has_deleted = 0;

    // Convert deleted states to empty and full states to deleted. We do not reinitialize them directly because we still
    // need them to iterator over elements.
    for (auto *states = storage.states; states < storage.states + storage.capacity; states += hash_table_group_width) {
        auto group  = hash_table_load_states(states);
        auto result = hash_table_empty_states_and_convert_full_to_deleted(group);
        hash_table_store_states(result, states);
    }

#if defined(__clang__) || defined(__GNUC__)
    // Copy the wrap-around sentinel state.
    __builtin_memcpy(storage.states + storage.capacity + 1, storage.states, hash_table_group_width - 1);
#else
    // Copy the wrap-around sentinel state.
    std::memcpy(storage.states + storage.capacity + 1, storage.states, hash_table_group_width - 1);
#endif
    storage.states[storage.capacity] = hash_table_state::sentinel;

    allocator_type origin_alloc{this->m_internal.template get<0>()};

    value_type *temp_value = nullptr;

    hash_table_state *state     = storage.states;
    hash_table_state *state_end = storage.states + storage.capacity;
    value_type       *value     = storage.values;

    const auto find_empty_slot = [&storage](size_type first, size_type last) -> size_type {
        hash_table_state *i   = storage.states + first;
        hash_table_state *end = storage.states + last;
        for (; i != end; ++i) [[likely]] {
            if (*i == hash_table_state::empty)
                return static_cast<size_type>(i - storage.states);
        }
        return last;
    };

    while (state != state_end) {
        if (*state == hash_table_state::empty) {
            temp_value = value;
            ++state, ++value;
            continue;
        }

        if (*state != hash_table_state::deleted) {
            ++state, ++value;
            continue;
        }

        auto i = static_cast<size_type>(state - storage.states);

        size_type h  = hash(key_reference(*value));
        size_type h2 = h & 0x7F;

        size_type offset       = storage.find_first_non_full(h);
        size_type probe_offset = hash_table_probe_sequence{h >> 7, storage.capacity}.offset();

        const auto probe_index = [&storage, probe_offset](size_type position) -> size_type {
            return ((position - probe_offset) & storage.capacity) / hash_table_group_width;
        };

        // No need to move this element.
        if (probe_index(offset) == probe_index(i)) [[likely]] {
            storage.set_state(i, static_cast<std::uint8_t>(h2));
            ++state, ++value;
            continue;
        }

        // Move the element.
        if (storage.states[offset] == hash_table_state::empty) {
            storage.set_state(offset, static_cast<std::uint8_t>(h2));
            allocator_traits::construct(origin_alloc, storage.values + offset, std::move(*value));
            allocator_traits::destroy(origin_alloc, value);
            storage.set_state(i, hash_table_state::empty);

            temp_value = value;

            ++state, ++value;
        } else {
            storage.set_state(offset, static_cast<std::uint8_t>(h2));

            if (temp_value == nullptr) [[unlikely]] {
                size_type empty_index = find_empty_slot(i + 1, storage.capacity);
                // empty_index should always be valid.
                temp_value = storage.values + empty_index;
            }

            allocator_traits::construct(origin_alloc, temp_value, std::move(storage.values[offset]));
            allocator_traits::destroy(origin_alloc, storage.values + offset);
            allocator_traits::construct(origin_alloc, storage.values + offset, std::move(*value));
            allocator_traits::destroy(origin_alloc, value);
            allocator_traits::construct(origin_alloc, value, std::move(*temp_value));
            allocator_traits::destroy(origin_alloc, temp_value);
        }
    }
}

namespace onion {

/// \class unordered_flat_set
/// \brief
///   Swiss-Table flat hash set.
template <typename Key,
          typename Hash      = onion::hash<Key>,
          typename KeyEqual  = onion::equal_to<>,
          typename Allocator = std::allocator<Key>>
class unordered_flat_set : private detail::hash_table<Key, void, Hash, KeyEqual, Allocator> {
private:
    using super = detail::hash_table<Key, void, Hash, KeyEqual, Allocator>;

public:
    using key_type        = typename super::key_type;
    using value_type      = typename super::value_type;
    using size_type       = typename super::size_type;
    using difference_type = typename super::difference_type;
    using hasher          = typename super::hasher;
    using key_equal       = typename super::key_equal;
    using allocator_type  = typename super::allocator_type;
    using reference       = typename super::reference;
    using const_reference = typename super::const_reference;
    using pointer         = typename super::pointer;
    using const_pointer   = typename super::const_pointer;
    using iterator        = typename super::iterator;
    using const_iterator  = typename super::const_iterator;

    /// \brief
    ///   Create an empty unordered flat set.
    unordered_flat_set() noexcept(std::conjunction_v<std::is_nothrow_default_constructible<allocator_type>,
                                                     std::is_nothrow_default_constructible<hasher>,
                                                     std::is_nothrow_default_constructible<key_equal>>) = default;

    /// \brief
    ///   Create an empty unordered flat set with the specified bucket count.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    explicit unordered_flat_set(size_type             bucket_count,
                                const hasher         &hash      = hasher{},
                                const key_equal      &equal     = key_equal{},
                                const allocator_type &allocator = allocator_type{})
        : super{bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an unordered flat set with the specified bucket count and allocator.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_set{bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an unordered flat set with the specified bucket count, hash function and allocator.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param hash
    ///   Hash function to use.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(size_type bucket_count, const hasher &hash, const allocator_type &allocator)
        : unordered_flat_set{bucket_count, hash, key_equal{}, allocator} {}

    /// \brief
    ///   Create an empty unordered flat set with the specified allocator.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    explicit unordered_flat_set(const allocator_type &allocator)
        : unordered_flat_set{0, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an unordered flat set with a range of elements.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    template <std::input_iterator InputIt>
    unordered_flat_set(InputIt               first,
                       InputIt               last,
                       size_type             bucket_count = 0,
                       const hasher         &hash         = hasher{},
                       const key_equal      &equal        = key_equal{},
                       const allocator_type &allocator    = allocator_type{})
        : super{first, last, bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an unordered flat set with a range of elements, the specified bucket count and allocator.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    template <std::input_iterator InputIt>
    unordered_flat_set(InputIt first, InputIt last, size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_set{first, last, bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an unordered flat set with a range of elements, the specified bucket count, hasher and allocator.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param hash
    ///   Hash function to use.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    template <std::input_iterator InputIt>
    unordered_flat_set(InputIt               first,
                       InputIt               last,
                       size_type             bucket_count,
                       const hasher         &hash,
                       const allocator_type &allocator)
        : unordered_flat_set{first, last, bucket_count, hash, key_equal{}, allocator} {}

    /// \brief
    ///   Copy constructor of \c unordered_flat_set.
    /// \param other
    ///   The \c unordered_flat_set to copy from.
    unordered_flat_set(const unordered_flat_set &other) = default;

    /// \brief
    ///   Copy constructor of \c unordered_flat_set with a different allocator.
    /// \param other
    ///   The \c unordered_flat_set to copy from.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(const unordered_flat_set &other, const allocator_type &allocator) : super{other, allocator} {}

    /// \brief
    ///   Move constructor of \c unordered_flat_set.
    /// \param other
    ///   The \c unordered_flat_set to move from.
    unordered_flat_set(unordered_flat_set &&other) noexcept = default;

    /// \brief
    ///   Move constructor of \c unordered_flat_set with a different allocator.
    /// \param other
    ///   The \c unordered_flat_set to move from.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(unordered_flat_set &&other, const allocator_type &allocator) noexcept
        : super{static_cast<super &&>(other), allocator} {}

    /// \brief
    ///   Create an unordered flat set with the specified initializer list.
    /// \param list
    ///   Initializer list to create the unordered flat set with.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(std::initializer_list<value_type> list,
                       size_type                         bucket_count = 0,
                       const hasher                     &hash         = hasher{},
                       const key_equal                  &equal        = key_equal{},
                       const allocator_type             &allocator    = allocator_type{})
        : super{list.begin(), list.end(), bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an unordered flat set with the specified initializer list, bucket count and allocator.
    /// \param list
    ///   Initializer list to create the unordered flat set with.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat set.
    /// \param allocator
    ///   Allocator for this unordered flat set.
    unordered_flat_set(std::initializer_list<value_type> list, size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_set{list, bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Destroy this unordered flat set.
    ~unordered_flat_set() = default;

    /// \brief
    ///   Copy assignment operator of \c unordered_flat_set.
    /// \param other
    ///   The \c unordered_flat_set to copy from.
    /// \return
    ///   Reference to this unordered flat set.
    auto operator=(const unordered_flat_set &other) -> unordered_flat_set & = default;

    /// \brief
    ///   Move assignment operator of \c unordered_flat_set.
    /// \param[inout] other
    ///   The \c unordered_flat_set to move from. The moved \c unordered_flat_set will be in a valid but unspecified
    ///   state.
    /// \return
    ///   Reference to this unordered flat set.
    auto operator=(unordered_flat_set &&other) noexcept -> unordered_flat_set & = default;

    /// \brief
    ///   Get allocator of this unordered flat set.
    /// \return
    ///   Allocator of this unordered flat set.
    [[nodiscard]] auto get_allocator() const noexcept -> allocator_type {
        return this->super::get_allocator();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat set.
    /// \return
    ///   Iterator to the first element in this unordered flat set.
    [[nodiscard]] auto begin() noexcept -> iterator {
        return this->super::begin();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat set.
    /// \return
    ///   Iterator to the first element in this unordered flat set.
    [[nodiscard]] auto begin() const noexcept -> const_iterator {
        return this->super::begin();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat set.
    /// \return
    ///   Iterator to the first element in this unordered flat set.
    [[nodiscard]] auto cbegin() const noexcept -> const_iterator {
        return this->super::cbegin();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this unordered flat set.
    /// \return
    ///   Iterator to the place after the last element in this unordered flat set.
    [[nodiscard]] auto end() noexcept -> iterator {
        return this->super::end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this unordered flat set.
    /// \return
    ///   Iterator to the place after the last element in this unordered flat set.
    [[nodiscard]] auto end() const noexcept -> const_iterator {
        return this->super::end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this unordered flat set.
    /// \return
    ///   Iterator to the place after the last element in this unordered flat set.
    [[nodiscard]] auto cend() const noexcept -> const_iterator {
        return this->super::cend();
    }

    /// \brief
    ///   Checks if this unordered flat set is empty.
    /// \retval true
    ///   This unordered flat set is empty.
    /// \retval false
    ///   This unordered flat set is not empty.
    [[nodiscard]] auto empty() const noexcept -> bool {
        return this->super::empty();
    }

    /// \brief
    ///   Get number of elements in this unordered flat set.
    /// \return
    ///   Number of elements in this unordered flat set.
    [[nodiscard]] auto size() const noexcept -> size_type {
        return this->super::size();
    }

    /// \brief
    ///   Erases all elements from this unordered flat set.
    auto clear() noexcept -> void {
        this->super::clear();
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat set if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(const value_type &value) -> std::pair<iterator, bool> {
        return this->super::insert(value);
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat set if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(value_type &&value) -> std::pair<iterator, bool> {
        return this->super::insert(std::move(value));
    }

    /// \brief
    ///   Try to insert a range of elements into this unordered flat set if the keys do not exist.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be inserted.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be inserted.
    template <std::input_iterator InputIt>
    auto insert(InputIt first, InputIt last) -> void {
        this->super::insert(first, last);
    }

    /// \brief
    ///   Try to insert a new element into this unordered hash set if the key does not exist.
    /// \tparam K
    ///   Type of the new value to insert.
    /// \param value
    ///   The new value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto insert(K &&key) -> std::pair<iterator, bool> {
        return this->super::insert(std::forward<K>(key));
    }

    /// \brief
    ///   Try to insert a range of elements into this unordered flat set if the keys do not exist.
    /// \tparam R
    ///   Type of input range.
    /// \param range
    ///   Range of elements to be inserted.
    template <typename R>
    auto insert_range(R &&range) -> void {
        return this->super::insert_range(std::forward<R>(range));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat set if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
        requires(std::is_constructible_v<value_type, Args && ...>)
    auto emplace(Args &&...args) -> std::pair<iterator, bool> {
        return this->super::emplace(std::forward<Args>(args)...);
    }

    /// \brief
    ///   Remove specified elements from this unordered flat set. We do not return iterator to the next element because
    ///   it is slow to find the next element.
    /// \param position
    ///   Iterator to the element to be removed.
    auto erase(const_iterator position) noexcept -> void {
        this->super::erase(position);
    }

    /// \brief
    ///   Remove elements between the specified range from this unordered flat set.
    /// \param first
    ///   Iterator to the first element to be removed.
    /// \param last
    ///   Iterator to the placeholder after the last element to be removed.
    /// \return
    ///   Iterator to the element after the last removed element.
    auto erase(const_iterator first, const_iterator last) noexcept -> iterator {
        return this->super::erase(first, last);
    }

    /// \brief
    ///   Remove all elements with the specified key from this unordered flat set.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    auto erase(const key_type &key) noexcept -> size_type {
        return this->super::erase(key);
    }

    /// \brief
    ///   Remove all elements with the specified key from this unordered flat set.
    /// \tparam K
    ///   Type of the key to be removed.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto erase(K &&key) noexcept -> size_type {
        return this->super::erase(std::forward<K>(key));
    }

    /// \brief
    ///   Get number of elements with the specified key in this unordered flat set.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    [[nodiscard]] auto count(const key_type &key) const noexcept -> size_type {
        return this->super::count(key);
    }

    /// \brief
    ///   Get number of elements with the specified key in this unordered flat set.
    /// \tparam K
    ///   Type of the key to count.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto count(K &&key) const noexcept -> size_type {
        return this->super::count(std::forward<K>(key));
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) noexcept -> iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) const noexcept -> const_iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto find(K &&key) noexcept -> iterator {
        return this->super::find(std::forward<K>(key));
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto find(K &&key) const noexcept -> const_iterator {
        return this->super::find(std::forward<K>(key));
    }

    /// \brief
    ///   Check if this unordered flat set contains the element with the specified key.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This unordered flat set contains the element with the specified key.
    /// \retval false
    ///   This unordered flat set does not contain the element with the specified key.
    [[nodiscard]] auto contains(const key_type &key) const noexcept -> bool {
        return this->super::contains(key);
    }

    /// \brief
    ///   Check if this unordered flat set contains the element with the specified key.
    /// \tparam K
    ///   Type of the key to check.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This unordered flat set contains the element with the specified key.
    /// \retval false
    ///   This unordered flat set does not contain the element with the specified key.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto contains(K &&key) const noexcept -> bool {
        return this->super::contains(std::forward<K>(key));
    }

    /// \brief
    ///   Get load factor of this unordered flat set.
    /// \return
    ///   Load factor of this unordered flat set.
    [[nodiscard]] auto load_factor() const noexcept -> float {
        return this->super::load_factor();
    }

    /// \brief
    ///   Get maximum load factor of this unordered flat set.
    /// \return
    ///   Maximum load factor of this unordered flat set.
    [[nodiscard]] static constexpr auto max_load_factor() noexcept -> float {
        return super::max_load_factor();
    }

    /// \brief
    ///   Rehash this unordered flat set with the specified bucket count.
    /// \param bucket_count
    ///   New number of buckets in this unordered flat set. This method will do nothing if the new bucket count is less
    ///   than or equal to the current bucket count.
    auto rehash(size_type bucket_count) -> void {
        this->super::rehash(bucket_count);
    }

    /// \brief
    ///   Rehash this unordered flat set to hold at least the specified number of elements.
    /// \param count
    ///   Number of elements that this unordered flat set should hold.
    auto reserve(size_type count) -> void {
        this->super::reserve(count);
    }

    /// \brief
    ///   Get hasher of this unordered flat set.
    /// \return
    ///   Hasher of this unordered flat set.
    [[nodiscard]] auto hash_function() const noexcept -> hasher {
        return this->super::hash_function();
    }

    /// \brief
    ///   Get key equality comparison of this unordered flat set.
    /// \return
    ///   Key equality comparison of this unordered flat set.
    [[nodiscard]] auto key_eq() const noexcept -> key_equal {
        return this->super::key_eq();
    }
};

/// \class unordered_flat_map
/// \brief
///   Swiss-Table flat hash map.
template <typename Key,
          typename Mapped,
          typename Hash      = onion::hash<Key>,
          typename KeyEqual  = onion::equal_to<>,
          typename Allocator = std::allocator<std::pair<Key, Mapped>>>
class unordered_flat_map : private detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator> {
private:
    using super = detail::hash_table<Key, Mapped, Hash, KeyEqual, Allocator>;
    static_assert(!std::is_void_v<Mapped>, "Mapped type should not be void.");

public:
    using key_type        = typename super::key_type;
    using mapped_type     = typename super::mapped_type;
    using value_type      = typename super::value_type;
    using size_type       = typename super::size_type;
    using difference_type = typename super::difference_type;
    using hasher          = typename super::hasher;
    using key_equal       = typename super::key_equal;
    using allocator_type  = typename super::allocator_type;
    using reference       = typename super::reference;
    using const_reference = typename super::const_reference;
    using pointer         = typename super::pointer;
    using const_pointer   = typename super::const_pointer;
    using iterator        = typename super::iterator;
    using const_iterator  = typename super::const_iterator;

    /// \brief
    ///   Create an empty \c unordered_flat_map.
    unordered_flat_map() noexcept(std::conjunction_v<std::is_nothrow_default_constructible<allocator_type>,
                                                     std::is_nothrow_default_constructible<hasher>,
                                                     std::is_nothrow_default_constructible<key_equal>>) = default;

    /// \brief
    ///   Create an empty \c unordered_flat_map with the specified bucket size, hasher, key equality comparison and
    ///   allocator.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    explicit unordered_flat_map(size_type             bucket_count,
                                const hasher         &hash      = hasher{},
                                const key_equal      &equal     = key_equal{},
                                const allocator_type &allocator = allocator_type{})
        : super{bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an empty \c unordered_flat_map with the specified bucket size and allocator.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_map{bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an empty \c unordered_flat_map with the specified bucket size, hasher and allocator.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(size_type bucket_count, const hasher &hash, const allocator_type &allocator)
        : unordered_flat_map{bucket_count, hash, key_equal{}, allocator} {}

    /// \brief
    ///   Create an empty \c unordered_flat_map with the specified allocator.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    explicit unordered_flat_map(const allocator_type &allocator)
        : unordered_flat_map{0, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified range, bucket count, hasher, key equality comparison and
    ///   allocator.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be copied.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    template <std::input_iterator InputIt>
    unordered_flat_map(InputIt               first,
                       InputIt               last,
                       size_type             bucket_count = 0,
                       const hasher         &hash         = hasher{},
                       const key_equal      &equal        = key_equal{},
                       const allocator_type &allocator    = allocator_type{})
        : super{first, last, bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified range, bucket count and allocator.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be copied.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    template <std::input_iterator InputIt>
    unordered_flat_map(InputIt first, InputIt last, size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_map{first, last, bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified range, bucket count, hasher and allocator.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be copied.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    template <std::input_iterator InputIt>
    unordered_flat_map(InputIt               first,
                       InputIt               last,
                       size_type             bucket_count,
                       const hasher         &hash,
                       const allocator_type &allocator)
        : unordered_flat_map{first, last, bucket_count, hash, key_equal{}, allocator} {}

    /// \brief
    ///   Copy construct of \c unordered_flat_map.
    /// \param other
    ///   The other \c unordered_flat_map to copy from.
    unordered_flat_map(const unordered_flat_map &other) = default;

    /// \brief
    ///   Copy construct of \c unordered_flat_map with the specified allocator.
    /// \param other
    ///   The other \c unordered_flat_map to copy from.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(const unordered_flat_map &other, const allocator_type &allocator) : super{other, allocator} {}

    /// \brief
    ///   Move construct of \c unordered_flat_map.
    /// \param other
    ///   The other \c unordered_flat_map to move from. The moved unordered flat map will be in a valid but
    ///   unspecified state.
    unordered_flat_map(unordered_flat_map &&other) noexcept = default;

    /// \brief
    ///   Move construct of \c unordered_flat_map with the specified allocator.
    /// \param other
    ///   The other \c unordered_flat_map to move from. The moved unordered flat map will be in a valid but
    ///   unspecified state.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(unordered_flat_map &&other, const allocator_type &allocator)
        : super{std::move(other), allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified initializer list of objects, bucket count, hasher, key
    ///   equality comparison and allocator.
    /// \param list
    ///   Initializer list of objects to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param equal
    ///   Key equality comparison to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(std::initializer_list<value_type> list,
                       size_type                         bucket_count = 0,
                       const hasher                     &hash         = hasher{},
                       const key_equal                  &equal        = key_equal{},
                       const allocator_type             &allocator    = allocator_type{})
        : unordered_flat_map{list.begin(), list.end(), bucket_count, hash, equal, allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified initializer list of objects, bucket count and allocator.
    /// \param list
    ///   Initializer list of objects to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(std::initializer_list<value_type> list, size_type bucket_count, const allocator_type &allocator)
        : unordered_flat_map{list, bucket_count, hasher{}, key_equal{}, allocator} {}

    /// \brief
    ///   Create an \c unordered_flat_map with the specified initializer list of objects, bucket count, hasher and
    ///   allocator.
    /// \param list
    ///   Initializer list of objects to be copied.
    /// \param bucket_count
    ///   Initial number of buckets in this unordered flat map.
    /// \param hash
    ///   Hash function to use.
    /// \param allocator
    ///   Allocator for this unordered flat map.
    unordered_flat_map(std::initializer_list<value_type> list,
                       size_type                         bucket_count,
                       const hasher                     &hash,
                       const allocator_type             &allocator)
        : unordered_flat_map{list, bucket_count, hash, key_equal{}, allocator} {}

    /// \brief
    ///   Destroy this unordered flat map.
    ~unordered_flat_map() = default;

    /// \brief
    ///   Copy assignment of \c unordered_flat_map.
    /// \param other
    ///   The other \c unordered_flat_map to copy from.
    /// \return
    ///   Reference to this unordered flat map.
    auto operator=(const unordered_flat_map &other) -> unordered_flat_map & = default;

    /// \brief
    ///   Move assignment of \c unordered_flat_map.
    /// \param other
    ///   The other \c unordered_flat_map to move from. The moved unordered flat map will be in a valid but
    ///   unspecified state.
    /// \return
    ///   Reference to this unordered flat map.
    auto operator=(unordered_flat_map &&other) noexcept -> unordered_flat_map & = default;

    /// \brief
    ///   Get allocator of this unordered flat map.
    /// \return
    ///   Allocator of this unordered flat map.
    [[nodiscard]] auto get_allocator() const noexcept -> allocator_type {
        return this->super::get_allocator();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat map.
    /// \return
    ///   Iterator to the first element in this unordered flat map.
    [[nodiscard]] auto begin() noexcept -> iterator {
        return this->super::begin();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat map.
    /// \return
    ///   Iterator to the first element in this unordered flat map.
    [[nodiscard]] auto begin() const noexcept -> const_iterator {
        return this->super::begin();
    }

    /// \brief
    ///   Get iterator to the first element in this unordered flat map.
    /// \return
    ///   Iterator to the first element in this unordered flat map.
    [[nodiscard]] auto cbegin() const noexcept -> const_iterator {
        return this->super::cbegin();
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this unordered flat map.
    /// \return
    ///   Iterator to the placeholder after the last element in this unordered flat map.
    [[nodiscard]] auto end() noexcept -> iterator {
        return this->super::end();
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this unordered flat map.
    /// \return
    ///   Iterator to the placeholder after the last element in this unordered flat map.
    [[nodiscard]] auto end() const noexcept -> const_iterator {
        return this->super::end();
    }

    /// \brief
    ///   Get iterator to the placeholder after the last element in this unordered flat map.
    /// \return
    ///   Iterator to the placeholder after the last element in this unordered flat map.
    [[nodiscard]] auto cend() const noexcept -> const_iterator {
        return this->super::cend();
    }

    /// \brief
    ///   Checks if this unordered flat map is empty.
    /// \retval true
    ///   This unordered flat map is empty.
    /// \retval false
    ///   This unordered flat map is not empty.
    [[nodiscard]] auto empty() const noexcept -> bool {
        return this->super::empty();
    }

    /// \brief
    ///   Get number of elements in this unordered flat map.
    /// \return
    ///   Number of elements in this unordered flat map.
    [[nodiscard]] auto size() const noexcept -> size_type {
        return this->super::size();
    }

    /// \brief
    ///   Erase all elements in this unordered flat map.
    auto clear() noexcept -> void {
        this->super::clear();
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(const value_type &value) -> std::pair<iterator, bool> {
        return this->super::insert(value);
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    auto insert(value_type &&value) -> std::pair<iterator, bool> {
        return this->super::insert(std::move(value));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \tparam P
    ///   Type of the new element to insert.
    /// \param value
    ///   The new element to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename P>
        requires(std::is_constructible_v<value_type, P &&>)
    auto insert(P &&value) -> std::pair<iterator, bool> {
        return this->super::emplace(std::forward<P>(value));
    }

    /// \brief
    ///   Try to insert a range of elements into this unordered flat map if the keys do not exist.
    /// \tparam InputIt
    ///   Type of input iterator.
    /// \param first
    ///   Iterator to the first element in the range to be copied.
    /// \param last
    ///   Iterator to the placeholder after the last element in the range to be copied.
    template <std::input_iterator InputIt>
    auto insert(InputIt first, InputIt last) -> void {
        this->super::insert(first, last);
    }

    /// \brief
    ///   Try to insert a range of elements into this unordered flat map if the keys do not exist.
    /// \param list
    ///   Initializer list of elements to be inserted.
    auto insert(std::initializer_list<value_type> list) -> void {
        this->super::insert(list);
    }

    /// \brief
    ///   Try to insert a range of elements into this unordered flat map if the keys do not exist.
    /// \tparam R
    ///   Type of input range.
    /// \param range
    ///   Range of elements to be inserted.
    template <typename R>
    auto insert_range(R &&range) -> void {
        this->super::insert_range(std::forward<R>(range));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist. Otherwise, replace the
    ///   existing element with the new one.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The key of the new element.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename M>
    auto insert_or_assign(const key_type &key, M &&value) -> std::pair<iterator, bool> {
        return this->super::insert_or_assign(key, std::forward<M>(value));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist. Otherwise, replace the
    ///   existing element with the new one.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The key of the new element.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename M>
    auto insert_or_assign(key_type &&key, M &&value) -> std::pair<iterator, bool> {
        return this->super::insert_or_assign(std::move(key), std::forward<M>(value));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist. Otherwise, replace the
    ///   existing element with the new one.
    /// \tparam K
    ///   Type of the new key to insert.
    /// \tparam M
    ///   Type of the new mapped value to insert.
    /// \param key
    ///   The new key to insert.
    /// \param value
    ///   The new mapped value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K, typename M>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto insert_or_assign(K &&key, M &&value) -> std::pair<iterator, bool> {
        return this->super::insert_or_assign(std::forward<K>(key), std::forward<M>(value));
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
        requires(std::constructible_from<value_type, Args && ...>)
    auto emplace(Args &&...args) -> std::pair<iterator, bool> {
        return this->super::emplace(std::forward<Args>(args)...);
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new mapped value.
    /// \param key
    ///   Key of the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
        requires(std::is_constructible_v<mapped_type, Args && ...>)
    auto try_emplace(const key_type &key, Args &&...args) -> std::pair<iterator, bool> {
        return this->super::try_emplace(key, std::forward<Args>(args)...);
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new mapped value.
    /// \param key
    ///   Key of the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename... Args>
        requires(std::is_constructible_v<mapped_type, Args && ...>)
    auto try_emplace(key_type &&key, Args &&...args) -> std::pair<iterator, bool> {
        return this->super::try_emplace(std::move(key), std::forward<Args>(args)...);
    }

    /// \brief
    ///   Try to insert a new element into this unordered flat map if the key does not exist.
    /// \tparam K
    ///   Type of the new key to insert.
    /// \tparam Args
    ///   Types of arguments to construct the new mapped value.
    /// \param key
    ///   Key of the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the position where the new element is inserted.
    ///   The boolean value indicates if the new element is inserted.
    template <typename K, typename... Args>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto try_emplace(K &&key, Args &&...args) -> std::pair<iterator, bool> {
        return this->super::try_emplace(std::forward<K>(key), std::forward<Args>(args)...);
    }

    /// \brief
    ///   Remove specified elements from this unordered flat map. We do not return iterator to the next element because
    ///   it is slow to find the next element.
    /// \param position
    ///   Iterator to the element to be removed.
    auto erase(const_iterator position) -> void {
        this->super::erase(position);
    }

    /// \brief
    ///   Remove elements between the specified range from this unordered flat map.
    /// \param first
    ///   Iterator to the first element to be removed.
    /// \param last
    ///   Iterator to the placeholder after the last element to be removed.
    /// \return
    ///   Iterator to the element after the last removed element.
    auto erase(const_iterator first, const_iterator last) -> const_iterator {
        return this->super::erase(first, last);
    }

    /// \brief
    ///   Remove all elements with the specified key from this unordered flat map.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    auto erase(const key_type &key) -> size_type {
        return this->super::erase(key);
    }

    /// \brief
    ///   Remove all elements with the specified key from this unordered flat map.
    /// \tparam K
    ///   Type of the key to be removed.
    /// \param key
    ///   The key of elements to be removed.
    /// \return
    ///   Number of elements removed. This value will be either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto erase(const K &key) -> size_type {
        return this->super::erase(key);
    }

    /// \brief
    ///   Get the element with the specified key with bound check.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    /// \throws std::out_of_range
    ///   Thrown if there is no element with the specified key exists.
    [[nodiscard]] auto at(const key_type &key) -> mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end()) [[unlikely]]
            throw std::out_of_range{"unordered_flat_map::at"};
        return iter->second;
    }

    /// \brief
    ///   Get the element with the specified key with bound check.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    /// \throws std::out_of_range
    ///   Thrown if there is no element with the specified key exists.
    [[nodiscard]] auto at(const key_type &key) const -> const mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end()) [[unlikely]]
            throw std::out_of_range{"unordered_flat_map::at"};
        return iter->second;
    }

    /// \brief
    ///   Get the element with the specified key with bound check.
    /// \tparam K
    ///   Type of the key to be found.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    /// \throws std::out_of_range
    ///   Thrown if there is no element with the specified key exists.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto at(const K &key) -> mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end()) [[unlikely]]
            throw std::out_of_range{"unordered_flat_map::at"};
        return iter->second;
    }

    /// \brief
    ///   Get the element with the specified key with bound check.
    /// \tparam K
    ///   Type of the key to be found.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    /// \throws std::out_of_range
    ///   Thrown if there is no element with the specified key exists.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto at(const K &key) const -> const mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end()) [[unlikely]]
            throw std::out_of_range{"unordered_flat_map::at"};
        return iter->second;
    }

    /// \brief
    ///   Get the element with the specified key. If the key does not exist, return a default-constructed mapped value.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    auto operator[](const key_type &key) noexcept -> mapped_type & {
        auto result = this->try_emplace(key);
        return result.first->second;
    }

    /// \brief
    ///   Get the element with the specified key. If the key does not exist, return a default-constructed mapped value.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    auto operator[](key_type &&key) noexcept -> mapped_type & {
        auto result = this->try_emplace(std::move(key));
        return result.first->second;
    }

    /// \brief
    ///   Get the element with the specified key. If the key does not exist, return a default-constructed mapped value.
    /// \tparam K
    ///   Type of the key to be found.
    /// \param key
    ///   The key of the element to be found.
    /// \return
    ///   Reference to the element with the specified key.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto operator[](const K &key) noexcept -> mapped_type & {
        auto result = this->try_emplace(key);
        return result.first->second;
    }

    /// \brief
    ///   Get number of elements that matches the specified key.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    [[nodiscard]] auto count(const key_type &key) const noexcept -> size_type {
        return this->super::count(key);
    }

    /// \brief
    ///   Get number of elements that matches the specified key.
    /// \tparam K
    ///   Type of the key to count.
    /// \param key
    ///   The key to count.
    /// \return
    ///   Number of elements with the specified key. This value will be either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto count(const K &key) const noexcept -> size_type {
        return this->super::count(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) noexcept -> iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    [[nodiscard]] auto find(const key_type &key) const noexcept -> const_iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto find(const K &key) noexcept -> iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Try to find the element with the specified key.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   The key to find.
    /// \return
    ///   Iterator to the element with the specified key. If the element is not found, the iterator will be equal to
    ///   \c end().
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto find(const K &key) const noexcept -> const_iterator {
        return this->super::find(key);
    }

    /// \brief
    ///   Check if this unordered flat map contains the element with the specified key.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This unordered flat map contains the element with the specified key.
    /// \retval false
    ///   This unordered flat map does not contain the element with the specified key.
    [[nodiscard]] auto contains(const key_type &key) const noexcept -> bool {
        return this->super::contains(key);
    }

    /// \brief
    ///   Check if this unordered flat map contains the element with the specified key.
    /// \tparam K
    ///   Type of the key to check.
    /// \param key
    ///   The key to check.
    /// \retval true
    ///   This unordered flat map contains the element with the specified key.
    /// \retval false
    ///   This unordered flat map does not contain the element with the specified key.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto contains(const K &key) const noexcept -> bool {
        return this->super::contains(key);
    }

    /// \brief
    ///   Get number of buckets in this unordered flat map.
    /// \return
    ///   Number of buckets in this unordered flat map.
    [[nodiscard]] auto bucket_count() const noexcept -> size_type {
        return this->super::bucket_count();
    }

    /// \brief
    ///   Get load factor of this unordered flat map.
    /// \return
    ///   Load factor of this unordered flat map.
    [[nodiscard]] auto load_factor() const noexcept -> float {
        return this->super::load_factor();
    }

    /// \brief
    ///   Get maximum load factor of this unordered flat map.
    /// \return
    ///   Maximum load factor of this unordered flat map.
    [[nodiscard]] static constexpr auto max_load_factor() noexcept -> float {
        return super::max_load_factor();
    }

    /// \brief
    ///   Rehash the unordered flat map with the specified bucket count.
    /// \param bucket_count
    ///   New number of buckets in the unordered flat map. This method will do nothing if the new bucket count is less
    ///   than or equal to the current bucket count.
    auto rehash(size_type bucket_count) noexcept -> void {
        this->super::rehash(bucket_count);
    }

    /// \brief
    ///   Rehash the unordered flat map to hold at least the specified number of elements.
    /// \param count
    ///   Number of elements that this unordered flat map should hold.
    auto reserve(size_type count) noexcept -> void {
        this->super::reserve(count);
    }

    /// \brief
    ///   Get hasher of this unordered flat map.
    /// \return
    ///   Hasher of this unordered flat map.
    [[nodiscard]] auto hash_function() const noexcept -> hasher {
        return this->super::hash_function();
    }

    /// \brief
    ///   Get key equality comparison of this unordered flat map.
    /// \return
    ///   Key equality comparison of this unordered flat map.
    [[nodiscard]] auto key_eq() const noexcept -> key_equal {
        return this->super::key_eq();
    }
};

} // namespace onion
