#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace onion {

/// \brief
///   Calculate hash value for the given data using rapidhash. Rapidhash only support 64-bit hash.
///   See https://github.com/Nicoshev/rapidhash for more details about rapid hash.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
[[nodiscard]]
ONION_API auto rapidHash(const void *data, std::size_t size) noexcept -> std::uint64_t;

/// \brief
///   Generic hash function for the given data.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
[[nodiscard]]
inline auto hash(const void *data, std::size_t size) noexcept -> std::size_t {
    static_assert(sizeof(std::size_t) == sizeof(std::uint64_t),
                  "Hash function for 32 bit is not implemented yet.");
    return rapidHash(data, size);
}

/// \struct Hash
/// \tparam Key
///   Key type to hash.
/// \brief
///   Hasher type for the given key type.
template <typename Key>
struct Hash;

/// \struct Hash
/// \brief
///   Generic hasher for trivial types.
template <typename Key>
    requires(std::is_trivial_v<Key>)
struct Hash<Key> {
    using argument_type = Key;
    using result_type   = std::size_t;

    /// \brief
    ///   Calculate hash value for the given key.
    /// \param value
    ///   Key to hash.
    [[nodiscard]]
    auto operator()(const argument_type &value) const noexcept -> result_type {
        return ::onion::hash(std::addressof(value), sizeof(value));
    }
};

/// \struct Hash
/// \brief
///   Hasher for \c std::basic_string.
template <typename Element, typename Traits, typename Allocator>
struct Hash<std::basic_string<Element, Traits, Allocator>> {
    using argument_type  = std::basic_string<Element, Traits, Allocator>;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   String to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(const argument_type &value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Element));
    }

    /// \brief
    ///   Calculate hash value for the given string view.
    /// \param value
    ///   String view to hash.
    /// \return
    ///   Hash value of the string view.
    [[nodiscard]]
    auto operator()(std::basic_string_view<Element, Traits> value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Element));
    }

    /// \brief
    ///   Calculate hash value for the given null-terminated string.
    /// \param value
    ///   A null-terminated string to hash.
    /// \return
    ///   Hash value of the null-terminated string.
    [[nodiscard]]
    auto operator()(const Element *value) const noexcept -> result_type {
        return ::onion::hash(value, Traits::length(value) * sizeof(Element));
    }
};

/// \struct Hash
/// \brief
///   Hasher for \c std::basic_string_view.
template <typename Element, typename Traits>
struct Hash<std::basic_string_view<Element, Traits>> {
    using argument_type  = std::basic_string_view<Element, Traits>;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given string view.
    /// \param value
    ///   String view to hash.
    [[nodiscard]]
    auto operator()(argument_type value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Element));
    }

    /// \brief
    ///   Calculate hash value for the given null-terminated string.
    /// \param value
    ///   A null-terminated string to hash.
    /// \return
    ///   Hash value of the null-terminated string.
    [[nodiscard]]
    auto operator()(const Element *value) const noexcept -> result_type {
        return ::onion::hash(value, Traits::length(value) * sizeof(Element));
    }

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   String to hash.
    /// \return
    ///   Hash value of the string.
    template <typename Allocator>
    auto operator()(const std::basic_string<Element, Traits, Allocator> &value) const noexcept
        -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Element));
    }
};

} // namespace onion
