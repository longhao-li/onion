#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <type_traits>

namespace onion {

/// \brief
///   Generic hash function for the given data.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
/// \return
///   Hash value of the given data.
[[nodiscard]]
ONION_API auto hash(const void *data, std::size_t size) noexcept -> std::size_t;

/// \struct Hash
/// \tparam Key
///   Key type to hash.
/// \brief
///   Hasher type for the given key type.
template <typename Key>
struct Hash;

/// \struct Hash
/// \tparam Key
///   Number type to hash.
/// \brief
///   Hasher type for number types.
template <typename Key>
    requires(std::is_arithmetic_v<Key>)
struct Hash<Key> {
    using argument_type  = Key;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given number.
    /// \param value
    ///   The number to hash.
    /// \return
    ///   Hash value of the number.
    [[nodiscard]]
    auto operator()(argument_type value) const noexcept -> result_type {
        return ::onion::hash(&value, sizeof(value));
    }

    /// \brief
    ///   Calculate hash value for the given number.
    /// \param value
    ///   The number to hash.
    /// \return
    ///   Hash value of the number.
    template <typename T>
        requires(std::is_convertible_v<T, Key>)
    auto operator()(const T &value) const noexcept -> result_type {
        auto key = static_cast<Key>(value);
        return ::onion::hash(&key, sizeof(key));
    }
};

/// \struct Hash
/// \tparam Char
///   Character type of string to hash.
/// \tparam Traits
///   Traits type of string to hash.
/// \tparam Allocator
///   Allocator type of string to hash.
/// \brief
///   Hasher type for string types.
template <typename Char, typename Traits, typename Allocator>
struct Hash<std::basic_string<Char, Traits, Allocator>> {
    using argument_type  = std::basic_string<Char, Traits, Allocator>;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   The string to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(const argument_type &value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Char));
    }

    /// \brief
    ///   Calculate hash value for the given null-terminated string.
    /// \param str
    ///   The null-terminated string to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(const Char *str) const noexcept -> result_type {
        return ::onion::hash(str, std::char_traits<Char>::length(str) * sizeof(Char));
    }

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   The string to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(std::basic_string_view<Char, Traits> value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Char));
    }
};

/// \struct Hash
/// \tparam Char
///   Character type of string view to hash.
/// \tparam Traits
///   Traits type of string view to hash.
/// \brief
///   Hasher type for string view types.
template <typename Char, typename Traits>
struct Hash<std::basic_string_view<Char, Traits>> {
    using argument_type  = std::basic_string_view<Char, Traits>;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   The string to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(argument_type value) const noexcept -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Char));
    }

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   The string to hash.
    /// \return
    ///   Hash value of the string.
    template <typename Allocator>
    auto operator()(const std::basic_string<Char, Traits, Allocator> &value) const noexcept
        -> result_type {
        return ::onion::hash(value.data(), value.size() * sizeof(Char));
    }

    /// \brief
    ///   Calculate hash value for the given null-terminated string.
    /// \param str
    ///   The null-terminated string to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    auto operator()(const Char *str) const noexcept -> result_type {
        return ::onion::hash(str, std::char_traits<Char>::length(str) * sizeof(Char));
    }
};

/// \struct Hash
/// \tparam T
///   Type of optional to hash.
/// \brief
///   Hasher type for optional types.
template <typename T>
struct Hash<std::optional<T>> : Hash<T> {
    using argument_type = std::optional<T>;
    using result_type   = std::size_t;

    /// \brief
    ///   Calculate hash value for the given optional.
    /// \param value
    ///   The optional to hash.
    /// \return
    ///   Hash value of the optional.
    [[nodiscard]]
    auto operator()(const argument_type &value) const noexcept -> result_type {
        if (value.has_value())
            return this->Hash<T>::operator()(*value);
        bool temp = false;
        return ::onion::hash(&temp, sizeof(temp));
    }

    /// \brief
    ///   Calculate hash value for \c std::nullopt.
    /// \return
    ///   Hash value of \c std::nullopt.
    [[nodiscard]]
    auto operator()(std::nullopt_t) const noexcept -> result_type {
        bool temp = false;
        return ::onion::hash(&temp, sizeof(temp));
    }
};

} // namespace onion
