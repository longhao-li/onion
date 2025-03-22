#pragma once

#include "export.hpp"
#include "task.hpp"

#include <bitset>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

namespace onion {
namespace detail {

/// \brief
///   Hash data using a custom hash function. We use rapidhash for 64-bit systems and wyhash32 for 32-bit systems.
/// \param data
///   Pointer to start of data to be hashed.
/// \param size
///   Size in byte of data to be hashed.
[[nodiscard]] ONION_API auto hash(const void *data, std::size_t size) noexcept -> std::size_t;

} // namespace detail

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
        return detail::hash(&value, sizeof(value));
    }

    template <typename U>
        requires(std::is_convertible_v<U, T>)
    auto operator()(U value) const noexcept -> std::size_t {
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
        return detail::hash(&value, sizeof(value));
    }
};

/// \struct hash
/// \brief
///   Hasher for \c std::error_condition.
template <>
struct hash<std::error_condition> {
    auto operator()(const std::error_condition &value) const noexcept -> std::size_t {
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
        return detail::hash(&value, sizeof(value));
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
        return detail::hash(&value, sizeof(value));
    }
};

} // namespace onion
