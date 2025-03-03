#pragma once

#include <cstddef>
#include <cstdint>

namespace onion {

/// \brief
///   Calculate 32-bit hash value for the given data.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
/// \return
///   32-bit hash value.
[[nodiscard]]
ONION_API auto hash32(const void *data, std::size_t size) noexcept -> std::uint32_t;

/// \brief
///   Calculate 64-bit hash value for the given data.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
/// \return
///   64-bit hash value.
[[nodiscard]]
ONION_API auto hash64(const void *data, std::size_t size) noexcept -> std::uint64_t;

/// \brief
///   Generic hash function for the given data.
/// \param data
///   Pointer to start of data to hash.
/// \param size
///   Size in byte of data to hash.
/// \return
///   Hash value of the given data.
[[nodiscard]]
inline auto hash(const void *data, std::size_t size) noexcept -> std::size_t {
    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        return static_cast<std::size_t>(hash32(data, size));
    } else {
        return static_cast<std::size_t>(hash64(data, size));
    }
}

} // namespace onion
