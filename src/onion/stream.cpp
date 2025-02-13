#include "onion/stream.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

using namespace onion;

StringStream::StringStream(std::string_view str) noexcept
    : m_buffer{static_cast<char *>(std::malloc(str.size()))},
      m_bufferEnd{m_buffer + str.size()},
      m_begin{m_buffer},
      m_end{m_bufferEnd} {
    // We assumes that memory allocation would never fail.
    if (m_buffer == nullptr) [[unlikely]]
        std::terminate();
    std::memcpy(m_buffer, str.data(), str.size());
}

StringStream::StringStream(const StringStream &other) noexcept
    : m_buffer{static_cast<char *>(std::malloc(other.size()))},
      m_bufferEnd{m_buffer + other.size()},
      m_begin{m_buffer},
      m_end{m_bufferEnd} {
    // We assumes that memory allocation would never fail.
    if (m_buffer == nullptr) [[unlikely]]
        std::terminate();
    std::memcpy(m_buffer, other.m_begin, other.size());
}

StringStream::~StringStream() noexcept {
    if (m_buffer != nullptr)
        std::free(m_buffer);
}

auto StringStream::operator=(const StringStream &other) noexcept -> StringStream & {
    if (this == &other) [[unlikely]]
        return *this;

    std::size_t newSize = other.size();
    if (capacity() >= newSize) {
        std::memcpy(m_buffer, other.m_begin, newSize);
        m_begin = m_buffer;
        m_end   = m_buffer + newSize;
        return *this;
    }

    if (m_buffer != nullptr)
        std::free(m_buffer);

    // We assumes that memory allocation would never fail.
    m_buffer = static_cast<char *>(std::malloc(newSize));
    if (m_buffer == nullptr) [[unlikely]]
        std::terminate();

    m_bufferEnd = m_buffer + newSize;
    m_begin     = m_buffer;
    m_end       = m_bufferEnd;

    std::memcpy(m_buffer, other.m_begin, newSize);
    return *this;
}

auto StringStream::operator=(StringStream &&other) noexcept -> StringStream & {
    if (this == &other) [[unlikely]]
        return *this;

    if (m_buffer != nullptr)
        std::free(m_buffer);

    m_buffer    = other.m_buffer;
    m_bufferEnd = other.m_bufferEnd;
    m_begin     = other.m_begin;
    m_end       = other.m_end;

    other.m_buffer    = nullptr;
    other.m_bufferEnd = nullptr;
    other.m_begin     = nullptr;
    other.m_end       = nullptr;

    return *this;
}

auto StringStream::reserve(std::size_t capacity) noexcept -> void {
    std::size_t oldCapacity = this->capacity();
    if (oldCapacity >= capacity)
        return;

    auto oldMaxCapacity = static_cast<std::size_t>(m_bufferEnd - m_buffer);
    if (capacity <= oldMaxCapacity) {
        std::size_t size = this->size();
        std::memmove(m_buffer, m_begin, size);
        m_begin = m_buffer;
        m_end   = m_buffer + size;
        return;
    }

    // We assumes that memory allocation would never fail.
    auto *newBuffer = static_cast<char *>(std::malloc(capacity));
    if (newBuffer == nullptr) [[unlikely]]
        std::terminate();

    std::size_t size = this->size();
    if (m_buffer != nullptr) {
        std::memcpy(newBuffer, m_begin, size);
        std::free(m_buffer);
    }

    m_buffer    = newBuffer;
    m_bufferEnd = newBuffer + capacity;
    m_begin     = newBuffer;
    m_end       = newBuffer + size;
}

auto StringStream::read(void *buffer, std::uint32_t size) noexcept -> std::uint32_t {
    size = std::min(size, static_cast<std::uint32_t>(this->size()));
    std::memcpy(buffer, m_begin, size);
    m_begin += size;

    if (m_begin == m_end) {
        m_begin = m_buffer;
        m_end   = m_buffer;
    }

    return size;
}

auto StringStream::write(const void *data, std::uint32_t size) noexcept -> std::uint32_t {
    if (m_end + size >= m_bufferEnd)
        this->reserve(static_cast<std::size_t>(m_bufferEnd - m_buffer + size));

    std::memcpy(m_end, data, size);
    m_end += size;
    return size;
}
