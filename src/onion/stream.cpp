#include "onion/stream.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

using namespace onion;

auto StringStream::ReadAwaitable::await_resume() noexcept -> std::uint32_t {
    m_size = std::min(m_size, static_cast<std::uint32_t>(m_stream->size()));
    std::memcpy(m_buffer, m_stream->m_begin, m_size);
    m_stream->m_begin += m_size;

    if (m_stream->m_begin == m_stream->m_end) {
        m_stream->m_begin = m_stream->m_buffer;
        m_stream->m_end   = m_stream->m_buffer;
    }

    return m_size;
}

auto StringStream::WriteAwaitable::await_resume() noexcept -> std::uint32_t {
    if (m_stream->m_end + m_size >= m_stream->m_bufferEnd)
        m_stream->reserve(
            static_cast<std::size_t>(m_stream->m_bufferEnd - m_stream->m_buffer + m_size));

    std::memcpy(m_stream->m_end, m_data, m_size);
    m_stream->m_end += m_size;
    return m_size;
}

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
