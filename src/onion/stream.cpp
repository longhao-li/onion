#ifndef _LARGEFILE64_SOURCE
#    define _LARGEFILE64_SOURCE
#endif
#include "onion/stream.hpp"

#include <liburing.h>

#include <cstring>

using namespace onion;
using namespace onion::detail;

auto ReadAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
    m_ovlp.promise = &promise;

    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_read(sqe, m_file, m_buffer, m_size, m_offset);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
}

auto WriteAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
    m_ovlp.promise = &promise;

    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_write(sqe, m_file, m_data, m_size, m_offset);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
}

auto SyncAwaitable::await_suspend(PromiseBase &promise) noexcept -> bool {
    m_ovlp.promise = &promise;

    auto *ring        = static_cast<io_uring *>(IoContextWorker::current()->uring());
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (sqe == nullptr) [[unlikely]] {
        int result = io_uring_submit(ring);
        if (result < 0) [[unlikely]] {
            m_ovlp.result = result;
            return false;
        }

        sqe = io_uring_get_sqe(ring);
    }

    io_uring_prep_fsync(sqe, m_file, 0);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, &m_ovlp);

    io_uring_submit(ring);
    return true;
}

StringStream::StringStream() noexcept
    : Stream{},
      m_buffer{nullptr},
      m_cursor{nullptr},
      m_last{nullptr},
      m_end{nullptr} {}

StringStream::~StringStream() {
    if (m_buffer != nullptr)
        std::free(m_buffer);
}

auto StringStream::size() const -> std::optional<std::size_t> {
    return static_cast<std::size_t>(m_last - m_cursor);
}

auto StringStream::copyTo(Stream &dest) -> Task<std::errc> {
    std::errc error = {};

    while (m_cursor < m_last) {
        auto result = co_await dest.write(m_cursor, static_cast<std::uint32_t>(m_last - m_cursor));
        if (result.has_value()) [[likely]] {
            m_cursor += *result;
        } else {
            error = result.error();
            break;
        }
    }

    if (m_cursor >= m_last) {
        m_cursor = m_buffer;
        m_last   = m_buffer;
    }

    co_return error;
}

auto StringStream::read(void *buffer, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::errc>> {
    size = std::min(size, static_cast<std::uint32_t>(m_last - m_cursor));
    std::memcpy(buffer, m_cursor, size);

    m_cursor += size;
    if (m_cursor >= m_last) {
        m_cursor = m_buffer;
        m_last   = m_buffer;
    }

    co_return size;
}

auto StringStream::write(const void *data, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::errc>> {
    if (size == 0) [[unlikely]]
        co_return 0;

    // Reserve memory.
    if (size > static_cast<std::size_t>(m_end - m_last)) {
        auto dataSize = static_cast<std::size_t>(m_last - m_cursor);
        auto newSize  = std::max(dataSize * 2, dataSize + size);

        // We assumes that memory allocation will never fail.
        auto *newBuffer = static_cast<char *>(std::malloc(newSize));
        if (newBuffer == nullptr) [[unlikely]]
            std::terminate();

        std::memcpy(newBuffer, m_cursor, dataSize);
        std::free(m_buffer);

        m_buffer = newBuffer;
        m_cursor = m_buffer;
        m_last   = m_buffer + dataSize;
        m_end    = m_buffer + newSize;
    }

    std::memcpy(m_last, data, size);
    m_last += size;
    co_return size;
}

auto StringStream::flush() -> Task<std::errc> {
    co_return {};
}

auto StringStream::close() noexcept -> void {
    m_cursor = m_buffer;
    m_last   = m_buffer;
}

FileStream::FileStream() noexcept : Stream{}, m_file{-1}, m_options{}, m_path{} {}

FileStream::FileStream(std::string_view path, FileOption option)
    : Stream{},
      m_file{-1},
      m_options{option},
      m_path{path} {
    int flags = O_LARGEFILE;
    if ((option & FileOption::Write) != FileOption::None) {
        if ((option & FileOption::Read) != FileOption::None)
            flags |= O_RDWR;
        else
            flags |= O_WRONLY;

        if ((option & FileOption::Append) != FileOption::None)
            flags |= O_APPEND;
        if ((option & FileOption::Create) != FileOption::None)
            flags |= O_CREAT;
        if ((option & FileOption::Truncate) != FileOption::None)
            flags |= O_TRUNC;
        if ((option & FileOption::Sync) != FileOption::None)
            flags |= O_DSYNC;
    } else if ((option & FileOption::Read) != FileOption::None) {
        flags |= O_RDONLY;
    }

    if ((option & FileOption::Direct) != FileOption::None)
        flags |= O_DIRECT;

    m_file = ::open(m_path.c_str(), flags, 0644);
    if (m_file == -1) [[unlikely]]
        throw std::system_error{errno, std::system_category(), "Failed to open file " + m_path};
}

FileStream::~FileStream() {
    if (m_file != -1)
        ::close(m_file);
}

auto FileStream::open(std::string_view path, FileOption option) noexcept -> std::errc {
    int flags = O_LARGEFILE;
    if ((option & FileOption::Write) != FileOption::None) {
        if ((option & FileOption::Read) != FileOption::None)
            flags |= O_RDWR;
        else
            flags |= O_WRONLY;

        if ((option & FileOption::Append) != FileOption::None)
            flags |= O_APPEND;
        if ((option & FileOption::Create) != FileOption::None)
            flags |= O_CREAT;
        if ((option & FileOption::Truncate) != FileOption::None)
            flags |= O_TRUNC;
        if ((option & FileOption::Sync) != FileOption::None)
            flags |= O_DSYNC;
    } else if ((option & FileOption::Read) != FileOption::None) {
        flags |= O_RDONLY;
    }

    if ((option & FileOption::Direct) != FileOption::None)
        flags |= O_DIRECT;

    std::string newPath{path};
    int file = ::open(newPath.c_str(), flags, 0644);
    if (file == -1) [[unlikely]]
        return static_cast<std::errc>(errno);

    if (m_file != -1)
        ::close(m_file);

    m_file    = file;
    m_options = option;
    m_path    = std::move(newPath);

    return {};
}

auto FileStream::size() const -> std::optional<std::size_t> {
    struct stat s{};
    int result = ::fstat(m_file, &s);
    if (result == -1) [[unlikely]]
        return std::nullopt;
    return static_cast<std::size_t>(s.st_size);
}

auto FileStream::path() const noexcept -> std::string_view {
    return m_path;
}

auto FileStream::options() const noexcept -> FileOption {
    return m_options;
}

auto FileStream::copyTo(Stream &dest) -> Task<std::errc> {
    struct stat s{};
    int result = ::fstat(m_file, &s);
    if (result == -1) [[unlikely]]
        co_return static_cast<std::errc>(errno);

    std::uint64_t fileSize = s.st_size;
    std::uint64_t readSize = 0;
    char buffer[81920];

    while (readSize < fileSize) {
        std::uint32_t size = std::min<std::uint32_t>(sizeof(buffer), fileSize - readSize);
        auto result        = co_await readAsync(buffer, size, readSize);

        if (result.has_value()) {
            std::uint32_t writtenSize = 0;
            while (writtenSize < *result) {
                auto writeResult = co_await dest.write(buffer + writtenSize, *result - writtenSize);
                if (writeResult.has_value())
                    writtenSize += *writeResult;
                else
                    co_return writeResult.error();
            }

            readSize += *result;
        } else {
            co_return result.error();
        }
    }

    co_return {};
}

auto FileStream::read(void *buffer, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::errc>> {
    co_return co_await readAsync(buffer, size);
}

auto FileStream::readAsync(void *buffer, std::uint32_t size, std::uint64_t offset) noexcept
    -> ReadAwaitable {
    return {m_file, buffer, size, offset};
}

auto FileStream::write(const void *data, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::errc>> {
    co_return co_await writeAsync(data, size);
}

auto FileStream::writeAsync(const void *data, std::uint32_t size, std::uint64_t offset) noexcept
    -> WriteAwaitable {
    return {m_file, data, size, offset};
}

auto FileStream::flush() -> Task<std::errc> {
    co_return co_await sync();
}

auto FileStream::sync() noexcept -> SyncAwaitable {
    return SyncAwaitable{m_file};
}

auto FileStream::seek(SeekOption option, std::int64_t offset) noexcept
    -> std::expected<std::int64_t, std::errc> {
    int base;
    switch (option) {
    case SeekOption::Begin:   base = SEEK_SET; break;
    case SeekOption::Current: base = SEEK_CUR; break;
    case SeekOption::End:     base = SEEK_END; break;
    default:                  return std::unexpected{std::errc::invalid_argument};
    }

    std::int64_t newOffset = ::lseek64(m_file, offset, base);
    if (newOffset == -1) [[unlikely]]
        return std::unexpected{static_cast<std::errc>(errno)};

    return newOffset;
}

auto FileStream::close() noexcept -> void {
    if (m_file != -1) {
        ::close(m_file);

        m_file    = -1;
        m_options = {};
        m_path.clear();
    }
}

FileStream::operator bool() const noexcept {
    return m_file != -1;
}
