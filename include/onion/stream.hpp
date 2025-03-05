#pragma once

#include "io_context.hpp"

#include <expected>
#include <system_error>

namespace onion {

/// \class ReadAwaitable
/// \brief
///   Awaitable object for asynchronous system file read operation.
class [[nodiscard]] ReadAwaitable {
public:
    /// \brief
    ///   Create a new \c ReadAwaitable object for asynchronous system read operation.
    /// \param file
    ///   The file descriptor to read from.
    /// \param[out] buffer
    ///   Pointer to start of data buffer.
    /// \param size
    ///   Size in byte of data buffer.
    /// \param offset
    ///   Offset in byte from the start of the file to read. Pass -1 to read from the current file
    ///   position. For files that do not support random access, this value must be -1 or 0.
    ReadAwaitable(int file, void *buffer, std::uint32_t size, std::uint64_t offset) noexcept
        : m_ovlp{},
          m_file{file},
          m_size{size},
          m_buffer{buffer},
          m_offset{offset} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async read operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data reading and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous read operation.
    /// \return
    ///   Number of bytes read if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, std::errc> {
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected{static_cast<std::errc>(-m_ovlp.result)};
    }

private:
    detail::Overlapped m_ovlp;
    int m_file;
    std::uint32_t m_size;
    void *m_buffer;
    std::uint64_t m_offset;
};

/// \class WriteAwaitable
/// \brief
///   Awaitable object for asynchronous system file write operation.
class [[nodiscard]] WriteAwaitable {
public:
    /// \brief
    ///   Create a new \c WriteAwaitable object for asynchronous system write operation.
    /// \param file
    ///   The file descriptor to write to.
    /// \param data
    ///   Pointer to start of data buffer.
    /// \param size
    ///   Size in byte of data buffer.
    /// \param offset
    ///   Offset in byte from the start of the file to write. Pass -1 to write to the current file
    ///   position. For files that do not support random access, this value must be -1 or 0.
    WriteAwaitable(int file, const void *data, std::uint32_t size, std::uint64_t offset) noexcept
        : m_ovlp{},
          m_file{file},
          m_size{size},
          m_data{data},
          m_offset{offset} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async write operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous data writing and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous write operation.
    /// \return
    ///   Number of bytes written if
    ///   succeeded. Otherwise, return a system error code that represents the IO error.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::expected<std::uint32_t, std::errc> {
        if (m_ovlp.result >= 0) [[likely]]
            return static_cast<std::uint32_t>(m_ovlp.result);
        return std::unexpected{static_cast<std::errc>(-m_ovlp.result)};
    }

private:
    detail::Overlapped m_ovlp;
    int m_file;
    std::uint32_t m_size;
    const void *m_data;
    std::uint64_t m_offset;
};

/// \class SyncAwaitable
/// \brief
///   Awaitable object for system file synchronous operation.
class [[nodiscard]] SyncAwaitable {
public:
    /// \brief
    ///   Create a new \c SyncAwaitable object for system file synchronous operation.
    /// \param file
    ///   The file descriptor to synchronize.
    explicit SyncAwaitable(int file) noexcept : m_ovlp{}, m_file{file} {}

    /// \brief
    ///   C++20 coroutine API method. Always execute \c await_suspend().
    /// \return
    ///   This function always returns \c false.
    [[nodiscard]]
    static constexpr auto await_ready() noexcept -> bool {
        return false;
    }

    /// \brief
    ///   Prepare for async sync operation and suspend the coroutine.
    /// \tparam T
    ///   Type of promise of current coroutine.
    /// \param coroutine
    ///   Current coroutine handle.
    /// \retval true
    ///   This coroutine should be suspended and resumed later.
    /// \retval false
    ///   This coroutine should not be suspended and should be resumed immediately.
    template <typename T>
    auto await_suspend(std::coroutine_handle<T> coroutine) noexcept -> bool {
        return this->await_suspend(coroutine.promise());
    }

    /// \brief
    ///   Prepare for asynchronous file synchronization and suspend this coroutine.
    /// \param[in] promise
    ///   Promise of current coroutine.
    /// \retval true
    ///   This coroutine should be suspended and be resumed later when the operation is completed.
    /// \retval false
    ///   The operation is completed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous sync operation.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    [[nodiscard]]
    auto await_resume() const noexcept -> std::errc {
        return static_cast<std::errc>(m_ovlp.result);
    }

private:
    detail::Overlapped m_ovlp;
    int m_file;
};

/// \class Stream
/// \brief
///   Base class for all input/output streams.
class Stream {
public:
    /// \brief
    ///   Default constructor for \c Stream. Do nothing.
    Stream() noexcept = default;

    /// \brief
    ///   \c Stream is not copyable.
    Stream(const Stream &other) = delete;

    /// \brief
    ///   \c Stream is not movable.
    Stream(Stream &&other) = delete;

    /// \brief
    ///   Destructor for \c Stream. Do nothing.
    virtual ~Stream() = default;

    /// \brief
    ///   \c Stream is not copyable.
    auto operator=(const Stream &other) = delete;

    /// \brief
    ///   \c Stream is not movable.
    auto operator=(Stream &&other) = delete;

    /// \brief
    ///   Get size in byte of the stream.
    /// \return
    ///   Size of the stream in bytes. The return value could be \c std::nullopt if the size is
    ///   unknown.
    [[nodiscard]]
    virtual auto size() const -> std::optional<std::size_t> = 0;

    /// \brief
    ///   Copy all data from this stream to the destination stream. This method may be faster than
    ///   reading and writing data manually.
    /// \note
    ///   The current position of the stream will be changed after this operation.
    /// \param[inout] dest
    ///   The destination stream.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    virtual auto copyTo(Stream &dest) -> Task<std::errc> = 0;

    /// \brief
    ///   Read some data from the stream.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the data.
    /// \param size
    ///   Expected size of data to read.
    /// \return
    ///   Number of bytes read if succeeded. Otherwise, return an error code that represents the IO
    ///   error.
    virtual auto read(void *buffer, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> = 0;

    /// \brief
    ///   Write some data to the stream.
    /// \param[in] data
    ///   Pointer to start of the data to write.
    /// \param size
    ///   Size of data to write.
    /// \return
    ///   Number of bytes written if succeeded. Otherwise, return an error code that represents the
    ///   IO error.
    virtual auto write(const void *data, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> = 0;

    /// \brief
    ///   Flush the stream. This method may be used to ensure all data is written to the stream.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    virtual auto flush() -> Task<std::errc> = 0;

    /// \brief
    ///   Close the stream. This method may be used to release resources of the stream.
    virtual auto close() noexcept -> void = 0;
};

/// \class StringStream
/// \brief
///   \c StringStream is a stream that reads and writes data from and to a string.
class ONION_API StringStream final : public Stream {
public:
    /// \brief
    ///   Create an empty \c StringStream object.
    StringStream() noexcept;

    /// \brief
    ///   \c StringStream is not copyable.
    StringStream(const StringStream &other) = delete;

    /// \brief
    ///   \c StringStream is not movable.
    StringStream(StringStream &&other) = delete;

    /// \brief
    ///   Create a \c StringStream object and initialize it with a string.
    /// \param string
    ///   The string to initialize this \c StringStream object.
    StringStream(std::string_view string) noexcept;

    /// \brief
    ///   Destroy this \c StringStream object and release memory.
    ~StringStream() override;

    /// \brief
    ///   \c StringStream is not copyable.
    auto operator=(const StringStream &other) = delete;

    /// \brief
    ///   \c StringStream is not movable.
    auto operator=(StringStream &&other) = delete;

    /// \brief
    ///   Get size in byte of the stream.
    /// \return
    ///   Size of the stream in bytes. The return value will never be \c std::nullopt.
    [[nodiscard]]
    auto size() const -> std::optional<std::size_t> override;

    /// \brief
    ///   Copy all data from this stream to the destination stream. This method may be faster than
    ///   reading and writing data manually.
    /// \note
    ///   The current position of the stream will be changed after this operation.
    /// \param[inout] dest
    ///   The destination stream.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    auto copyTo(Stream &dest) -> Task<std::errc> override;

    /// \brief
    ///   Read some data from the stream.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the data.
    /// \param size
    ///   Expected size of data to read.
    /// \return
    ///   Number of bytes read if succeeded. This method would never fail.
    auto read(void *buffer, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> override;

    /// \brief
    ///   Write some data to the stream.
    /// \param[in] data
    ///   Pointer to start of the data to write.
    /// \param size
    ///   Size of data to write.
    /// \return
    ///   Number of bytes written if succeeded. Otherwise, return an error code that represents the
    ///   IO error.
    auto write(const void *data, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> override;

    /// \brief
    ///   Flush the stream. This method does nothing.
    /// \return
    ///   This method will never fail.
    auto flush() -> Task<std::errc> override;

    /// \brief
    ///   Close the stream. This method clears everything in this stream.
    auto close() noexcept -> void override;

private:
    char *m_buffer;
    char *m_cursor;
    char *m_last;
    char *m_end;
};

/// \enum FileOption
/// \brief
///   Options for file stream operations.
enum class FileOption : std::uint32_t {
    None     = 0,
    Read     = (1 << 0),
    Write    = (1 << 1),
    Append   = (1 << 2),
    Create   = (1 << 3),
    Truncate = (1 << 4),
    Direct   = (1 << 5),
    Sync     = (1 << 6),
};

/// \brief
///   Reverse all bits of \c FileOption.
/// \param option
///   The \c FileOption to reverse bits.
/// \return
///   The reversed \c FileOption.
[[nodiscard]]
constexpr auto operator~(FileOption option) noexcept -> FileOption {
    return static_cast<FileOption>(~static_cast<std::uint32_t>(option));
}

/// \brief
///   Combine two \c FileOption values using bitwise OR operator.
/// \param lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   The combined \c FileOption.
[[nodiscard]]
constexpr auto operator|(FileOption lhs, FileOption rhs) noexcept -> FileOption {
    return static_cast<FileOption>(static_cast<std::uint32_t>(lhs) |
                                   static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Combine two \c FileOption values using bitwise AND operator.
/// \param lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   The combined \c FileOption.
[[nodiscard]]
constexpr auto operator&(FileOption lhs, FileOption rhs) noexcept -> FileOption {
    return static_cast<FileOption>(static_cast<std::uint32_t>(lhs) &
                                   static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Combine two \c FileOption values using bitwise XOR operator.
/// \param lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   The combined \c FileOption.
[[nodiscard]]
constexpr auto operator^(FileOption lhs, FileOption rhs) noexcept -> FileOption {
    return static_cast<FileOption>(static_cast<std::uint32_t>(lhs) ^
                                   static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Combine two \c FileOption values using bitwise OR operator.
/// \param[inout] lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   Reference to the left-hand side \c FileOption.
[[nodiscard]]
constexpr auto operator|=(FileOption &lhs, FileOption rhs) noexcept -> FileOption & {
    lhs = lhs | rhs;
    return lhs;
}

/// \brief
///   Combine two \c FileOption values using bitwise AND operator.
/// \param[inout] lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   Reference to the left-hand side \c FileOption.
[[nodiscard]]
constexpr auto operator&=(FileOption &lhs, FileOption rhs) noexcept -> FileOption & {
    lhs = lhs & rhs;
    return lhs;
}

/// \brief
///   Combine two \c FileOption values using bitwise XOR operator.
/// \param[inout] lhs
///   The left-hand side \c FileOption.
/// \param rhs
///   The right-hand side \c FileOption.
/// \return
///   Reference to the left-hand side \c FileOption.
[[nodiscard]]
constexpr auto operator^=(FileOption &lhs, FileOption rhs) noexcept -> FileOption & {
    lhs = lhs ^ rhs;
    return lhs;
}

/// \enum SeekOption
/// \brief
///   Options for seeking file stream.
enum class SeekOption : std::uint8_t {
    Begin   = 0,
    Current = 1,
    End     = 2,
};

/// \class FileStream
/// \brief
///   \c FileStream is a stream that reads and writes data from and to a file.
class ONION_API FileStream final : public Stream {
public:
    /// \brief
    ///   Create an empty \c FileStream object.
    FileStream() noexcept;

    /// \brief
    ///   Create a \c FileStream object and open a file.
    /// \param path
    ///   The path to the file.
    /// \param option
    ///   The options for file operations.
    /// \throws std::system_error
    ///   Thrown if failed to open the file.
    FileStream(std::string_view path, FileOption option);

    /// \brief
    ///   \c FileStream is not copyable.
    FileStream(const FileStream &other) = delete;

    /// \brief
    ///   \c FileStream is not movable.
    FileStream(FileStream &&other) = delete;

    /// \brief
    ///   Destroy this \c FileStream object and release resources.
    ~FileStream() override;

    /// \brief
    ///   \c FileStream is not copyable.
    auto operator=(const FileStream &other) = delete;

    /// \brief
    ///   \c FileStream is not movable.
    auto operator=(FileStream &&other) = delete;

    /// \brief
    ///   Try to open a file with specified path and options.
    /// \param path
    ///   The path to the file to be opened.
    /// \param option
    ///   The options for file operations.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful. This object will not be affected if failed to open the file.
    auto open(std::string_view path, FileOption option) noexcept -> std::errc;

    /// \brief
    ///   Get size in byte of the stream.
    /// \return
    ///   Size of the stream in bytes. Return \c std::nullopt if this file stream is not opened.
    [[nodiscard]]
    auto size() const -> std::optional<std::size_t> override;

    /// \brief
    ///   Get the path of the file.
    /// \return
    ///   The path of the file. Return an empty string if this file stream is not opened.
    [[nodiscard]]
    auto path() const noexcept -> std::string_view;

    /// \brief
    ///   Get the options for file operations.
    /// \return
    ///   The options for file operations. Return \c FileOption::None if this file stream is not
    ///   opened.
    [[nodiscard]]
    auto options() const noexcept -> FileOption;

    /// \brief
    ///   Copy all data from this stream to the destination stream. This method may be faster than
    ///   reading and writing data manually.
    /// \note
    ///   The current position of the stream will be changed after this operation.
    /// \param[inout] dest
    ///   The destination stream.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    auto copyTo(Stream &dest) -> Task<std::errc> override;

    /// \brief
    ///   Read some data from the stream. You are suggested to use \c readAsync() for better
    ///   performance. This method is implemented for \c Stream interface compatibility.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the data.
    /// \param size
    ///   Expected size of data to read.
    /// \return
    ///   Number of bytes read if succeeded. Otherwise, return an error code that represents the IO
    ///   error.
    auto read(void *buffer, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> override;

    /// \brief
    ///   Read some data from the stream asynchronously. This method is the same as \c read() except
    ///   for fewer heap allocations.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the data.
    /// \param size
    ///   Expected size of data to read.
    /// \param offset
    ///   Offset in byte from the start of the file to read. Pass -1 to read from the current file
    ///   position.
    /// \return
    ///   Number of bytes read if succeeded. Otherwise, return an error code that represents the IO
    ///   error.
    auto readAsync(void *buffer, std::uint32_t size, std::uint64_t offset = -1) noexcept
        -> ReadAwaitable;

    /// \brief
    ///   Write some data to the stream. You are suggested to use \c writeAsync() for better
    ///   performance. This method is implemented for \c Stream interface compatibility.
    /// \param[in] data
    ///   Pointer to start of the data to write.
    /// \param size
    ///   Size of data to write.
    /// \return
    ///   Number of bytes written if succeeded. Otherwise, return an error code that represents the
    ///   IO error.
    auto write(const void *data, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::errc>> override;

    /// \brief
    ///   Write some data to the stream asynchronously. This method is the same as \c write() except
    ///   for fewer heap allocations.
    /// \param[in] data
    ///   Pointer to start of the data to write.
    /// \param size
    ///   Size of data to write.
    /// \param offset
    ///   Offset in byte from the start of the file to write. Pass -1 to write to the current file
    ///   position.
    /// \return
    ///   Number of bytes written if succeeded. Otherwise, return an error code that represents the
    ///   IO error.
    auto writeAsync(const void *data, std::uint32_t size, std::uint64_t offset = -1) noexcept
        -> WriteAwaitable;

    /// \brief
    ///   Flush the stream. This method may be used to ensure all data is written to the stream. You
    ///   are suggested to use \c sync() for better performance. This method is implemented for
    ///   \c Stream interface compatibility.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    auto flush() -> Task<std::errc> override;

    /// \brief
    ///   Flush the stream asynchronously. This method is the same as \c flush() except for fewer
    ///   heap allocations.
    /// \return
    ///   An error code that indicates the result of the operation. The error code is 0 if the
    ///   operation is successful.
    auto sync() noexcept -> SyncAwaitable;

    /// \brief
    ///   Seek to a specific position in the stream.
    /// \param option
    ///   The option for seeking.
    /// \param offset
    ///   Offset in byte from the seek base option of the file to seek.
    /// \return
    ///   Offset of the new position from the start of the file if succeeded. Otherwise, return an
    ///   error code that represents the IO error.
    auto seek(SeekOption option, std::int64_t offset) noexcept
        -> std::expected<std::int64_t, std::errc>;

    /// \brief
    ///   Close the stream. This method may be used to release resources of the stream.
    auto close() noexcept -> void override;

    /// \brief
    ///   Checks if this file stream is opened.
    /// \retval true
    ///   This file stream is opened.
    /// \retval false
    ///   This file stream is not opened.
    explicit operator bool() const noexcept;

private:
    int m_file;
    FileOption m_options;
    std::string m_path;
};

} // namespace onion
