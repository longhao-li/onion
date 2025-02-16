#pragma once

#include "error_code.hpp"
#include "io_context.hpp"

#include <cstring>
#include <expected>

namespace onion::detail {

/// \struct is_expected
/// \brief
///   Traits type to determine if a type is a \c std::expected type.
template <typename T>
struct is_expected : std::false_type {};

/// \struct is_expected
/// \brief
///   Traits type to determine if a type is a \c std::expected type.
template <typename T, typename E>
struct is_expected<std::expected<T, E>> : std::true_type {};

/// \brief
///   Helper variable template to determine if a type is a \c std::expected type.
template <typename T>
inline constexpr bool is_expected_v = is_expected<T>::value;

/// \struct is_expected_convertible
/// \brief
///   Traits type to determine if a type could be converted into another expected type.
template <typename From, typename To, typename = void>
struct is_expected_convertible : std::false_type {};

/// \struct is_expected_convertible
/// \brief
///   Traits type to determine if a type could be converted into another expected type.
template <typename From, typename ToValue, typename ToError>
struct is_expected_convertible<From,
                               std::expected<ToValue, ToError>,
                               std::enable_if_t<std::is_convertible_v<From, ToValue>>>
    : std::true_type {};

/// \struct is_expected_convertible
/// \brief
///   Traits type to determine if a type could be converted into another expected type.
template <typename FromValue, typename FromError, typename ToValue, typename ToError>
struct is_expected_convertible<
    std::expected<FromValue, FromError>,
    std::expected<ToValue, ToError>,
    std::enable_if_t<std::conjunction_v<std::is_convertible<FromValue, ToValue>,
                                        std::is_convertible<FromError, ToError>>>>
    : std::true_type {};

/// \brief
///   Helper variable template to determine if a type could be converted into another expected type.
template <typename From, typename To>
inline constexpr bool is_expected_convertible_v = is_expected_convertible<From, To>::value;

/// \struct async_result
/// \brief
///   Traits type to determine the result type of an asynchronous operation.
template <typename T, typename = void>
struct async_result {};

/// \struct async_result
/// \brief
///   Traits type to determine the result type of an asynchronous operation.
template <typename T>
struct async_result<T, std::enable_if_t<is_task_v<T>>> : task_result<task_result_t<T>> {};

/// \struct async_result
/// \brief
///   Traits type to determine the result type of an asynchronous operation.
template <typename T>
struct async_result<T, std::enable_if_t<is_awaitable_v<T>>> : awaitable_result<T> {};

/// \struct async_result_t
/// \brief
///   Helper alias to get the result type of an asynchronous operation.
template <typename T>
using async_result_t = typename async_result<T>::type;

/// \struct is_async_readable
/// \brief
///   Traits type to determine if a type supports asynchronous reading operation.
template <typename T, typename = void>
struct is_async_readable : std::false_type {};

/// \struct is_async_readable
/// \brief
///   Traits type to determine if a type supports asynchronous reading operation.
template <typename T>
struct is_async_readable<
    T,
    std::enable_if_t<std::is_convertible_v<
        async_result_t<decltype(std::declval<T>().read(std::declval<void *>(),
                                                       std::declval<std::uint32_t>()))>,
        std::uint32_t>>> : std::true_type {};

/// \struct is_async_readable
/// \brief
///   Traits type to determine if a type supports asynchronous reading operation.
template <typename T>
struct is_async_readable<
    T,
    std::enable_if_t<is_expected_v<async_result_t<
        decltype(std::declval<T>().read(std::declval<void *>(), std::declval<std::uint32_t>()))>>>>
    : is_expected_convertible<
          async_result_t<decltype(std::declval<T>().read(std::declval<void *>(),
                                                         std::declval<std::uint32_t>()))>,
          std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports asynchronous reading operation.
template <typename T>
inline constexpr bool is_async_readable_v = is_async_readable<T>::value;

/// \struct is_input_stream
/// \brief
///   Traits type to determine if a type is an input stream. An input must have a read method and a
///   read method which accepts a buffer and a size.
template <typename T>
struct is_input_stream : is_async_readable<T> {};

/// \brief
///   Helper variable template to determine if a type is an input stream.
template <typename T>
inline constexpr bool is_input_stream_v = is_input_stream<T>::value;

/// \struct is_async_writable
/// \brief
///   Traits type to determine if a type supports asynchronous writing operation.
template <typename T, typename = void>
struct is_async_writable : std::false_type {};

/// \struct is_async_writable
/// \brief
///   Traits type to determine if a type supports asynchronous writing operation.
template <typename T>
struct is_async_writable<
    T,
    std::enable_if_t<std::is_convertible_v<
        async_result_t<decltype(std::declval<T>().write(std::declval<const void *>(),
                                                        std::declval<std::uint32_t>()))>,
        std::uint32_t>>> : std::true_type {};

/// \struct is_async_writable
/// \brief
///   Traits type to determine if a type supports asynchronous writing operation.
template <typename T>
struct is_async_writable<T,
                         std::enable_if_t<is_expected_v<async_result_t<
                             decltype(std::declval<T>().write(std::declval<const void *>(),
                                                              std::declval<std::uint32_t>()))>>>>
    : is_expected_convertible<
          async_result_t<decltype(std::declval<T>().write(std::declval<const void *>(),
                                                          std::declval<std::uint32_t>()))>,
          std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports asynchronous writing operation.
template <typename T>
inline constexpr bool is_async_writable_v = is_async_writable<T>::value;

/// \struct is_output_stream
/// \brief
///   Traits type to determine if a type is an output stream. An output must have a write method and
///   a write method which accepts a buffer and a size.
template <typename T>
struct is_output_stream : is_async_writable<T> {};

/// \brief
///   Helper variable template to determine if a type is an output stream.
template <typename T>
inline constexpr bool is_output_stream_v = is_output_stream<T>::value;

/// \struct is_input_output_stream
/// \brief
///   Traits type to determine if a type is an input/output stream. An input/output stream must be
///   both an input stream and an output stream.
template <typename T>
struct is_input_output_stream : std::conjunction<is_input_stream<T>, is_output_stream<T>> {};

/// \brief
///   Helper variable template to determine if a type is an input/output stream.
template <typename T>
inline constexpr bool is_input_output_stream_v = is_input_output_stream<T>::value;

/// \brief
///   Helper function to acquire destroy function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param[in] object
///   Pointer to the stream object to destroy.
template <typename T>
auto streamDestroyFunc(void *object) noexcept -> void {
    delete static_cast<T *>(object);
}

/// \brief
///   Helper function to acquire read function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to read from.
/// \param buffer
///   Pointer to the buffer to store the read data.
/// \param size
///   Maximum size in byte of data that could be read.
/// \return
///   The actual number of bytes read from the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamReadFuncHelper(void *object, void *buffer, std::uint32_t size, char)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    auto result = co_await static_cast<T *>(object)->read(buffer, size);
    co_return result;
}

/// \brief
///   Helper function to acquire read function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to read from.
/// \param buffer
///   Pointer to the buffer to store the read data.
/// \param size
///   Maximum size in byte of data that could be read.
/// \return
///   The actual number of bytes read from the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamReadFuncHelper(void *object, void *buffer, std::uint32_t size, int)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    return static_cast<T *>(object)->read(buffer, size);
}

/// \brief
///   Helper function to acquire read function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to read from.
/// \param buffer
///   Pointer to the buffer to store the read data.
/// \param size
///   Maximum size in byte of data that could be read.
/// \return
///   The actual number of bytes read from the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamReadFunc(void *object, void *buffer, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    using dummy_t = std::conditional_t<
        std::is_same_v<decltype(std::declval<T>().read(std::declval<void *>(),
                                                       std::declval<std::uint32_t>())),
                       Task<std::expected<std::uint32_t, std::error_code>>>,
        int, char>;
    return streamReadFuncHelper<T>(object, buffer, size, dummy_t{});
}

/// \brief
///   Helper function to acquire write function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to write to.
/// \param data
///   Pointer to the data to write to the stream.
/// \param size
///   Size in byte of the data to write.
/// \return
///   The actual number of bytes written to the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamWriteFuncHelper(void *object, const void *data, std::uint32_t size, char)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    auto result = co_await static_cast<T *>(object)->write(data, size);
    co_return result;
}

/// \brief
///   Helper function to acquire write function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to write to.
/// \param data
///   Pointer to the data to write to the stream.
/// \param size
///   Size in byte of the data to write.
/// \return
///   The actual number of bytes written to the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamWriteFuncHelper(void *object, const void *data, std::uint32_t size, int)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    return static_cast<T *>(object)->write(data, size);
}

/// \brief
///   Helper function to acquire write function for a stream object.
/// \tparam T
///   The type of the stream object.
/// \param object
///   Pointer to the stream object to write to.
/// \param data
///   Pointer to the data to write to the stream.
/// \param size
///   Size in byte of the data to write.
/// \return
///   The actual number of bytes written to the stream. If an error occurs, an error code will be
///   returned.
template <typename T>
auto streamWriteFunc(void *object, const void *data, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    using dummy_t = std::conditional_t<
        std::is_same_v<decltype(std::declval<T>().write(std::declval<const void *>(),
                                                        std::declval<std::uint32_t>())),
                       Task<std::expected<std::uint32_t, std::error_code>>>,
        int, char>;
    return streamWriteFuncHelper<T>(object, data, size, dummy_t{});
}

} // namespace onion::detail

namespace onion {

/// \class Stream
/// \brief
///   Proxy class for input output streams.
class Stream {
public:
    /// \brief
    ///   Create a null stream.
    Stream() noexcept : m_object{nullptr}, m_destroy{nullptr}, m_read{nullptr}, m_write{nullptr} {}

    /// \brief
    ///   Create a stream from a pointer to an input/output stream object.
    /// \tparam T
    ///   The type of the stream object.
    /// \param[in] stream
    ///   Pointer to the stream object. The stream object must be created with new and this object
    ///   will take over ownership of the object. The behavior is similar to \c std::unique_ptr.
    template <typename T>
        requires(detail::is_input_output_stream_v<T>)
    Stream(T *stream) noexcept
        : m_object{stream},
          m_destroy{&detail::streamDestroyFunc<T>},
          m_read{&detail::streamReadFunc<T>},
          m_write{&detail::streamWriteFunc<T>} {}

    /// \brief
    ///   Create a null stream.
    Stream(std::nullptr_t) noexcept
        : m_object{nullptr},
          m_destroy{nullptr},
          m_read{nullptr},
          m_write{nullptr} {}

    /// \brief
    ///   \c Stream is not copyable.
    Stream(const Stream &other) = delete;

    /// \brief
    ///   Move constructor of \c Stream.
    /// \param[inout] other
    ///   The stream to move from. The moved stream will be null.
    Stream(Stream &&other) noexcept
        : m_object{other.m_object},
          m_destroy{other.m_destroy},
          m_read{other.m_read},
          m_write{other.m_write} {
        other.m_object = nullptr;
    }

    /// \brief
    ///   Destroy this stream and the underlying stream object.
    ~Stream() noexcept {
        if (m_object != nullptr)
            m_destroy(m_object);
    }

    /// \brief
    ///   \c Stream is not copyable.
    auto operator=(const Stream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c Stream.
    /// \param[inout] other
    ///   The stream to move from. The moved stream will be null.
    /// \return
    ///   Reference to this stream.
    auto operator=(Stream &&other) noexcept -> Stream & {
        if (this == &other) [[unlikely]]
            return *this;

        if (m_object != nullptr)
            m_destroy(m_object);

        m_object  = other.m_object;
        m_destroy = other.m_destroy;
        m_read    = other.m_read;
        m_write   = other.m_write;

        other.m_object = nullptr;
        return *this;
    }

    /// \brief
    ///   Try to read some data from this stream asynchronously.
    /// \note
    ///   It is possible that the underlying stream object does not return error codes. Instead, it
    ///   throws exceptions for errors. This method does not handle exceptions and the exceptions
    ///   will be propagated to the caller.
    /// \param[out] buffer
    ///   Pointer to the buffer to store the read data.
    /// \param size
    ///   Maximum size in byte of data that could be read.
    /// \return
    ///   The actual number of bytes read from the stream. If an error occurs, an error code will be
    ///   returned.
    auto read(void *buffer, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::error_code>> {
        return m_read(m_object, buffer, size);
    }

    /// \brief
    ///   Try to write some data to this stream asynchronously.
    /// \note
    ///   It is possible that the underlying stream object does not return error codes. Instead, it
    ///   throws exceptions for errors. This method does not handle exceptions and the exceptions
    ///   will be propagated to the caller.
    /// \param[in] data
    ///   Pointer to the data to write to the stream.
    /// \param size
    ///   Size in byte of the data to write.
    /// \return
    ///   The actual number of bytes written to the stream. If an error occurs, an error code will
    ///   be returned.
    auto write(const void *data, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::error_code>> {
        return m_write(m_object, data, size);
    }

private:
    /// \brief
    ///   Pointer to the actual stream object.
    void *m_object;

    /// \brief
    ///   Pointer to the function that destroys the stream object.
    auto (*m_destroy)(void *) noexcept -> void;

    /// \brief
    ///   Pointer to the function that reads some bytes from the stream object asynchronously.
    auto (*m_read)(void *, void *, std::uint32_t)
        -> Task<std::expected<std::uint32_t, std::error_code>>;

    /// \brief
    ///   Pointer to the function that writes some bytes to the stream object asynchronously.
    auto (*m_write)(void *, const void *, std::uint32_t)
        -> Task<std::expected<std::uint32_t, std::error_code>>;
};

/// \class StringStream
/// \brief
///   Stream type for reading and writing string.
class StringStream {
public:
    /// \class ReadAwaitable
    /// \brief
    ///   Dummy awaitable type for asynchronous reading operation.
    class [[nodiscard]] ReadAwaitable {
    public:
        /// \brief
        ///   Create a dummy awaitable for asynchronous reading operation.
        /// \param[in] stream
        ///   The \c StringStream to read from.
        /// \param[out] buffer
        ///   Pointer to the buffer to store the read data.
        /// \param size
        ///   Maximum size in byte of data that could be read.
        ReadAwaitable(StringStream &stream, void *buffer, std::uint32_t size) noexcept
            : m_stream{&stream},
              m_buffer{buffer},
              m_size{size} {}

        /// \brief
        ///   C++20 coroutine API. \c StringStream is always ready for reading.
        static constexpr auto await_ready() noexcept -> bool {
            return true;
        }

        /// \brief
        ///   C++20 coroutine API. \c StringStream does not suspend for reading.
        template <typename T>
        static constexpr auto await_suspend(T) noexcept -> bool {
            return false;
        }

        /// \brief
        ///   C++20 coroutine API. Read some data from the \c StringStream.
        /// \return
        ///   The actual number of bytes read from the \c StringStream.
        ONION_API auto await_resume() noexcept -> std::uint32_t;

    private:
        StringStream *m_stream;
        void *m_buffer;
        std::uint32_t m_size;
    };

    /// \class WriteAwaitable
    /// \brief
    ///   Dummy awaitable type for asynchronous writing operation.
    class [[nodiscard]] WriteAwaitable {
    public:
        /// \brief
        ///   Create a dummy awaitable for asynchronous writing operation.
        /// \param[in] stream
        ///   The \c StringStream to write to.
        /// \param[in] data
        ///   Pointer to the data to write to the \c StringStream.
        /// \param size
        ///   Size in byte of the data to write.
        WriteAwaitable(StringStream &stream, const void *data, std::uint32_t size) noexcept
            : m_stream{&stream},
              m_data{data},
              m_size{size} {}

        /// \brief
        ///   C++20 coroutine API. \c StringStream is always ready for writing.
        static constexpr auto await_ready() noexcept -> bool {
            return true;
        }

        /// \brief
        ///   C++20 coroutine API. \c StringStream does not suspend for writing.
        template <typename T>
        static constexpr auto await_suspend(T) noexcept -> bool {
            return false;
        }

        /// \brief
        ///   C++20 coroutine API. Write some data to the \c StringStream.
        /// \return
        ///   The actual number of bytes written to the \c StringStream.
        ONION_API auto await_resume() noexcept -> std::uint32_t;

    private:
        StringStream *m_stream;
        const void *m_data;
        std::uint32_t m_size;
    };

public:
    /// \brief
    ///   Create an empty \c StringBuffer.
    StringStream() noexcept
        : m_buffer{nullptr},
          m_bufferEnd{nullptr},
          m_begin{nullptr},
          m_end{nullptr} {}

    /// \brief
    ///   Create a \c StringBuffer from a string.
    /// \param str
    ///   The string to be stored in this \c StringBuffer from.
    ONION_API StringStream(std::string_view str) noexcept;

    /// \brief
    ///   Copy constructor of \c StringBuffer.
    ONION_API StringStream(const StringStream &other) noexcept;

    /// \brief
    ///   Move constructor of \c StringBuffer.
    /// \param[inout] other
    ///   The \c StringBuffer to move from. The moved \c StringBuffer will be empty.
    StringStream(StringStream &&other) noexcept
        : m_buffer{other.m_buffer},
          m_bufferEnd{other.m_bufferEnd},
          m_begin{other.m_begin},
          m_end{other.m_end} {
        other.m_buffer    = nullptr;
        other.m_bufferEnd = nullptr;
        other.m_begin     = nullptr;
        other.m_end       = nullptr;
    }

    /// \brief
    ///   Destroy this \c StringBuffer.
    ONION_API ~StringStream() noexcept;

    /// \brief
    ///   Copy assignment operator of \c StringBuffer.
    /// \param other
    ///   The \c StringBuffer to copy from.
    /// \return
    ///   Reference to this \c StringBuffer.
    ONION_API auto operator=(const StringStream &other) noexcept -> StringStream &;

    /// \brief
    ///   Move assignment operator of \c StringBuffer.
    /// \param[inout] other
    ///   The \c StringBuffer to move from. The moved \c StringBuffer will be empty.
    /// \return
    ///   Reference to this \c StringBuffer.
    ONION_API auto operator=(StringStream &&other) noexcept -> StringStream &;

    /// \brief
    ///   Checks if this \c StringBuffer is empty.
    /// \retval true
    ///   This \c StringBuffer is empty.
    /// \retval false
    ///   This \c StringBuffer is not empty.
    [[nodiscard]]
    auto empty() const noexcept -> bool {
        return m_begin == m_end;
    }

    /// \brief
    ///   Get number of bytes stored in this \c StringBuffer.
    /// \return
    ///   Number of bytes stored in this \c StringBuffer.
    [[nodiscard]]
    auto size() const noexcept -> std::size_t {
        return static_cast<std::size_t>(m_end - m_begin);
    }

    /// \brief
    ///   Get maximum number of bytes that could be stored in this \c StringBuffer without
    ///   reallocation.
    /// \return
    ///   Maximum number of bytes that could be stored in this \c StringBuffer.
    [[nodiscard]]
    auto capacity() const noexcept -> std::size_t {
        return static_cast<std::size_t>(m_bufferEnd - m_begin);
    }

    /// \brief
    ///   Reserve space for storing data in this \c StringBuffer.
    /// \param capacity
    ///   The new capacity of this \c StringBuffer.
    ONION_API auto reserve(std::size_t capacity) noexcept -> void;

    /// \brief
    ///   Read some data from this \c StringBuffer.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the read data.
    /// \param size
    ///   Maximum size in byte of data that could be read.
    /// \return
    ///   The actual number of bytes read from the \c StringBuffer.
    auto read(void *buffer, std::uint32_t size) noexcept -> ReadAwaitable {
        return {*this, buffer, size};
    }

    /// \brief
    ///   Write some data to this \c StringBuffer.
    /// \param[in] data
    ///   Pointer to the data to write to the \c StringBuffer.
    /// \param size
    ///   Size in byte of the data to write.
    /// \return
    ///   The actual number of bytes written to the \c StringBuffer.
    auto write(const void *data, std::uint32_t size) noexcept -> WriteAwaitable {
        return {*this, data, size};
    }

private:
    char *m_buffer;
    char *m_bufferEnd;
    char *m_begin;
    char *m_end;
};

namespace detail {

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Windows handle type.
using handle_t = void *;
#else
/// \brief
///   Unix file descriptor handle type.
using handle_t = int;
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
/// \brief
///   Invalid handle value for Windows. This is the same as \c INVALID_HANDLE_VALUE in Windows API.
inline const handle_t InvalidHandle = reinterpret_cast<handle_t>(~static_cast<std::uintptr_t>(0));
#else
/// \brief
///   Invalid handle value for Unix.
inline constexpr handle_t InvalidHandle = -1;
#endif

} // namespace detail

/// \class ReadAwaitable
/// \brief
///   Awaitable object for asynchronous reading operation.
class [[nodiscard]] ReadAwaitable {
public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Create a new \c ReadAwaitable object for asynchronous reading operation.
    /// \param handle
    ///   The system handle to the file to read from.
    /// \param[out] buffer
    ///   Pointer to the buffer to store the read data.
    /// \param size
    ///   Size in byte of data to read.
    /// \param offset
    ///   Offset in byte from the beginning of the file to read from. Please pass -1 if you do not
    ///   want to use the file pointer as the starting point.
    ReadAwaitable(detail::handle_t handle,
                  void *buffer,
                  std::uint32_t size,
                  std::uint64_t offset) noexcept
        : m_ovlp{},
          m_handle{handle},
          m_buffer{buffer},
          m_size{size} {
        m_ovlp.dummyUnionName.dummyStructName.offset     = static_cast<std::uint32_t>(offset);
        m_ovlp.dummyUnionName.dummyStructName.offsetHigh = static_cast<std::uint32_t>(offset >> 32);
    }
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   Create a new \c ReadAwaitable object for asynchronous reading operation.
    /// \param handle
    ///   The system handle to the file to read from.
    /// \param[out] buffer
    ///   Pointer to the buffer to store the read data.
    /// \param size
    ///   Size in byte of data to read.
    /// \param offset
    ///   Offset in byte from the beginning of the file to read from. Please pass -1 if you do not
    ///   want to use the file pointer as the starting point.
    ReadAwaitable(detail::handle_t handle,
                  void *buffer,
                  std::uint32_t size,
                  std::uint64_t offset) noexcept
        : m_ovlp{},
          m_handle{handle},
          m_buffer{buffer},
          m_size{size},
          m_offset{offset} {}
#endif

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
    ///   This coroutine should be suspended and be resumed later when data is read or failed.
    /// \retval false
    ///   Data reading succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous read operation.
    /// \return
    ///   Number of bytes read if succeeded. Otherwise, return a system error code that represents
    ///   the IO error.
    [[nodiscard]]
    ONION_API auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode>;

private:
    detail::Overlapped m_ovlp;
    detail::handle_t m_handle;
    void *m_buffer;
    std::uint32_t m_size;
#if defined(__linux) || defined(__linux__)
    std::uint64_t m_offset;
#endif
};

/// \class WriteAwaitable
/// \brief
///   Awaitable object for asynchronous writing operation.
class [[nodiscard]] WriteAwaitable {
public:
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /// \brief
    ///   Create a new \c WriteAwaitable object for asynchronous writing operation.
    /// \param handle
    ///   The system handle to the file to write to.
    /// \param data
    ///   Pointer to the data to write.
    /// \param size
    ///   Size in byte of data to write.
    /// \param offset
    ///   Offset in byte from the beginning of the file to write to. Please pass -1 if you do not
    ///   want to use the file pointer as the starting point.
    WriteAwaitable(detail::handle_t handle,
                   const void *data,
                   std::uint32_t size,
                   std::uint64_t offset) noexcept
        : m_ovlp{},
          m_handle{handle},
          m_data{data},
          m_size{size} {
        m_ovlp.dummyUnionName.dummyStructName.offset     = static_cast<std::uint32_t>(offset);
        m_ovlp.dummyUnionName.dummyStructName.offsetHigh = static_cast<std::uint32_t>(offset >> 32);
    }
#elif defined(__linux) || defined(__linux__)
    /// \brief
    ///   Create a new \c WriteAwaitable object for asynchronous writing operation.
    /// \param handle
    ///   The system handle to the file to write to.
    /// \param data
    ///   Pointer to the data to write.
    /// \param size
    ///   Size in byte of data to write.
    /// \param offset
    ///   Offset in byte from the beginning of the file to write to. Please pass -1 if you do not
    ///   want to use the file pointer as the starting point.
    WriteAwaitable(detail::handle_t handle,
                   const void *data,
                   std::uint32_t size,
                   std::uint64_t offset) noexcept
        : m_ovlp{},
          m_handle{handle},
          m_data{data},
          m_size{size},
          m_offset{offset} {}
#endif

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
    ///   This coroutine should be suspended and be resumed later when data is written or failed.
    /// \retval false
    ///   Data writing succeeded or failed immediately and this coroutine should not be suspended.
    [[nodiscard]]
    ONION_API auto await_suspend(detail::PromiseBase &promise) noexcept -> bool;

    /// \brief
    ///   Get the result of the asynchronous write operation.
    /// \return
    ///   Number of bytes written if succeeded. Otherwise, return a system error code that
    ///   represents the IO error.
    [[nodiscard]]
    ONION_API auto await_resume() const noexcept -> std::expected<std::uint32_t, SystemErrorCode>;

private:
    detail::Overlapped m_ovlp;
    detail::handle_t m_handle;
    const void *m_data;
    std::uint32_t m_size;
#if defined(__linux) || defined(__linux__)
    std::uint64_t m_offset;
#endif
};

/// \enum FileFlag
/// \brief
///   File stream attribute flags. Could be combined with bitwise OR.
enum class FileFlag : std::uint32_t {
    None     = 0,
    Read     = (1U << 0),
    Write    = (1U << 1),
    Create   = (1U << 2),
    Truncate = (1U << 3),
    Direct   = (1U << 4),
    Sync     = (1U << 5),
};

/// \brief
///   Bitwise NOT operator for \c FileFlag.
/// \param flag
///   The \c FileFlag to be negated.
/// \return
///   The negated \c FileFlag.
[[nodiscard]]
constexpr auto operator~(FileFlag flag) noexcept -> FileFlag {
    return static_cast<FileFlag>(~static_cast<std::uint32_t>(flag));
}

/// \brief
///   Bitwise OR operator for \c FileFlag.
/// \param lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   The combined \c FileFlag.
[[nodiscard]]
constexpr auto operator|(FileFlag lhs, FileFlag rhs) noexcept -> FileFlag {
    return static_cast<FileFlag>(static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Bitwise AND operator for \c FileFlag.
/// \param lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   The common part of the two \c FileFlag.
[[nodiscard]]
constexpr auto operator&(FileFlag lhs, FileFlag rhs) noexcept -> FileFlag {
    return static_cast<FileFlag>(static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Bitwise XOR operator for \c FileFlag.
/// \param lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   The exclusive part of the two \c FileFlag.
[[nodiscard]]
constexpr auto operator^(FileFlag lhs, FileFlag rhs) noexcept -> FileFlag {
    return static_cast<FileFlag>(static_cast<std::uint32_t>(lhs) ^ static_cast<std::uint32_t>(rhs));
}

/// \brief
///   Bitwise OR assignment operator for \c FileFlag.
/// \param[inout] lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   Reference to the left hand side \c FileFlag.
[[nodiscard]]
constexpr auto operator|=(FileFlag &lhs, FileFlag rhs) noexcept -> FileFlag & {
    lhs = lhs | rhs;
    return lhs;
}

/// \brief
///   Bitwise AND assignment operator for \c FileFlag.
/// \param[inout] lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   Reference to the left hand side \c FileFlag.
[[nodiscard]]
constexpr auto operator&=(FileFlag &lhs, FileFlag rhs) noexcept -> FileFlag & {
    lhs = lhs & rhs;
    return lhs;
}

/// \brief
///   Bitwise XOR assignment operator for \c FileFlag.
/// \param[inout] lhs
///   The left hand side \c FileFlag.
/// \param rhs
///   The right hand side \c FileFlag.
/// \return
///   Reference to the left hand side \c FileFlag.
[[nodiscard]]
constexpr auto operator^=(FileFlag &lhs, FileFlag rhs) noexcept -> FileFlag & {
    lhs = lhs ^ rhs;
    return lhs;
}

/// \class FileStream
/// \brief
///   Stream type for reading and writing files.
class FileStream {
public:
    /// \brief
    ///   Create an empty file stream object. Empty file stream object cannot be used for reading or
    ///   writing operations.
    FileStream() noexcept : m_handle{detail::InvalidHandle}, m_flags{FileFlag::None}, m_path{} {}

    /// \brief
    ///   \c FileStream is not copyable.
    FileStream(const FileStream &other) = delete;

    /// \brief
    ///   Move constructor of \c FileStream.
    /// \param[inout] other
    ///   The \c FileStream to move from. The moved \c FileStream will be empty.
    FileStream(FileStream &&other) noexcept
        : m_handle{other.m_handle},
          m_flags{other.m_flags},
          m_path{std::move(other.m_path)} {
        other.m_handle = detail::InvalidHandle;
        other.m_flags  = FileFlag::None;
    }

    /// \brief
    ///   Close the file stream and release the system handle.
    ONION_API ~FileStream() noexcept;

    /// \brief
    ///   \c FileStream is not copyable.
    auto operator=(const FileStream &other) = delete;

    /// \brief
    ///   Move assignment operator of \c FileStream.
    /// \param[inout] other
    ///   The \c FileStream to move from. The moved \c FileStream will be empty.
    /// \return
    ///   Reference to this \c FileStream.
    ONION_API auto operator=(FileStream &&other) noexcept -> FileStream &;

    /// \brief
    ///   Try to open a file for IO operations.
    /// \param path
    ///   Path to the file in UTF-8 encoding.
    /// \param flags
    ///   Attribute flags for the file stream. Please notice that different operating systems may
    ///   have different memory alignment requirement for direct IO operations. Please see the
    ///   corresponding system manuals for more details.
    /// \return
    ///   Zero if the file is opened successfully. Otherwise, a system error code will be returned.
    ///   This object will not be changed if any error occurs.
    [[nodiscard]]
    ONION_API auto open(std::string_view path, FileFlag flags) noexcept -> SystemErrorCode;

    /// \brief
    ///   Checks if this file stream is opened.
    /// \retval true
    ///   This file stream is opened.
    /// \retval false
    ///   This file stream is not opened.
    [[nodiscard]]
    auto isOpened() const noexcept -> bool {
        return m_handle != detail::InvalidHandle;
    }

    /// \brief
    ///   Get attribute flags of this file stream.
    /// \return
    ///   Attribute flags of this file stream. The return value could be anything if this file
    ///   stream is not opened.
    [[nodiscard]]
    auto flags() const noexcept -> FileFlag {
        return m_flags;
    }

    /// \brief
    ///   Checks if this file stream supports reading operation.
    /// \retval true
    ///   This file stream supports reading operation.
    /// \retval false
    ///   This file stream does not support reading operation.
    [[nodiscard]]
    auto isReadable() const noexcept -> bool {
        return (m_flags & FileFlag::Read) != FileFlag::None;
    }

    /// \brief
    ///   Checks if this file stream supports writing operation.
    /// \retval true
    ///   This file stream supports writing operation.
    /// \retval false
    ///   This file stream does not support writing operation.
    [[nodiscard]]
    auto isWritable() const noexcept -> bool {
        return (m_flags & FileFlag::Write) != FileFlag::None;
    }

    /// \brief
    ///   Get path to the file in UTF-8 encoding.
    /// \return
    ///   Path to the file in UTF-8 encoding. The return value could be anything if this file stream
    ///   is not opened.
    [[nodiscard]]
    auto path() const noexcept -> std::string_view {
        return m_path;
    }

    /// \brief
    ///   Get size in byte of this file.
    /// \return
    ///   Size in byte of this file. A system error code will be returned if any error occurs.
    [[nodiscard]]
    ONION_API auto size() const noexcept -> std::expected<std::uint64_t, SystemErrorCode>;

private:
    /// \brief
    ///   System handle to the file.
    detail::handle_t m_handle;

    /// \brief
    ///   File attribute flags.
    FileFlag m_flags;

    /// \brief
    ///   Path to the file in UTF-8 encoding.
    std::string m_path;
};

} // namespace onion
