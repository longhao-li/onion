#pragma once

#include "task.hpp"

#include <cstring>
#include <expected>
#include <system_error>

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

/// \struct is_blocked_readable
/// \brief
///   Traits type to determine if a type supports blocked reading operation.
template <typename T, typename = void>
struct is_blocked_readable : std::false_type {};

/// \struct is_blocked_readable
/// \brief
///   Traits type to determine if a type supports blocked reading operation.
template <typename T>
struct is_blocked_readable<
    T,
    std::enable_if_t<std::is_convertible_v<
        decltype(std::declval<T>().read(std::declval<void *>(), std::declval<std::uint32_t>())),
        std::uint32_t>>> : std::true_type {};

/// \struct is_blocked_readable
/// \brief
///   Traits type to determine if a type supports blocked reading operation.
template <typename T>
struct is_blocked_readable<
    T,
    std::enable_if_t<is_expected_v<
        decltype(std::declval<T>().read(std::declval<void *>(), std::declval<std::uint32_t>()))>>>
    : is_expected_convertible<decltype(std::declval<T>().read(std::declval<void *>(),
                                                              std::declval<std::uint32_t>())),
                              std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports blocked reading operation.
template <typename T>
inline constexpr bool is_blocked_readable_v = is_blocked_readable<T>::value;

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
        async_result_t<decltype(std::declval<T>().readAsync(std::declval<void *>(),
                                                            std::declval<std::uint32_t>()))>,
        std::uint32_t>>> : std::true_type {};

/// \struct is_async_readable
/// \brief
///   Traits type to determine if a type supports asynchronous reading operation.
template <typename T>
struct is_async_readable<
    T,
    std::enable_if_t<is_expected_v<
        async_result_t<decltype(std::declval<T>().readAsync(std::declval<void *>(),
                                                            std::declval<std::uint32_t>()))>>>>
    : is_expected_convertible<
          async_result_t<decltype(std::declval<T>().readAsync(std::declval<void *>(),
                                                              std::declval<std::uint32_t>()))>,
          std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports asynchronous reading operation.
template <typename T>
inline constexpr bool is_async_readable_v = is_async_readable<T>::value;

/// \struct is_input_stream
/// \brief
///   Traits type to determine if a type is an input stream. An input must have a read method and a
///   readAsync method which accepts a buffer and a size.
template <typename T>
struct is_input_stream : std::conjunction<is_blocked_readable<T>, is_async_readable<T>> {};

/// \brief
///   Helper variable template to determine if a type is an input stream.
template <typename T>
inline constexpr bool is_input_stream_v = is_input_stream<T>::value;

/// \struct is_blocked_writable
/// \brief
///   Traits type to determine if a type supports blocked writing operation.
template <typename T, typename = void>
struct is_blocked_writable : std::false_type {};

/// \struct is_blocked_writable
/// \brief
///   Traits type to determine if a type supports blocked writing operation.
template <typename T>
struct is_blocked_writable<T,
                           std::enable_if_t<std::is_convertible_v<
                               decltype(std::declval<T>().write(std::declval<const void *>(),
                                                                std::declval<std::uint32_t>())),
                               std::uint32_t>>> : std::true_type {};

/// \struct is_blocked_writable
/// \brief
///   Traits type to determine if a type supports blocked writing operation.
template <typename T>
struct is_blocked_writable<T,
                           std::enable_if_t<is_expected_v<decltype(std::declval<T>().write(
                               std::declval<const void *>(),
                               std::declval<std::uint32_t>()))>>>
    : is_expected_convertible<decltype(std::declval<T>().write(std::declval<const void *>(),
                                                               std::declval<std::uint32_t>())),
                              std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports blocked writing operation.
template <typename T>
inline constexpr bool is_blocked_writable_v = is_blocked_writable<T>::value;

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
        async_result_t<decltype(std::declval<T>().writeAsync(std::declval<const void *>(),
                                                             std::declval<std::uint32_t>()))>,
        std::uint32_t>>> : std::true_type {};

/// \struct is_async_writable
/// \brief
///   Traits type to determine if a type supports asynchronous writing operation.
template <typename T>
struct is_async_writable<
    T,
    std::enable_if_t<is_expected_v<
        async_result_t<decltype(std::declval<T>().writeAsync(std::declval<const void *>(),
                                                             std::declval<std::uint32_t>()))>>>>
    : is_expected_convertible<
          async_result_t<decltype(std::declval<T>().writeAsync(std::declval<const void *>(),
                                                               std::declval<std::uint32_t>()))>,
          std::expected<std::uint32_t, std::error_code>> {};

/// \brief
///   Helper variable template to determine if a type supports asynchronous writing operation.
template <typename T>
inline constexpr bool is_async_writable_v = is_async_writable<T>::value;

/// \struct is_output_stream
/// \brief
///   Traits type to determine if a type is an output stream. An output must have a write method and
///   a writeAsync method which accepts a buffer and a size.
template <typename T>
struct is_output_stream : std::conjunction<is_blocked_writable<T>, is_async_writable<T>> {};

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
auto streamReadFunc(void *object, void *buffer, std::uint32_t size)
    -> std::expected<std::uint32_t, std::error_code> {
    return static_cast<T *>(object)->read(buffer, size);
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
    -> std::expected<std::uint32_t, std::error_code> {
    return static_cast<T *>(object)->write(data, size);
}

/// \brief
///   Helper function to acquire readAsync function for a stream object.
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
auto streamReadAsyncFuncHelper(void *object, void *buffer, std::uint32_t size, char)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    auto result = co_await static_cast<T *>(object)->readAsync(buffer, size);
    co_return result;
}

/// \brief
///   Helper function to acquire readAsync function for a stream object.
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
auto streamReadAsyncFuncHelper(void *object, void *buffer, std::uint32_t size, int)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    return static_cast<T *>(object)->readAsync(buffer, size);
}

/// \brief
///   Helper function to acquire readAsync function for a stream object.
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
auto streamReadAsyncFunc(void *object, void *buffer, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    using dummy_t = std::conditional_t<
        std::is_same_v<decltype(std::declval<T>().readAsync(std::declval<void *>(),
                                                            std::declval<std::uint32_t>())),
                       Task<std::expected<std::uint32_t, std::error_code>>>,
        int, char>;
    return streamReadAsyncFuncHelper<T>(object, buffer, size, dummy_t{});
}

/// \brief
///   Helper function to acquire writeAsync function for a stream object.
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
auto streamWriteAsyncFuncHelper(void *object, const void *data, std::uint32_t size, char)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    auto result = co_await static_cast<T *>(object)->writeAsync(data, size);
    co_return result;
}

/// \brief
///   Helper function to acquire writeAsync function for a stream object.
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
auto streamWriteAsyncFuncHelper(void *object, const void *data, std::uint32_t size, int)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    return static_cast<T *>(object)->writeAsync(data, size);
}

/// \brief
///   Helper function to acquire writeAsync function for a stream object.
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
auto streamWriteAsyncFunc(void *object, const void *data, std::uint32_t size)
    -> Task<std::expected<std::uint32_t, std::error_code>> {
    using dummy_t = std::conditional_t<
        std::is_same_v<decltype(std::declval<T>().writeAsync(std::declval<const void *>(),
                                                             std::declval<std::uint32_t>())),
                       Task<std::expected<std::uint32_t, std::error_code>>>,
        int, char>;
    return streamWriteAsyncFuncHelper<T>(object, data, size, dummy_t{});
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
    Stream() noexcept
        : m_object{nullptr},
          m_destroy{nullptr},
          m_read{nullptr},
          m_write{nullptr},
          m_readAsync{nullptr},
          m_writeAsync{nullptr} {}

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
          m_write{&detail::streamWriteFunc<T>},
          m_readAsync{&detail::streamReadAsyncFunc<T>},
          m_writeAsync{&detail::streamWriteAsyncFunc<T>} {}

    /// \brief
    ///   Create a null stream.
    Stream(std::nullptr_t) noexcept
        : m_object{nullptr},
          m_destroy{nullptr},
          m_read{nullptr},
          m_write{nullptr},
          m_readAsync{nullptr},
          m_writeAsync{nullptr} {}

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
          m_write{other.m_write},
          m_readAsync{other.m_readAsync},
          m_writeAsync{other.m_writeAsync} {
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

        m_object     = other.m_object;
        m_destroy    = other.m_destroy;
        m_read       = other.m_read;
        m_write      = other.m_write;
        m_readAsync  = other.m_readAsync;
        m_writeAsync = other.m_writeAsync;

        other.m_object = nullptr;
        return *this;
    }

    /// \brief
    ///   Try to read some data from this stream.
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
    auto read(void *buffer, std::uint32_t size) -> std::expected<std::uint32_t, std::error_code> {
        return m_read(m_object, buffer, size);
    }

    /// \brief
    ///   Try to write some data to this stream.
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
        -> std::expected<std::uint32_t, std::error_code> {
        return m_write(m_object, data, size);
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
    auto readAsync(void *buffer, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::error_code>> {
        return m_readAsync(m_object, buffer, size);
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
    auto writeAsync(const void *data, std::uint32_t size)
        -> Task<std::expected<std::uint32_t, std::error_code>> {
        return m_writeAsync(m_object, data, size);
    }

private:
    /// \brief
    ///   Pointer to the actual stream object.
    void *m_object;

    /// \brief
    ///   Pointer to the function that destroys the stream object.
    auto (*m_destroy)(void *) noexcept -> void;

    /// \brief
    ///   Pointer to the function that reads some bytes from the stream object.
    auto (*m_read)(void *, void *, std::uint32_t) -> std::expected<std::uint32_t, std::error_code>;

    /// \brief
    ///   Pointer to the function that writes some bytes to the stream object.
    auto (*m_write)(void *, const void *, std::uint32_t)
        -> std::expected<std::uint32_t, std::error_code>;

    /// \brief
    ///   Pointer to the function that reads some bytes from the stream object asynchronously.
    auto (*m_readAsync)(void *, void *, std::uint32_t)
        -> Task<std::expected<std::uint32_t, std::error_code>>;

    /// \brief
    ///   Pointer to the function that writes some bytes to the stream object asynchronously.
    auto (*m_writeAsync)(void *, const void *, std::uint32_t)
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
        auto await_resume() noexcept -> std::uint32_t {
            return m_stream->read(m_buffer, m_size);
        }

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
        auto await_resume() noexcept -> std::uint32_t {
            return m_stream->write(m_data, m_size);
        }

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
    ONION_API auto read(void *buffer, std::uint32_t size) noexcept -> std::uint32_t;

    /// \brief
    ///   Read some data from this \c StringBuffer. This is actually the same as \c read.
    /// \param[out] buffer
    ///   Pointer to start of the buffer to store the read data.
    /// \param size
    ///   Maximum size in byte of data that could be read.
    /// \return
    ///   The actual number of bytes read from the \c StringBuffer.
    auto readAsync(void *buffer, std::uint32_t size) noexcept -> ReadAwaitable {
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
    ONION_API auto write(const void *data, std::uint32_t size) noexcept -> std::uint32_t;

    /// \brief
    ///   Write some data to this \c StringBuffer. This is actually the same as \c write.
    /// \param[in] data
    ///   Pointer to the data to write to the \c StringBuffer.
    /// \param size
    ///   Size in byte of the data to write.
    /// \return
    ///   The actual number of bytes written to the \c StringBuffer.
    auto writeAsync(const void *data, std::uint32_t size) noexcept -> WriteAwaitable {
        return {*this, data, size};
    }

private:
    char *m_buffer;
    char *m_bufferEnd;
    char *m_begin;
    char *m_end;
};

} // namespace onion
