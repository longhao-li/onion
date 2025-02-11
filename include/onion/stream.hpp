#pragma once

#include "task.hpp"

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
          m_destroy{&destroyFunc<T>},
          m_read{&readFunc<T>},
          m_write{&writeFunc<T>},
          m_readAsync{&ReadAsyncHelper<T>::func},
          m_writeAsync{&WriteAsyncHelper<T>::func} {}

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
    ///   Helper function to acquire destroy function for a stream object.
    /// \tparam T
    ///   The type of the stream object.
    /// \param[in] object
    ///   Pointer to the stream object to destroy.
    template <typename T>
    static auto destroyFunc(void *object) noexcept -> void {
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
    static auto readFunc(void *object, void *buffer, std::uint32_t size)
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
    ///   The actual number of bytes written to the stream. If an error occurs, an error code will
    ///   be returned.
    template <typename T>
    static auto writeFunc(void *object, const void *data, std::uint32_t size)
        -> std::expected<std::uint32_t, std::error_code> {
        return static_cast<T *>(object)->write(data, size);
    }

    /// \struct ReadAsyncHelper
    /// \brief
    ///   Helper class to acquire readAsync function for a stream object.
    template <typename T, typename = void>
    struct ReadAsyncHelper {
        static auto func(void *object, void *buffer, std::uint32_t size)
            -> Task<std::expected<std::uint32_t, std::error_code>> {
            co_return co_await static_cast<T *>(object)->readAsync(buffer, size);
        }
    };

    /// \struct ReadAsyncHelper
    /// \brief
    ///   Helper class to acquire readAsync function for a stream object.
    template <typename T>
    struct ReadAsyncHelper<T,
                           std::enable_if_t<std::is_same_v<
                               decltype(std::declval<T>().readAsync(std::declval<void *>(),
                                                                    std::declval<std::uint32_t>())),
                               Task<std::expected<std::uint32_t, std::error_code>>>>> {
        static auto func(void *object, void *buffer, std::uint32_t size)
            -> Task<std::expected<std::uint32_t, std::error_code>> {
            return static_cast<T *>(object)->readAsync(buffer, size);
        }
    };

    /// \struct WriteAsyncHelper
    /// \brief
    ///   Helper class to acquire writeAsync function for a stream object.
    template <typename T, typename = void>
    struct WriteAsyncHelper {
        static auto func(void *object, const void *data, std::uint32_t size)
            -> Task<std::expected<std::uint32_t, std::error_code>> {
            co_return co_await static_cast<T *>(object)->writeAsync(data, size);
        }
    };

    /// \struct WriteAsyncHelper
    /// \brief
    ///   Helper class to acquire writeAsync function for a stream object.
    template <typename T>
    struct WriteAsyncHelper<
        T,
        std::enable_if_t<
            std::is_same_v<decltype(std::declval<T>().writeAsync(std::declval<const void *>(),
                                                                 std::declval<std::uint32_t>())),
                           Task<std::expected<std::uint32_t, std::error_code>>>>> {
        static auto func(void *object, const void *data, std::uint32_t size)
            -> Task<std::expected<std::uint32_t, std::error_code>> {
            return static_cast<T *>(object)->writeAsync(data, size);
        }
    };

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

} // namespace onion
