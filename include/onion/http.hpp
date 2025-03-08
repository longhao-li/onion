#pragma once

#include "hash.hpp"
#include "socket.hpp"

namespace onion {
namespace detail {

/// \struct CaseInsensitiveStringHash
/// \brief
///   Case insensitive string hasher.
struct CaseInsensitiveStringHash {
    using argument_type  = std::string_view;
    using result_type    = std::size_t;
    using is_transparent = void;

    /// \brief
    ///   Calculate hash value for the given string.
    /// \param value
    ///   String to hash.
    /// \return
    ///   Hash value of the string.
    [[nodiscard]]
    ONION_API auto operator()(argument_type value) const noexcept -> result_type;
};

/// \struct CaseInsensitiveStringEqual
/// \brief
///   Case insensitive string equal-to.
struct CaseInsensitiveStringEqual {
    using argument_type  = std::string_view;
    using is_transparent = void;

    /// \brief
    ///   Check if two strings are equal in case-insensitive manner.
    /// \param lhs
    ///   The first string to compare.
    /// \param rhs
    ///   The second string to compare.
    /// \retval true
    ///   The two strings are equal in case-insensitive manner.
    /// \retval false
    ///   The two strings are not equal in case-insensitive manner.
    [[nodiscard]]
    ONION_API auto operator()(argument_type lhs, argument_type rhs) const noexcept -> bool;
};

} // namespace detail

/// \enum HttpMethod
/// \brief
///   HTTP request methods.
enum class HttpMethod : std::uint8_t {
    Get     = 0,
    Head    = 1,
    Post    = 2,
    Put     = 3,
    Delete  = 4,
    Connect = 5,
    Options = 6,
    Trace   = 7,
    Patch   = 8,
};

/// \struct HttpVersion
/// \brief
///   HTTP version.
struct HttpVersion {
    std::uint8_t major;
    std::uint8_t minor;
};

/// \enum HttpStatus
/// \brief
///   HTTP response status codes.
enum class HttpStatus : std::uint16_t {
    Continue                      = 100,
    SwitchingProtocols            = 101,
    Processing                    = 102,
    EarlyHints                    = 103,
    Ok                            = 200,
    Created                       = 201,
    Accepted                      = 202,
    NonAuthoritativeInformation   = 203,
    NoContent                     = 204,
    ResetContent                  = 205,
    PartialContent                = 206,
    MultiStatus                   = 207,
    AlreadyReported               = 208,
    IMUsed                        = 226,
    MultipleChoices               = 300,
    MovedPermanently              = 301,
    Found                         = 302,
    SeeOther                      = 303,
    NotModified                   = 304,
    UseProxy                      = 305,
    TemporaryRedirect             = 307,
    PermanentRedirect             = 308,
    BadRequest                    = 400,
    Unauthorized                  = 401,
    PaymentRequired               = 402,
    Forbidden                     = 403,
    NotFound                      = 404,
    MethodNotAllowed              = 405,
    NotAcceptable                 = 406,
    ProxyAuthenticationRequired   = 407,
    RequestTimeout                = 408,
    Conflict                      = 409,
    Gone                          = 410,
    LengthRequired                = 411,
    PreconditionFailed            = 412,
    ContentTooLarge               = 413,
    UriTooLong                    = 414,
    UnsupportedMediaType          = 415,
    RangeNotSatisfiable           = 416,
    ExpectationFailed             = 417,
    ImATeapot                     = 418,
    MisdirectedRequest            = 421,
    UnprocessableContent          = 422,
    Locked                        = 423,
    FailedDependency              = 424,
    TooEarlyExperimental          = 425,
    UpgradeRequired               = 426,
    PreconditionRequired          = 428,
    TooManyRequests               = 429,
    RequestHeaderFieldsTooLarge   = 431,
    UnavailableForLegalReasons    = 451,
    InternalServerError           = 500,
    NotImplemented                = 501,
    BadGateway                    = 502,
    ServiceUnavailable            = 503,
    GatewayTimeout                = 504,
    HttpVersionNotSupported       = 505,
    VariantAlsoNegotiates         = 506,
    InsufficientStorage           = 507,
    LoopDetected                  = 508,
    NotExtended                   = 510,
    NetworkAuthenticationRequired = 511,
};

/// \class HttpHeader
/// \brief
///   HTTP header container.
class HttpHeader {
public:
    using key_type        = std::string;
    using mapped_type     = std::string;
    using value_type      = std::pair<const std::string, std::string>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using hasher          = detail::CaseInsensitiveStringHash;
    using key_equal       = detail::CaseInsensitiveStringEqual;
    using container_type  = HashMap<key_type, mapped_type, hasher, key_equal>;
    using reference       = typename container_type::reference;
    using const_reference = typename container_type::const_reference;
    using pointer         = typename container_type::pointer;
    using const_pointer   = typename container_type::const_pointer;
    using iterator        = typename container_type::iterator;
    using const_iterator  = typename container_type::const_iterator;

    /// \brief
    ///   Create an empty \c HttpHeaders object.
    HttpHeader() noexcept = default;

    /// \brief
    ///   Copy constructor of \c HttpHeaders.
    /// \param[in] other
    ///   The \c HttpHeaders object to copy from.
    ONION_API HttpHeader(const HttpHeader &other) noexcept;

    /// \brief
    ///   Move constructor of \c HttpHeaders.
    /// \param[inout] other
    ///   The \c HttpHeaders object to move from. The moved \c HttpHeaders object will be empty
    ///   after the move.
    ONION_API HttpHeader(HttpHeader &&other) noexcept;

    /// \brief
    ///   Destroy the \c HttpHeaders object.
    ONION_API ~HttpHeader() noexcept;

    /// \brief
    ///   Copy assignment operator of \c HttpHeaders.
    /// \param[in] other
    ///   The \c HttpHeaders object to copy from.
    /// \return
    ///   Reference to this \c HttpHeaders object.
    ONION_API auto operator=(const HttpHeader &other) noexcept -> HttpHeader &;

    /// \brief
    ///   Move assignment operator of \c HttpHeaders.
    /// \param[inout] other
    ///   The \c HttpHeaders object to move from. The moved \c HttpHeaders object will be empty
    ///   after the move.
    /// \return
    ///   Reference to this \c HttpHeaders object.
    ONION_API auto operator=(HttpHeader &&other) noexcept -> HttpHeader &;

    /// \brief
    ///   Get iterator to the first header of this container.
    /// \return
    ///   Iterator to the first header of this container.
    [[nodiscard]]
    auto begin() noexcept -> iterator {
        return m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the first header of this container.
    /// \return
    ///   Iterator to the first header of this container.
    [[nodiscard]]
    auto begin() const noexcept -> const_iterator {
        return m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the place after the last header of this container.
    /// \return
    ///   Iterator to the place after the last header of this container.
    [[nodiscard]]
    auto end() noexcept -> iterator {
        return m_headers.end();
    }

    /// \brief
    ///   Get iterator to the place after the last header of this container.
    /// \return
    ///   Iterator to the place after the last header of this container.
    [[nodiscard]]
    auto end() const noexcept -> const_iterator {
        return m_headers.end();
    }

    /// \brief
    ///   Checks if this container is empty.
    /// \retval true
    ///   This container is empty.
    /// \retval false
    ///   This container is not empty.
    [[nodiscard]]
    auto empty() const noexcept -> bool {
        return m_headers.empty();
    }

    /// \brief
    ///   Get the number of HTTP header fields in this container. Multiple headers with the same
    ///   name are counted as one.
    /// \return
    ///   Number of HTTP header fields in this container.
    [[nodiscard]]
    auto size() const noexcept -> size_type {
        return m_headers.size();
    }

    /// \brief
    ///   Add a HTTP header to this container. Please notice that HTTP allows multiple headers with
    ///   the same name. This method appends the value to the existing header if the header with the
    ///   same name exists.
    /// \param key
    ///   Name of the header.
    /// \param value
    ///   Value of the header.
    ONION_API auto add(std::string_view key, std::string_view value) noexcept -> void;

    /// \brief
    ///   Erase a HTTP header from this container. This method would erase the whole header with the
    ///   given name no matter how many values it has.
    /// \param key
    ///   Name of the header to be erased.
    /// \retval true
    ///   The header is erased from this container.
    /// \retval false
    ///   The header is not found in this container.
    ONION_API auto erase(std::string_view key) noexcept -> bool;

    /// \brief
    ///   Clears all headers in this container.
    ONION_API auto clear() noexcept -> void;

    /// \brief
    ///   Checks if this container contains a header with the given name.
    /// \param key
    ///   Name of the header to check.
    /// \retval true
    ///   This container contains a header with the given name.
    /// \retval false
    ///   This container does not contain a header with the given name.
    [[nodiscard]]
    auto contains(std::string_view key) const noexcept -> bool {
        return m_headers.contains(key);
    }

    /// \brief
    ///   Find a header with the given name.
    /// \param key
    ///   Name of the header to find.
    /// \return
    ///   Iterator to the header with the given name. If the header is not found, return \c end().
    [[nodiscard]]
    auto find(std::string_view key) noexcept -> iterator {
        return m_headers.find(key);
    }

    /// \brief
    ///   Find a header with the given name.
    /// \param key
    ///   Name of the header to find.
    /// \return
    ///   Iterator to the header with the given name. If the header is not found, return \c end().
    [[nodiscard]]
    auto find(std::string_view key) const noexcept -> const_iterator {
        return m_headers.find(key);
    }

    /// \brief
    ///   Try to get HTTP content length from the headers.
    /// \return
    ///   Content length if it exists in the headers. Otherwise, return \c std::nullopt.
    [[nodiscard]]
    ONION_API auto contentLength() const noexcept -> std::optional<std::size_t>;

    /// \brief
    ///   Set HTTP content length in the headers. This method will replace the Content-Length field
    ///   if it exists.
    /// \param length
    ///   Content length to set.
    ONION_API auto setContentLength(std::size_t length) noexcept -> void;

    /// \brief
    ///   Try to get HTTP content type from the headers.
    /// \return
    ///   Content type if it exists in the headers. Otherwise, return \c std::nullopt. The returned
    ///   content type may have multiple values separated by comma.
    [[nodiscard]]
    auto contentType() const noexcept -> std::optional<std::string_view> {
        auto iter = this->find("Content-Type");
        if (iter == this->end()) [[unlikely]]
            return std::nullopt;
        return (*iter).second;
    }

    /// \brief
    ///   Set HTTP content type in the headers. This method will replace the Content-Type field if
    ///   it exists.
    /// \param type
    ///   Content type to set.
    ONION_API auto setContentType(std::string_view type) noexcept -> void {
        m_headers["Content-Type"] = type;
    }

    /// \brief
    ///   Try to get HTTP date from the headers.
    /// \return
    ///   UTC date if it exists in the headers. The returned date will always be UTC time.
    ///   Otherwise, return \c std::nullopt.
    [[nodiscard]]
    ONION_API auto date() const noexcept -> std::optional<std::chrono::system_clock::time_point>;

    /// \brief
    ///   Set HTTP date in the headers. This method will replace the Date field if it exists.
    /// \param time
    ///   UTC date to set. Although the STL chrono library may use the same \c time_point type for
    ///   different clocks, you must make sure that this argument is always in UTC time.
    ONION_API auto setDate(std::chrono::system_clock::time_point time) noexcept -> void;

    /// \brief
    ///   Checks if the HTTP content is chunked.
    /// \retval true
    ///   The HTTP content is chunked.
    /// \retval false
    ///   The HTTP content is not chunked.
    [[nodiscard]]
    ONION_API auto isChunked() const noexcept -> bool;

    /// \brief
    ///   Access a header with the given name. If the header does not exist, it will be created with
    ///   no value.
    /// \param key
    ///   Name of the header to access.
    /// \return
    ///   Reference to the value of the header.
    [[nodiscard]]
    auto operator[](std::string_view key) noexcept -> mapped_type & {
        return m_headers[key];
    }

private:
    /// \brief
    ///   We store headers in a case-insensitive manner. The HTTP standard allows multiple headers
    ///   and we compress them into one element in the hash map with the values separated by comma.
    container_type m_headers;
};

/// \struct HttpUrl
/// \brief
///   Represents a URL.
struct HttpUrl {
    /// \brief
    ///   Scheme of the URL.
    std::string scheme;

    /// \brief
    ///   Username of the URL.
    std::string username;

    /// \brief
    ///   Password of the URL.
    std::string password;

    /// \brief
    ///   Host or Host:Port of the URL.
    std::string host;

    /// \brief
    ///   Path of the URL. Relative path may not start with '/'.
    std::string path;

    /// \brief
    ///   Query string in URL. Array queries will be stored separately by key directly.
    HashMap<std::string, std::string> query;

    /// \brief
    ///   Fragment of the URL without the leading '#'.
    std::string fragment;
};

/// \struct HttpRequest
/// \brief
///   Represents a HTTP request.
struct HttpRequest {
    /// \brief
    ///   HTTP request method for this request.
    HttpMethod method;

    /// \brief
    ///   HTTP version of this request.
    HttpVersion version;

    /// \brief
    ///   URL of this request.
    HttpUrl url;

    /// \brief
    ///   Path parameters. Path parameters are set by HTTP router. This is different from URL
    ///   queries.
    HashMap<std::string, std::string> params;

    /// \brief
    ///   HTTP header items.
    HttpHeader header;

    /// \brief
    ///   HTTP body of this request.
    std::string body;
};

/// \struct HttpResponse
/// \brief
///   Represents a HTTP response.
struct HttpResponse {
    /// \brief
    ///   HTTP version of this response.
    HttpVersion version;

    /// \brief
    ///   HTTP status code of this response.
    HttpStatus status;

    /// \brief
    ///   HTTP header items.
    HttpHeader header;

    /// \brief
    ///   HTTP body of this response.
    std::string body;
};

/// \class HttpServer
/// \brief
///   HTTP web server application.
class HttpServer;

/// \struct HttpContext
/// \brief
///   HTTP context for current request.
struct HttpContext {
    /// \brief
    ///   HTTP server for current HTTP session.
    HttpServer &server;

    /// \brief
    ///   TCP stream for current HTTP session.
    TcpStream &connection;

    /// \brief
    ///   Current HTTP request.
    HttpRequest request;

    /// \brief
    ///   The HTTP response to be sent.
    HttpResponse response;
};

} // namespace onion
