#pragma once

#include "hash.hpp"
#include "socket.hpp"

#include <chrono>
#include <functional>

namespace onion {
namespace detail {

/// \struct case_insensitive_hash
/// \brief
///   Case-insensitive hasher structure.
struct case_insensitive_hash {
    using is_transparent = void;

    /// \brief
    ///   Hash the given string in case-insensitive manner.
    /// \param value
    ///   The string to hash.
    /// \return
    ///   Hash value of the given string.
    ONION_API auto operator()(std::string_view value) const noexcept -> std::size_t;
};

/// \struct case_insensitive_equal
/// \brief
///   Case-insensitive equality structure.
struct case_insensitive_equal {
    using is_transparent = void;

    /// \brief
    ///   Compare the given strings in case-insensitive manner.
    /// \param lhs
    ///   The left-hand side string to compare.
    /// \param rhs
    ///   The right-hand side string to compare.
    /// \return
    ///   True if the strings are equal, false otherwise.
    ONION_API auto operator()(std::string_view lhs, std::string_view rhs) const noexcept -> bool;
};

} // namespace detail

/// \enum http_version
/// \brief
///   HTTP version enumeration.
enum http_version : std::uint16_t {
    http_version_1_0 = 0x0100,
    http_version_1_1 = 0x0101,
    http_version_2_0 = 0x0200,
    http_version_3_0 = 0x0300,
};

/// \enum http_method
/// \brief
///   HTTP request method enumeration.
enum http_method : std::uint16_t {
    http_method_get     = 0,
    http_method_head    = 1,
    http_method_post    = 2,
    http_method_put     = 3,
    http_method_delete  = 4,
    http_method_connect = 5,
    http_method_options = 6,
    http_method_trace   = 7,
    http_method_patch   = 8,
};

/// \enum http_status
/// \brief
///   HTTP response status enumeration.
enum http_status : std::int32_t {
    http_status_continue                        = 100,
    http_status_switching_protocols             = 101,
    http_status_processing                      = 102,
    http_status_early_hints                     = 103,
    http_status_ok                              = 200,
    http_status_created                         = 201,
    http_status_accepted                        = 202,
    http_status_non_authoritative_information   = 203,
    http_status_no_content                      = 204,
    http_status_reset_content                   = 205,
    http_status_partial_content                 = 206,
    http_status_multi_status                    = 207,
    http_status_already_reported                = 208,
    http_status_im_used                         = 226,
    http_status_multiple_choices                = 300,
    http_status_moved_permanently               = 301,
    http_status_found                           = 302,
    http_status_see_other                       = 303,
    http_status_not_modified                    = 304,
    http_status_use_proxy                       = 305,
    http_status_temporary_redirect              = 307,
    http_status_permanent_redirect              = 308,
    http_status_bad_request                     = 400,
    http_status_unauthorized                    = 401,
    http_status_payment_required                = 402,
    http_status_forbidden                       = 403,
    http_status_not_found                       = 404,
    http_status_method_not_allowed              = 405,
    http_status_not_acceptable                  = 406,
    http_status_proxy_authentication_required   = 407,
    http_status_request_timeout                 = 408,
    http_status_conflict                        = 409,
    http_status_gone                            = 410,
    http_status_length_required                 = 411,
    http_status_precondition_failed             = 412,
    http_status_content_too_large               = 413,
    http_status_uri_too_long                    = 414,
    http_status_unsupported_media_type          = 415,
    http_status_range_not_satisfiable           = 416,
    http_status_expectation_failed              = 417,
    http_status_im_a_teapot                     = 418,
    http_status_misdirected_request             = 421,
    http_status_unprocessable_content           = 422,
    http_status_locked                          = 423,
    http_status_failed_dependency               = 424,
    http_status_too_early                       = 425,
    http_status_upgrade_required                = 426,
    http_status_precondition_required           = 428,
    http_status_too_many_requests               = 429,
    http_status_request_header_fields_too_large = 431,
    http_status_unavailable_for_legal_reasons   = 451,
    http_status_internal_server_error           = 500,
    http_status_not_implemented                 = 501,
    http_status_bad_gateway                     = 502,
    http_status_service_unavailable             = 503,
    http_status_gateway_timeout                 = 504,
    http_status_http_version_not_supported      = 505,
    http_status_variant_also_negotiates         = 506,
    http_status_insufficient_storage            = 507,
    http_status_loop_detected                   = 508,
    http_status_not_extended                    = 510,
    http_status_network_authentication_required = 511,
};

/// \brief
///   Default HTTP reason phrase for the given status code. This is only used by HTTP/1.0 and HTTP/1.1.
/// \param status
///   The HTTP status code.
/// \return
///   The default HTTP reason phrase for the given status code.
[[nodiscard]] constexpr auto http_reason_phrase(http_status status) noexcept -> std::string_view {
    switch (status) {
    case http_status_continue:                        return "Continue";
    case http_status_switching_protocols:             return "Switching Protocols";
    case http_status_processing:                      return "Processing";
    case http_status_early_hints:                     return "Early Hints";
    case http_status_ok:                              return "OK";
    case http_status_created:                         return "Created";
    case http_status_accepted:                        return "Accepted";
    case http_status_non_authoritative_information:   return "Non-Authoritative Information";
    case http_status_no_content:                      return "No Content";
    case http_status_reset_content:                   return "Reset Content";
    case http_status_partial_content:                 return "Partial Content";
    case http_status_multi_status:                    return "Multi-Status";
    case http_status_already_reported:                return "Already Reported";
    case http_status_im_used:                         return "IM Used";
    case http_status_multiple_choices:                return "Multiple Choices";
    case http_status_moved_permanently:               return "Moved Permanently";
    case http_status_found:                           return "Found";
    case http_status_see_other:                       return "See Other";
    case http_status_not_modified:                    return "Not Modified";
    case http_status_use_proxy:                       return "Use Proxy";
    case http_status_temporary_redirect:              return "Temporary Redirect";
    case http_status_permanent_redirect:              return "Rermanent Redirect";
    case http_status_bad_request:                     return "Bad Request";
    case http_status_unauthorized:                    return "Unauthorized";
    case http_status_payment_required:                return "Payment Required";
    case http_status_forbidden:                       return "Forbidden";
    case http_status_not_found:                       return "Not Found";
    case http_status_method_not_allowed:              return "Method Not Allowed";
    case http_status_not_acceptable:                  return "Not Acceptable";
    case http_status_proxy_authentication_required:   return "Proxy Authentication Required";
    case http_status_request_timeout:                 return "Request Timeout";
    case http_status_conflict:                        return "Conflict";
    case http_status_gone:                            return "Gone";
    case http_status_length_required:                 return "Length Required";
    case http_status_precondition_failed:             return "Precondition Failed";
    case http_status_content_too_large:               return "Content Too Large";
    case http_status_uri_too_long:                    return "URI Too Long";
    case http_status_unsupported_media_type:          return "Unsupported Media Type";
    case http_status_range_not_satisfiable:           return "Range Not Satisfiable";
    case http_status_expectation_failed:              return "Expectation Failed";
    case http_status_im_a_teapot:                     return "I'm a teapot";
    case http_status_misdirected_request:             return "Misdirected Request";
    case http_status_unprocessable_content:           return "Unprocessable Content";
    case http_status_locked:                          return "Locked";
    case http_status_failed_dependency:               return "Failed Dependency";
    case http_status_too_early:                       return "Too Early";
    case http_status_upgrade_required:                return "Upgrade Required";
    case http_status_precondition_required:           return "Precondition Required";
    case http_status_too_many_requests:               return "Too Many Requests";
    case http_status_request_header_fields_too_large: return "Request Header Fields Too Large";
    case http_status_unavailable_for_legal_reasons:   return "Unavailable For Legal Reasons";
    case http_status_internal_server_error:           return "Internal Server Error";
    case http_status_not_implemented:                 return "Not Implemented";
    case http_status_bad_gateway:                     return "Bad Gateway";
    case http_status_service_unavailable:             return "Service Unavailable";
    case http_status_gateway_timeout:                 return "Gateway Timeout";
    case http_status_http_version_not_supported:      return "HTTP Version Not Supported";
    case http_status_variant_also_negotiates:         return "Variant Also Negotiates";
    case http_status_insufficient_storage:            return "Insufficient Storage";
    case http_status_loop_detected:                   return "Loop Detected";
    case http_status_not_extended:                    return "Not Extended";
    case http_status_network_authentication_required: return "Network Authentication Required";
    default:                                          return "Undefined";
    }
}

/// \class http_header_map
/// \brief
///   HTTP header map.
class http_header_map {
public:
    using key_type        = std::string;
    using mapped_type     = std::string;
    using value_type      = std::pair<key_type, mapped_type>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using hasher          = detail::case_insensitive_hash;
    using key_equal       = detail::case_insensitive_equal;
    using reference       = value_type &;
    using const_reference = const value_type &;
    using pointer         = typename unordered_flat_map<std::string, std::string, hasher, key_equal>::pointer;
    using const_pointer   = typename unordered_flat_map<std::string, std::string, hasher, key_equal>::const_pointer;
    using iterator        = typename unordered_flat_map<std::string, std::string, hasher, key_equal>::iterator;
    using const_iterator  = typename unordered_flat_map<std::string, std::string, hasher, key_equal>::const_iterator;

    /// \brief
    ///   Create an empty \c http_header_map.
    http_header_map() noexcept = default;

    /// \brief
    ///   Copy construct of \c http_header_map.
    /// \param other
    ///   The \c http_header_map to copy from.
    http_header_map(const http_header_map &other) = default;

    /// \brief
    ///   Move construct an \c http_header_map.
    /// \param[inout] other
    ///   The \c http_header_map to move. The moved \c http_header_map is left in a valid but unspecified state.
    http_header_map(http_header_map &&other) noexcept = default;

    /// \brief
    ///   Destroy this \c http_header_map.
    ~http_header_map() noexcept = default;

    /// \brief
    ///   Copy assignment of \c http_header_map.
    /// \param other
    ///   The \c http_header_map to copy from.
    /// \return
    ///   Reference to this \c http_header_map.
    auto operator=(const http_header_map &other) -> http_header_map & = default;

    /// \brief
    ///   Move assignment of \c http_header_map.
    /// \param[inout] other
    ///   The \c http_header_map to move. The moved \c http_header_map is left in a valid but unspecified state.
    /// \return
    ///   Reference to this \c http_header_map.
    auto operator=(http_header_map &&other) noexcept -> http_header_map & = default;

    /// \brief
    ///   Get iterator to the first element of the \c http_header_map.
    /// \return
    ///   Iterator to the first element of the \c http_header_map.
    [[nodiscard]] auto begin() noexcept -> iterator {
        return this->m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the first element of the \c http_header_map.
    /// \return
    ///   Iterator to the first element of the \c http_header_map.
    [[nodiscard]] auto begin() const noexcept -> const_iterator {
        return this->m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the first element of the \c http_header_map.
    /// \return
    ///   Iterator to the first element of the \c http_header_map.
    [[nodiscard]] auto cbegin() const noexcept -> const_iterator {
        return this->m_headers.cbegin();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header_map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header_map.
    [[nodiscard]] auto end() noexcept -> iterator {
        return this->m_headers.end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header_map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header_map.
    [[nodiscard]] auto end() const noexcept -> const_iterator {
        return this->m_headers.end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header_map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header_map.
    [[nodiscard]] auto cend() const noexcept -> const_iterator {
        return this->m_headers.cend();
    }

    /// \brief
    ///   Checks if this \c http_header_map is empty.
    /// \retval true
    ///   This \c http_header_map is empty.
    /// \retval false
    ///   This \c http_header_map is not empty.
    [[nodiscard]] auto empty() const noexcept -> bool {
        return this->m_headers.empty();
    }

    /// \brief
    ///   Get number of HTTP header items in this \c http_header_map. Please notice that HTTP allows multiple header
    ///   items with the same key and they are counted separately.
    /// \return
    ///   Number of HTTP header items in this \c http_header_map.
    [[nodiscard]] auto size() const noexcept -> size_type {
        return this->m_headers.size();
    }

    /// \brief
    ///   Clear all HTTP headers in this \c http_header_map.
    auto clear() noexcept -> void {
        this->m_headers.clear();
    }

    /// \brief
    ///   Add a new HTTP header item into this \c http_header_map. We do not use multimap and the value will be appended
    ///   to the existing value with a comma seperated if the key already exists.
    /// \param key
    ///   The HTTP header key to be inserted. Do not escape the key value before inserting.
    /// \param value
    ///   The HTTP header value to be inserted.  Do not escape the header value before inserting.
    ONION_API auto add(std::string_view key, std::string_view value) noexcept -> void;

    /// \brief
    ///   Remove all HTTP header items with the given key from this \c http_header_map.
    /// \param key
    ///   The HTTP header key to be removed. Do not escape the key value before removing.
    /// \return
    ///   The number of HTTP header items removed.
    auto remove(std::string_view key) noexcept -> size_type {
        return this->m_headers.erase(key);
    }

    /// \brief
    ///   Checks if this \c http_header_map contains the given key.
    /// \param key
    ///   The HTTP header key to be checked. Do not escape the key value before checking.
    /// \retval true
    ///   This \c http_header_map contains the given key.
    /// \retval false
    ///   This \c http_header_map does not contain the given key.
    [[nodiscard]] auto contains(std::string_view key) const noexcept -> bool {
        return this->m_headers.contains(key);
    }

    /// \brief
    ///   Get the value of the HTTP header item with the given key.
    /// \param key
    ///   The HTTP header key to be checked. Do not escape the key value before checking.
    /// \return
    ///   Iterator to the value of the HTTP header item with the given key. If the key does not exist, \c end() will be
    ///   returned.
    [[nodiscard]] auto find(std::string_view key) noexcept -> iterator {
        return this->m_headers.find(key);
    }

    /// \brief
    ///   Get the value of the HTTP header item with the given key.
    /// \param key
    ///   The HTTP header key to be checked. Do not escape the key value before checking.
    /// \return
    ///   Iterator to the value of the HTTP header item with the given key. If the key does not exist, \c end() will be
    ///   returned.
    [[nodiscard]] auto find(std::string_view key) const noexcept -> const_iterator {
        return this->m_headers.find(key);
    }

    /// \brief
    ///   Get HTTP Authorization header value from this \c http_header_map.
    /// \return
    ///   HTTP Authorization header value. If the header does not exist, return empty string.
    [[nodiscard]] auto authorization() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Authorization"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set authorization for this HTTP header. The original authorization header will be covered.
    /// \param value
    ///   The authorization to be set.
    ONION_API auto set_authorization(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Content-Encoding header value from this \c http_header_map.
    /// \return
    ///   HTTP Content-Encoding header value. If the header does not exist, return empty string.
    [[nodiscard]] auto content_encoding() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Content-Encoding"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set content encoding for this HTTP header. The original content encoding header will be covered.
    /// \param value
    ///   The content encoding to be set.
    ONION_API auto set_content_encoding(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Cache-Control header value from this \c http_header_map.
    /// \return
    ///   HTTP Cache-Control header value. If the header does not exist, return empty string.
    [[nodiscard]] auto cache_control() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Cache-Control"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set cache control for this HTTP header. The original cache control header will be covered.
    /// \param value
    ///   The cache control to be set.
    ONION_API auto set_cache_control(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Connection header value from this \c http_header_map.
    /// \return
    ///   HTTP Connection header value. If the header does not exist, return empty string.
    [[nodiscard]] auto connection() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Connection"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set connection for this HTTP header. The original connection header will be covered.
    /// \param value
    ///   The connection to be set.
    ONION_API auto set_connection(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Content-Length header value from this \c http_header_map.
    /// \return
    ///   HTTP Content-Length header value. If the header does not exist, return \c std::nullopt.
    [[nodiscard]] ONION_API auto content_length() const noexcept -> std::optional<std::uint64_t>;

    /// \brief
    ///   Set content length for this HTTP header. The original content length header will be covered.
    /// \param value
    ///   The content length to be set.
    ONION_API auto set_content_length(std::uint64_t value) noexcept -> void;

    /// \brief
    ///   Get HTTP Content-Type header value from this \c http_header_map.
    /// \return
    ///   HTTP Content-Type header value. If the header does not exist, return empty string.
    [[nodiscard]] auto content_type() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Content-Type"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set content type for this HTTP header. The original content type header will be covered.
    /// \param value
    ///   The content type to be set.
    ONION_API auto set_content_type(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get the date of the HTTP header item with the given key.
    /// \return
    ///   UTC timepoint that represents the HTTP date header. If the header does not exist, return \c std::nullopt.
    ONION_API auto date() const noexcept -> std::optional<std::chrono::system_clock::time_point>;

    /// \brief
    ///   Set date for this HTTP header. The original date header will be covered.
    /// \param value
    ///   The date to be set.
    ONION_API auto set_date(std::chrono::system_clock::time_point value) noexcept -> void;

    /// \brief
    ///   Get HTTP Expires header value from this \c http_header_map.
    /// \return
    ///   HTTP Expires header value. If the header does not exist, return \c std::nullopt.
    [[nodiscard]] ONION_API auto expires() const noexcept -> std::optional<std::chrono::system_clock::time_point>;

    /// \brief
    ///   Set expires for this HTTP header. The original expires header will be covered.
    /// \param value
    ///   The expires to be set.
    ONION_API auto set_expires(std::chrono::system_clock::time_point value) noexcept -> void;

    /// \brief
    ///   Get HTTP Keep-Alive header value from this \c http_header_map.
    /// \return
    ///   HTTP Keep-Alive header value. If the header does not exist, return empty string.
    [[nodiscard]] auto keep_alive() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Keep-Alive"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Keep-Alive header value for this \c http_header_map. The original Keep-Alive header will be covered.
    /// \param value
    ///   The Keep-Alive value to be set.
    ONION_API auto set_keep_alive(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Transfer-Encoding header value from this \c http_header_map.
    /// \return
    ///   HTTP Transfer-Encoding header value. If the header does not exist, return empty string.
    [[nodiscard]] auto transfer_encoding() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Transfer-Encoding"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Transfer-Encoding header value for this \c http_header_map. The original Transfer-Encoding header
    ///   will be covered.
    /// \param value
    ///   The Transfer-Encoding value to be set.
    ONION_API auto set_transfer_encoding(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Host header value from this \c http_header_map.
    /// \return
    ///   HTTP Host header value. If the header does not exist, return empty string.
    [[nodiscard]] auto host() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Host"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Host header value for this \c http_header_map. The original Host header will be covered.
    /// \param value
    ///   The Host value to be set.
    ONION_API auto set_host(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP User-Agent header value from this \c http_header_map.
    /// \return
    ///   HTTP User-Agent header value. If the header does not exist, return empty string.
    [[nodiscard]] auto user_agent() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("User-Agent"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP User-Agent header value for this \c http_header_map. The original User-Agent header will be covered.
    /// \param value
    ///   The User-Agent value to be set.
    ONION_API auto set_user_agent(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Referer header value from this \c http_header_map.
    /// \return
    ///   HTTP Referer header value. If the header does not exist, return empty string.
    [[nodiscard]] auto referer() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Referer"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Referer header value for this \c http_header_map. The original Referer header will be covered.
    /// \param value
    ///   The Referer value to be set.
    ONION_API auto set_referer(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Upgrade header value from this \c http_header_map.
    /// \return
    ///   HTTP Upgrade header value. If the header does not exist, return empty string.
    [[nodiscard]] auto upgrade() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Upgrade"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Upgrade header value for this \c http_header_map. The original Upgrade header will be covered.
    /// \param value
    ///   The Upgrade value to be set.
    ONION_API auto set_upgrade(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get HTTP Location header value from this \c http_header_map.
    /// \return
    ///   HTTP Location header value. If the header does not exist, return empty string.
    [[nodiscard]] auto location() const noexcept -> std::string_view {
        if (auto it = this->m_headers.find("Location"); it != this->m_headers.end())
            return it->second;
        return {};
    }

    /// \brief
    ///   Set HTTP Location header value for this \c http_header_map. The original Location header will be covered.
    /// \param value
    ///   The Location value to be set.
    ONION_API auto set_location(std::string_view value) noexcept -> void;

    /// \brief
    ///   Get the value of the HTTP header item with the given key.
    /// \param key
    ///   The HTTP header key to be checked. Do not escape the key value before checking.
    /// \return
    ///   Reference to the value of the HTTP header item with the given key. If the key does not exist, an empty string
    ///   will be returned.
    [[nodiscard]] auto operator[](std::string_view key) noexcept -> mapped_type & {
        return this->m_headers[key];
    }

private:
    /// \brief
    ///   Generic container for HTTP headers.
    unordered_flat_map<std::string, std::string, hasher, key_equal> m_headers;
};

/// \class http_server
/// \brief
///   HTTP server application.
class http_server;

/// \struct http_request
/// \brief
///   HTTP request structure.
struct http_request {
    /// \brief
    ///   HTTP request method.
    http_method method;

    /// \brief
    ///   HTTP request version.
    http_version version;

    /// \brief
    ///   HTTP request path in URI. The path string is already unescaped.
    std::string path;

    /// \brief
    ///   HTTP parameters in route path in HTTP request URI. The parameter value strings are already unescaped.
    unordered_flat_map<std::string, std::string> params;

    /// \brief
    ///   HTTP query string in HTTP request URI. The query value strings are already unescaped.
    unordered_flat_map<std::string, std::string> queries;

    /// \brief
    ///   HTTP request headers.
    http_header_map headers;

    /// \brief
    ///   HTTP request body.
    std::string body;

    /// \brief
    ///   Reset all fields in this \c http_request to default values.
    auto clear() noexcept -> void {
        this->method  = http_method_get;
        this->version = http_version_1_1;
        this->path.clear();
        this->params.clear();
        this->queries.clear();
        this->headers.clear();
        this->body.clear();
    }
};

/// \struct http_response
/// \brief
///   HTTP response structure.
struct http_response {
    /// \brief
    ///   HTTP response version.
    http_version version;

    /// \brief
    ///   HTTP response status code.
    http_status status;

    /// \brief
    ///   HTTP response headers.
    http_header_map headers;

    /// \brief
    ///   HTTP response body.
    std::string body;

    /// \brief
    ///   Reset all fields in this \c http_response to default values.
    auto clear() noexcept -> void {
        this->version = http_version_1_1;
        this->status  = http_status_ok;
        this->headers.clear();
        this->body.clear();
    }

    /// \brief
    ///   Set HTTP status code for this HTTP response.
    /// \param code
    ///   The HTTP status code to be set.
    auto set_status(http_status code) noexcept -> void {
        this->status = code;
    }

    /// \brief
    ///   Set HTTP status code for this HTTP response.
    /// \param code
    ///   The HTTP status code to be set.
    auto set_status(std::int32_t code) noexcept -> void {
        this->status = static_cast<http_status>(code);
    }

    /// \brief
    ///   Set the HTTP response body as UTF-8 plain text.
    /// \param text
    ///   The text to be set as the HTTP response body. The text will be copied into the body.
    auto set_body(const char *text) noexcept -> void {
        this->body.assign(text);
        this->headers.set_content_length(this->body.size());
        this->headers.set_content_type("text/plain; charset=UTF-8");
    }

    /// \brief
    ///   Set the HTTP response body as UTF-8 plain text.
    /// \param text
    ///   The text to be set as the HTTP response body. The text will be copied into the body.
    auto set_body(std::string_view text) noexcept -> void {
        this->body.assign(text);
        this->headers.set_content_length(this->body.size());
        this->headers.set_content_type("text/plain; charset=UTF-8");
    }

    /// \brief
    ///   Set the HTTP response body as UTF-8 plain text.
    /// \param text
    ///   The text to be set as the HTTP response body. The text will be copied into the body.
    auto set_body(std::string text) noexcept -> void {
        this->body.assign(std::move(text));
        this->headers.set_content_length(this->body.size());
        this->headers.set_content_type("text/plain; charset=UTF-8");
    }

    /// \brief
    ///   Set date for this HTTP response. The original date header will be covered.
    /// \param value
    ///   The date to be set. If the value is not provided, current time will be used.
    auto set_date(std::chrono::system_clock::time_point value = std::chrono::system_clock::now()) noexcept -> void {
        this->headers.set_date(value);
    }

    /// \brief
    ///   Set the HTTP response body as plain text with HTTP status code 200 OK.
    /// \param text
    ///   The text to be set as the HTTP response body. This method assumes that the text is UTF-8 plaintext.
    auto ok(const char *text) noexcept -> void {
        this->set_status(http_status_ok);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response body as plain text with HTTP status code 200 OK.
    /// \param text
    ///   The text to be set as the HTTP response body. This method assumes that the text is UTF-8 plaintext.
    auto ok(std::string_view text) noexcept -> void {
        this->set_status(http_status_ok);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response body as plain text with HTTP status code 200 OK.
    /// \param text
    ///   The text to be set as the HTTP response body. This method assumes that the text is UTF-8 plaintext.
    auto ok(std::string text) noexcept -> void {
        this->set_status(http_status_ok);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 301 Moved Permanently.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    auto moved_permanently(std::string_view location) noexcept -> void {
        this->set_status(http_status_moved_permanently);
        this->headers.set_location(location);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 301 Moved Permanently.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto moved_permanently(std::string_view location, const char *text) noexcept -> void {
        this->set_status(http_status_moved_permanently);
        this->headers.set_location(location);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 301 Moved Permanently.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto moved_permanently(std::string_view location, std::string_view text) noexcept -> void {
        this->set_status(http_status_moved_permanently);
        this->headers.set_location(location);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 301 Moved Permanently.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto moved_permanently(std::string_view location, std::string text) noexcept -> void {
        this->set_status(http_status_moved_permanently);
        this->headers.set_location(location);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 302 Found.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    auto found(std::string_view location) noexcept -> void {
        this->set_status(http_status_found);
        this->headers.set_location(location);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 302 Found.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto found(std::string_view location, const char *text) noexcept -> void {
        this->set_status(http_status_found);
        this->headers.set_location(location);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 302 Found.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto found(std::string_view location, std::string_view text) noexcept -> void {
        this->set_status(http_status_found);
        this->headers.set_location(location);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 302 Found.
    /// \param location
    ///   The location to be redirected to. The location should be a valid URL. Please notice that this method does not
    ///   check if the location is a valid URL.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto found(std::string_view location, std::string text) noexcept -> void {
        this->set_status(http_status_found);
        this->headers.set_location(location);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 400 Bad Request without body.
    auto bad_request() noexcept -> void {
        this->set_status(http_status_bad_request);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 400 Bad Request.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto bad_request(const char *text) noexcept -> void {
        this->set_status(http_status_bad_request);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 400 Bad Request.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto bad_request(std::string_view text) noexcept -> void {
        this->set_status(http_status_bad_request);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 400 Bad Request.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto bad_request(std::string text) noexcept -> void {
        this->set_status(http_status_bad_request);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 403 Forbidden without body.
    auto forbidden() noexcept -> void {
        this->set_status(http_status_forbidden);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 403 Forbidden.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto forbidden(const char *text) noexcept -> void {
        this->set_status(http_status_forbidden);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 403 Forbidden.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto forbidden(std::string_view text) noexcept -> void {
        this->set_status(http_status_forbidden);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 403 Forbidden.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto forbidden(std::string text) noexcept -> void {
        this->set_status(http_status_forbidden);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 404 Not Found without body.
    auto not_found() noexcept -> void {
        this->set_status(http_status_not_found);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 404 Not Found.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto not_found(const char *text) noexcept -> void {
        this->set_status(http_status_not_found);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 404 Not Found.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto not_found(std::string_view text) noexcept -> void {
        this->set_status(http_status_not_found);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 404 Not Found.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto not_found(std::string text) noexcept -> void {
        this->set_status(http_status_not_found);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 405 Method Not Allowed without body.
    auto method_not_allowed() noexcept -> void {
        this->set_status(http_status_method_not_allowed);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 405 Method Not Allowed.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto method_not_allowed(const char *text) noexcept -> void {
        this->set_status(http_status_method_not_allowed);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 405 Method Not Allowed.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto method_not_allowed(std::string_view text) noexcept -> void {
        this->set_status(http_status_method_not_allowed);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 405 Method Not Allowed.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto method_not_allowed(std::string text) noexcept -> void {
        this->set_status(http_status_method_not_allowed);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 500 Internal Server Error without body.
    auto internal_server_error() noexcept -> void {
        this->set_status(http_status_internal_server_error);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 500 Internal Server Error.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto internal_server_error(const char *text) noexcept -> void {
        this->set_status(http_status_internal_server_error);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 500 Internal Server Error.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto internal_server_error(std::string_view text) noexcept -> void {
        this->set_status(http_status_internal_server_error);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 500 Internal Server Error.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto internal_server_error(std::string text) noexcept -> void {
        this->set_status(http_status_internal_server_error);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 503 Service Unavailable without body.
    auto service_unavailable() noexcept -> void {
        this->set_status(http_status_service_unavailable);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 503 Service Unavailable.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto service_unavailable(const char *text) noexcept -> void {
        this->set_status(http_status_service_unavailable);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 503 Service Unavailable.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto service_unavailable(std::string_view text) noexcept -> void {
        this->set_status(http_status_service_unavailable);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 503 Service Unavailable.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto service_unavailable(std::string text) noexcept -> void {
        this->set_status(http_status_service_unavailable);
        this->set_body(std::move(text));
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 505 HTTP Version Not Supported without body.
    auto http_version_not_supported() noexcept -> void {
        this->set_status(http_status_http_version_not_supported);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 505 HTTP Version Not Supported.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto http_version_not_supported(const char *text) noexcept -> void {
        this->set_status(http_status_http_version_not_supported);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 505 HTTP Version Not Supported.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto http_version_not_supported(std::string_view text) noexcept -> void {
        this->set_status(http_status_http_version_not_supported);
        this->set_body(text);
    }

    /// \brief
    ///   Set the HTTP response as a redirect with HTTP status code 505 HTTP Version Not Supported.
    /// \param text
    ///   The body to be set as the HTTP response body. This method assumes that the body is UTF-8 plaintext.
    auto http_version_not_supported(std::string text) noexcept -> void {
        this->set_status(http_status_http_version_not_supported);
        this->set_body(std::move(text));
    }
};

/// \struct http_context
/// \brief
///   HTTP context for handling HTTP requests.
struct http_context {
    /// \brief
    ///   The HTTP server object that is serving current HTTP service.
    http_server &server;

    /// \brief
    ///   Current HTTP request.
    http_request request;

    /// \brief
    ///   The HTTP response to be sent.
    http_response response;
};

/// \class http_router
/// \brief
///   HTTP path router implemented in radix tree.
class http_router {
public:
    /// \brief
    ///   Create an empty HTTP router.
    http_router() noexcept = default;

    /// \brief
    ///   \c http_router is not copyable.
    http_router(const http_router &other) noexcept = delete;

    /// \brief
    ///   Move constructor of \c http_router.
    /// \param[inout] other
    ///   The \c http_router to be moved from. The moved \c http_router will be in a valid but undefined state.
    http_router(http_router &&other) noexcept = default;

    /// \brief
    ///   Destroy this \c http_router.
    ~http_router() noexcept = default;

    /// \brief
    ///   \c http_router is not copyable.
    auto operator=(const http_router &other) noexcept = delete;

    /// \brief
    ///   Move assignment of \c http_router.
    /// \param[inout] other
    ///   The \c http_router to be moved. The moved \c http_router will be in a valid but undefined state.
    /// \return
    ///   Reference to this \c http_router.
    auto operator=(http_router &&other) noexcept -> http_router & = default;

    /// \brief
    ///   Add a new HTTP handler for the given path and method. The original handler and path params will be replaced if
    ///   the path and method already exists.
    /// \param path
    ///   The path to be matched. The path should be in the format of "/path/to/resource" or "/path/to/resource/:param"
    ///   or "/path/to/resource/:param/:param2". The path will be escaped before matching.
    /// \param handler
    ///   The handler to be called when the path is matched.
    ONION_API auto map(std::string_view path, std::function<task<>(http_context &)> handler) noexcept -> void;

    /// \brief
    ///   Match the given path and method with the registered handlers.
    /// \note
    ///   Currently depth-first matching is used to match the path.
    /// \param[inout] context
    ///   The HTTP context to be matched. The matched path parameters will be stored in the http request.
    /// \return
    ///   A task that could be scheduled if and only if the path is matched. Otherwise, return a null task.
    [[nodiscard]] ONION_API auto match(http_context &context) const noexcept -> task<>;

private:
    /// \struct radix_node
    /// \brief
    ///   Radix tree node.
    struct radix_node {
        /// \brief
        ///   The node that could be used to match any path component. This should be matched if and only if non of
        ///   named path rules matches current path.
        std::unique_ptr<radix_node> match_any = nullptr;

        /// \brief
        ///   Named path rules.
        unordered_flat_map<std::string, radix_node> next;

        /// \brief
        ///   Pattern for the handler if this node is a leaf node.
        std::string pattern;

        /// \brief
        ///   Handler for current node.
        std::function<task<>(http_context &)> handler;
    };

    /// \brief
    ///   Root node of router radix tree.
    radix_node m_root;
};

/// \class http_server
/// \brief
///   HTTP server application.
class http_server {
public:
    /// \brief
    ///   Create an HTTP server.
    http_server() noexcept = default;

    /// \brief
    ///   Create a new HTTP server that listens on the specified TCP address.
    /// \param[in] address
    ///   The TCP address to be listened.
    explicit http_server(const inet_address &address) noexcept
        : m_kind{stream_kind::tcp_stream},
          m_address{.inet = address} {}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Create a new HTTP server that listens on the specified Unix socket address.
    /// \param address
    ///   The Unix socket address to be listened.
    /// \throws std::invalid_argument
    ///   Thrown if \p address is too long for the Unix socket address.
    explicit http_server(std::string_view address) : m_kind{stream_kind::unix_stream} {
        if (address.size() >= sizeof(this->m_address.unix_socket.sun_path))
            throw std::invalid_argument("Unix socket address is too long");

        this->m_address.unix_socket.sun_family = AF_UNIX;
        std::memcpy(this->m_address.unix_socket.sun_path, address.data(), address.size());
        this->m_address.unix_socket.sun_path[address.size()] = '\0';
    }
#endif

    /// \brief
    ///   Create a new HTTP server that uses the specified IO context pool.
    /// \param[in] context
    ///   The IO context pool to be used by this HTTP server. This context pool should not be started when this
    ///   constructor is called.
    explicit http_server(io_context_pool &context) noexcept : m_context{&context} {}

    /// \brief
    ///   Create a new HTTP server that uses the specified IO context pool and listens on the specified TCP address.
    /// \param[in] context
    ///   The IO context pool to be used by this HTTP server. This context pool should not be started when this
    ///   constructor is called.
    /// \param[in] address
    ///   The TCP address to be listened.
    http_server(io_context_pool &context, const inet_address &address) noexcept
        : m_kind{stream_kind::tcp_stream},
          m_context{&context},
          m_address{.inet = address} {}

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Create a new HTTP server that uses the specified IO context pool and listens on the specified Unix socket
    ///   address.
    /// \param[in] context
    ///   The IO context pool to be used by this HTTP server. This context pool should not be started when this
    ///   constructor is called.
    /// \param address
    ///   The Unix socket address to be listened.
    /// \throws std::invalid_argument
    ///   Thrown if \p address is too long for the Unix socket address.
    http_server(io_context_pool &context, std::string_view address) : m_context{&context} {
        if (address.size() >= sizeof(this->m_address.unix_socket.sun_path))
            throw std::invalid_argument("Unix socket address is too long");
        this->m_kind                           = stream_kind::unix_stream;
        this->m_address.unix_socket.sun_family = AF_UNIX;
        std::memcpy(this->m_address.unix_socket.sun_path, address.data(), address.size());
        this->m_address.unix_socket.sun_path[address.size()] = '\0';
    }
#endif

    /// \brief
    ///   \c http_server is not copyable.
    http_server(const http_server &other) noexcept = delete;

    /// \brief
    ///   \c http_server is not movable.
    http_server(http_server &&other) noexcept = delete;

    /// \brief
    ///   Destroy this HTTP server.
    ONION_API ~http_server() noexcept;

    /// \brief
    ///   \c http_server is not copyable.
    auto operator=(const http_server &other) noexcept = delete;

    /// \brief
    ///   \c http_server is not movable.
    auto operator=(http_server &&other) noexcept = delete;

    /// \brief
    ///   Listen to the specified TCP address.
    /// \param[in] address
    ///   The TCP address to be listened.
    auto listen(const inet_address &address) noexcept -> void {
        this->m_kind    = stream_kind::tcp_stream;
        this->m_address = {.inet = address};
    }

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Listen to the specified Unix socket address.
    /// \param address
    ///   The Unix socket address to be listened.
    /// \throws std::invalid_argument
    ///   Thrown if \p address is too long for the Unix socket address.
    auto listen(std::string_view address) -> void {
        if (address.size() >= sizeof(this->m_address.unix_socket.sun_path))
            throw std::invalid_argument("Unix socket address is too long");

        this->m_kind                           = stream_kind::unix_stream;
        this->m_address.unix_socket.sun_family = AF_UNIX;
        std::memcpy(this->m_address.unix_socket.sun_path, address.data(), address.size());
        this->m_address.unix_socket.sun_path[address.size()] = '\0';
    }
#endif

    /// \brief
    ///   Try to add a new service into this HTTP server. There could be at most 1 service for each type and the new
    ///   service will not be added if there is already one.
    /// \tparam T
    ///   Type of the service to be added.
    /// \param args
    ///   Arguments to be passed to the constructor of the service.
    /// \return
    ///   Reference to the added service if the service is added successfully. Otherwise, return a reference to the
    ///   existing service.
    template <typename T, typename... Args>
        requires(std::is_constructible_v<T, Args && ...>)
    auto add_service(Args &&...args) -> T & {
        auto iter = this->m_services.find(typeid(T));
        if (iter != this->m_services.end())
            return *static_cast<T *>(iter->second.object);

        auto *object  = new T{std::forward<Args>(args)...};
        auto *deleter = +[](void *pointer) { delete static_cast<T *>(pointer); };

        this->m_services.insert({std::type_index{typeid(T)}, service{object, object, deleter}});
        return *object;
    }

    /// \brief
    ///   Try to add a new service as an interface type into this HTTP server. There could be at most 1 service for each
    ///   interface type and the new service will not be added if there is already one.
    /// \tparam I
    ///   Interface type of the service to be added. The implementation type \c T must be derived from \c I.
    /// \tparam T
    ///   Implementation type of the service to be added. The implementation type \c T must be derived from \c I.
    /// \param args
    ///   Arguments to be passed to the constructor of the service.
    /// \return
    ///   Reference to the added service if the service is added successfully. Otherwise, return a reference to the
    ///   existing service.
    template <typename I, typename T, typename... Args>
        requires(std::is_base_of_v<I, T> && std::is_constructible_v<T, Args && ...>)
    auto add_service(Args &&...args) -> I & {
        auto iter = this->m_services.find(typeid(I));
        if (iter != this->m_services.end())
            return *static_cast<I *>(iter->second.interface);

        auto *object    = new T{std::forward<Args>(args)...};
        auto *interface = static_cast<I *>(object);
        auto *deleter   = +[](void *pointer) { delete static_cast<T *>(pointer); };

        this->m_services.insert({std::type_index{typeid(I)}, service{interface, object, deleter}});
        return *interface;
    }

    /// \brief
    ///   Get the service of the specified type from this HTTP server.
    /// \tparam T
    ///   Type of the service to be retrieved. This could be either the implementation type or the interface type.
    /// \return
    ///   Pointer to the service of the specified type if the service is found. Otherwise, return \c nullptr.
    template <typename T>
    auto get_service() const noexcept -> T * {
        auto iter = this->m_services.find(typeid(T));
        if (iter == this->m_services.end())
            return nullptr;
        return static_cast<T *>(iter->second.interface);
    }

    /// \brief
    ///   Add a new middleware to this HTTP server. This method is not concurrent safe.
    /// \tparam Func
    ///   The type of the middleware function.
    /// \param middleware
    ///   The middleware function to be added.
    /// \note
    ///   The middleware function should be a coroutine function that takes a \c http_context and a \c task<> as
    ///   parameters. The middleware function should call the \c next task to continue the request handling. The
    ///   middleware function should not throw any exception.
    template <typename Func>
    auto use(Func &&middleware) noexcept -> void {
        if (this->m_middleware != nullptr) {
            this->m_middleware = [prev = std::move(this->m_middleware), middleware = std::forward<Func>(middleware)](
                                     http_context &ctx, task<> next) -> task<> {
                co_await middleware(ctx, prev(ctx, std::move(next)));
            };
        } else {
            this->m_middleware = std::forward<Func>(middleware);
        }
    }

    /// \brief
    ///   Add a new HTTP handler to this HTTP server. This method is not concurrent safe.
    /// \tparam Func
    ///   The type of the handler function.
    /// \param method
    ///   The HTTP method to be handled.
    /// \param path
    ///   The HTTP path to be handled.
    /// \param handler
    ///   The handler function to be added.
    template <typename Func>
    auto map(http_method method, std::string_view path, Func &&handler) noexcept -> void {
        this->m_routers[method].map(path, std::forward<Func>(handler));
    }

    /// \brief
    ///   Initialize IO context pool, create listeners and start handling HTTP requests. This method blocks current
    ///   thread until the server is stopped.
    /// \throws std::system_error
    ///   Thrown if failed to create IO context pool or failed to listen to incoming connections.
    /// \throws std::runtime_error
    ///   Thrown if no address is specified.
    ONION_API auto run() -> void;

private:
    /// \brief
    ///   Handle incoming HTTP connection.
    /// \param stream
    ///   The incoming TCP stream.
    /// \return
    ///   A task to be scheduled to handle HTTP requests.
    auto handle_connection(tcp_stream stream) noexcept -> task<>;

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
    /// \brief
    ///   Handle incoming HTTP connection.
    /// \param stream
    ///   The incoming unix domain socket stream.
    /// \return
    ///   A task to be scheduled to handle HTTP requests.
    auto handle_connection(unix_stream stream) noexcept -> task<>;
#endif

private:
    /// \struct service
    /// \brief
    ///   Type-erased service object.
    struct service {
        void *interface;
        void *object;
        void (*destroy)(void *);
    };

    /// \enum stream_kind
    /// \brief
    ///   Represents underlying listener kind for this HTTP server.
    enum class stream_kind {
        none,
        tcp_stream,
        unix_stream,
    };

    /// \brief
    ///   Underlying listener kind for this HTTP server.
    stream_kind m_kind = stream_kind::none;

    /// \brief
    ///   A boolean that indicates whether this HTTP server owns the context pool.
    mutable bool m_own_context = false;

    /// \brief
    ///   Underlying IO context pool for this HTTP server.
    mutable io_context_pool *m_context = nullptr;

    /// \brief
    ///   Listener for this HTTP server.
    union {
        /// \brief
        ///   A placeholder that indicates there is no listener constructed.
        std::nullptr_t null;

        /// \brief
        ///   TCP address to listen.
        inet_address inet;

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
        /// \brief
        ///   Unix socket address to listen.
        sockaddr_un unix_socket;
#endif
    } m_address{.null = nullptr};

    /// \brief
    ///   Middlewares for this HTTP server.
    std::function<task<>(http_context &, task<>)> m_middleware;

    /// \brief
    ///   Routers for this HTTP server.
    unordered_flat_map<http_method, http_router> m_routers;

    /// \brief
    ///   Service map for this HTTP server. TODO: Use static reflection instead of RTTI.
    unordered_flat_map<std::type_index, service> m_services;
};

} // namespace onion
