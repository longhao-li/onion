#pragma once

#include "socket.hpp"

#include <unordered_map>

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
    http_method_get,
    http_method_head,
    http_method_post,
    http_method_put,
    http_method_delete,
    http_method_connect,
    http_method_options,
    http_method_trace,
    http_method_patch,
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

/// \struct http_url
/// \brief
///   HTTP URL structure.
struct http_url {
    std::string schema;
    std::string username;
    std::string password;
    std::string host;
    std::string path;
    std::string query;
    std::string fragment;
};

/// \class http_header
/// \brief
///   HTTP header map.
class http_header {
public:
    using key_type        = std::string;
    using mapped_type     = std::string;
    using value_type      = std::pair<const key_type, mapped_type>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using hasher          = detail::case_insensitive_hash;
    using key_equal       = detail::case_insensitive_equal;
    using reference       = value_type &;
    using const_reference = const value_type &;
    using pointer         = typename std::unordered_map<std::string, std::string, hasher, key_equal>::pointer;
    using const_pointer   = typename std::unordered_map<std::string, std::string, hasher, key_equal>::const_pointer;
    using iterator        = typename std::unordered_map<std::string, std::string, hasher, key_equal>::iterator;
    using const_iterator  = typename std::unordered_map<std::string, std::string, hasher, key_equal>::const_iterator;

    /// \brief
    ///   Create an empty \c http_header map.
    http_header() noexcept = default;

    /// \brief
    ///   Copy construct of \c http_header map.
    /// \param other
    ///   The \c http_header map to copy from.
    http_header(const http_header &other) = default;

    /// \brief
    ///   Move construct an \c http_header map.
    /// \param[inout] other
    ///   The \c http_header map to move. The moved \c http_header map is left in a valid but unspecified state.
    http_header(http_header &&other) noexcept = default;

    /// \brief
    ///   Destroy this \c http_header map.
    ~http_header() noexcept = default;

    /// \brief
    ///   Copy assignment of \c http_header map.
    /// \param other
    ///   The \c http_header map to copy from.
    /// \return
    ///   Reference to this \c http_header map.
    auto operator=(const http_header &other) -> http_header & = default;

    /// \brief
    ///   Move assignment of \c http_header map.
    /// \param[inout] other
    ///   The \c http_header map to move. The moved \c http_header map is left in a valid but unspecified state.
    /// \return
    ///   Reference to this \c http_header map.
    auto operator=(http_header &&other) noexcept -> http_header & = default;

    /// \brief
    ///   Get iterator to the first element of the \c http_header map.
    /// \return
    ///   Iterator to the first element of the \c http_header map.
    [[nodiscard]] auto begin() noexcept -> iterator {
        return this->m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the first element of the \c http_header map.
    /// \return
    ///   Iterator to the first element of the \c http_header map.
    [[nodiscard]] auto begin() const noexcept -> const_iterator {
        return this->m_headers.begin();
    }

    /// \brief
    ///   Get iterator to the first element of the \c http_header map.
    /// \return
    ///   Iterator to the first element of the \c http_header map.
    [[nodiscard]] auto cbegin() const noexcept -> const_iterator {
        return this->m_headers.cbegin();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header map.
    [[nodiscard]] auto end() noexcept -> iterator {
        return this->m_headers.end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header map.
    [[nodiscard]] auto end() const noexcept -> const_iterator {
        return this->m_headers.end();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this \c http_header map.
    /// \return
    ///   Iterator to the place after the last element in this \c http_header map.
    [[nodiscard]] auto cend() const noexcept -> const_iterator {
        return this->m_headers.cend();
    }

    /// \brief
    ///   Checks if this \c http_header map is empty.
    /// \retval true
    ///   This \c http_header map is empty.
    /// \retval false
    ///   This \c http_header map is not empty.
    [[nodiscard]] auto empty() const noexcept -> bool {
        return this->m_headers.empty();
    }

    /// \brief
    ///   Get number of HTTP header items in this \c http_header map. Please notice that HTTP allows multiple header
    ///   items with the same key and they are counted separately.
    /// \return
    ///   Number of HTTP header items in this \c http_header map.
    [[nodiscard]] auto size() const noexcept -> size_type {
        return this->m_headers.size();
    }

    /// \brief
    ///   Clear all HTTP headers in this \c http_header map.
    auto clear() noexcept -> void {
        this->m_headers.clear();
    }

    /// \brief
    ///   Insert a new HTTP header item into this HTTP header map.
    /// \return
    ///   Iterator to the newly added HTTP header item.
    auto insert(std::string key, std::string value) noexcept -> iterator {
        return this->m_headers.emplace(std::move(key), std::move(value));
    }

    /// \brief
    ///   Remove all HTTP header items with the specified key.
    /// \param key
    ///   Key of HTTP header items to be removed.
    /// \return
    ///   Number of HTTP header items removed from this \c http_header map.
    auto erase(const std::string &key) noexcept -> size_type {
        return this->m_headers.erase(key);
    }

private:
    /// \brief
    ///   Generic container for HTTP headers.
    std::unordered_multimap<std::string, std::string, hasher, key_equal> m_headers;
};

} // namespace onion
