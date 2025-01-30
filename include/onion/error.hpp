#pragma once

#include <cstdint>
#include <string>

namespace onion {

/// \class SystemErrorCode
/// \brief
///   Wrapper class for system error code.
class SystemErrorCode {
public:
    /// \brief
    ///   Construct a \c SystemErrorCode that represents no error.
    constexpr SystemErrorCode() noexcept : m_code{0} {}

    /// \brief
    ///   Construct a \c SystemErrorCode with the given error code.
    /// \param code
    ///   System error code value.
    constexpr SystemErrorCode(std::int32_t code) noexcept : m_code{code} {}

    /// \brief
    ///   Checks if this \c SystemErrorCode represents an error.
    /// \retval true
    ///   This \c SystemErrorCode represents no error.
    /// \retval false
    ///   This \c SystemErrorCode represents an error.
    [[nodiscard]]
    constexpr auto ok() const noexcept -> bool {
        return m_code == 0;
    }

    /// \brief
    ///   Get error code value of this \c SystemErrorCode. 0 means no error.
    /// \return
    ///   Error code value of this \c SystemErrorCode.
    [[nodiscard]]
    constexpr auto value() const noexcept -> std::int32_t {
        return m_code;
    }

    /// \brief
    ///   Get error message of this \c SystemErrorCode.
    /// \return
    ///   Error message of this \c SystemErrorCode.
    [[nodiscard]]
    ONION_API auto message() const noexcept -> std::string;

    /// \brief
    ///   Check if this \c SystemErrorCode is equal to another \c SystemErrorCode.
    /// \param other
    ///   The \c SystemErrorCode to compare with.
    /// \retval true
    ///   This \c SystemErrorCode is equal to \c other.
    /// \retval false
    ///   This \c SystemErrorCode is not equal to \c other.
    [[nodiscard]]
    constexpr auto operator==(SystemErrorCode other) const noexcept -> bool {
        return m_code == other.m_code;
    }

    /// \brief
    ///   Compare this \c SystemErrorCode with another \c SystemErrorCode.
    /// \param other
    ///   The \c SystemErrorCode to compare with.
    /// \retval std::strong_ordering::equal
    ///   This \c SystemErrorCode is equal to \c other.
    /// \retval std::strong_ordering::less
    ///   This \c SystemErrorCode is less than \c other.
    /// \retval std::strong_ordering::greater
    ///   This \c SystemErrorCode is greater than \c other.
    [[nodiscard]]
    constexpr auto operator<=>(SystemErrorCode other) const noexcept -> std::strong_ordering {
        return m_code <=> other.m_code;
    }

private:
    /// \brief
    ///   System error code. For Windows, this is the value returned by \c GetLastError(); For other
    ///   platforms, this is the value of \c errno.
    std::int32_t m_code;
};

} // namespace onion
