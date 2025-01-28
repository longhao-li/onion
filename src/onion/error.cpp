#include "onion/error.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <Windows.h>
#endif

#include <array>
#include <cstring>

using namespace onion;

auto SystemErrorCode::message() const noexcept -> std::string {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    std::array<char, 1024> buffer;

    DWORD length =
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                       static_cast<DWORD>(m_code), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                       buffer.data(), static_cast<DWORD>(buffer.size()), nullptr);

    return {buffer.begin(), buffer.begin() + length};
#else
    return std::strerror(m_code);
#endif
}
