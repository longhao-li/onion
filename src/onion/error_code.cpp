#include "onion/error_code.hpp"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <Windows.h>
#else
#    include <cstring>
#endif

using namespace onion;

auto SystemErrorCode::message() const noexcept -> std::string {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    char buffer[512]{};
    DWORD length =
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                       static_cast<DWORD>(m_code), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                       buffer, static_cast<DWORD>(sizeof(buffer)), nullptr);

    return {buffer, length};
#else
    return std::strerror(m_code);
#endif
}
