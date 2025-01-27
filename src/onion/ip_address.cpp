#include "onion/ip_address.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#    include <WS2tcpip.h>
#endif

using namespace onion;

IpAddress::IpAddress(std::string_view address) : m_isIpv6{}, m_addr{} {
    std::array<char, INET6_ADDRSTRLEN> buffer;
    if (address.size() >= buffer.size())
        throw std::invalid_argument("Invalid IP address: " + std::string(address));

    // Copy the address into the buffer to make it null-terminated.
    std::ranges::copy(address, buffer.begin());
    buffer[address.size()] = '\0';

    std::uint16_t family;
    if (address.find(':') == std::string_view::npos) {
        family   = AF_INET;
        m_isIpv6 = false;
    } else {
        family   = AF_INET6;
        m_isIpv6 = true;
    }

    if (inet_pton(family, buffer.data(), &m_addr) != 1) [[unlikely]]
        throw std::invalid_argument("Invalid IP address: " + std::string(address));
}
