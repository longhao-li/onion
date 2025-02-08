#include "onion/map.hpp"

using namespace onion::detail;
using namespace onion::detail::hash;

alignas(16) constexpr const ControlFlag onion::detail::hash::EmptyGroup[32] = {
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Zero,     ControlFlag::Zero,  ControlFlag::Zero,  ControlFlag::Zero,
    ControlFlag::Sentinel, ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
    ControlFlag::Empty,    ControlFlag::Empty, ControlFlag::Empty, ControlFlag::Empty,
};
