#pragma once

#include "hash.hpp"

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#    include <emmintrin.h>
#endif

#include <bit>
#include <cstring>
#include <stdexcept>

namespace onion::detail {
namespace hash {

/// \enum ControlFlag
/// \brief
///   Control flag for swiss-table hash-map slot status.
enum class ControlFlag : std::int8_t {
    Zero     = 0,
    Empty    = static_cast<std::int8_t>(0x80),
    Deleted  = static_cast<std::int8_t>(0xFE),
    Sentinel = static_cast<std::int8_t>(0xFF),
};

/// \brief
///   Empty control group for hash-container slots.
ONION_API extern const ControlFlag EmptyGroup[32];

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
/// \brief
///   Number of slots per group.
inline constexpr std::size_t GroupWidth = 16;

/// \class BitMask
/// \brief
///   Bit mask for swiss-table hash container. A bitmask stores status for a group of slots. Usually
///   this is used to handle result of SIMD operations.
class BitMask {
public:
    /// \brief
    ///   Create a \c BitMask with the specified value.
    /// \param value
    ///   Value of this \c BitMask.
    constexpr BitMask(std::uint16_t value) noexcept : m_mask{value} {}

    /// \brief
    ///   Allow iterating over \c BitMask. Iterating over \c BitMask generates masks with the least
    ///   bit removed one by one.
    /// \return
    ///   A copy of this \c BitMask.
    [[nodiscard]]
    constexpr auto begin() const noexcept -> BitMask {
        return *this;
    }

    /// \brief
    ///   Allow iterating over \c BitMask. Iterating over \c BitMask generates masks with the least
    ///   bit removed one by one.
    /// \return
    ///   A zero \c BitMask as a sentinel.
    [[nodiscard]]
    constexpr auto end() const noexcept -> BitMask {
        return {0};
    }

    /// \brief
    ///   Get value of this \c BitMask.
    /// \return
    ///   Value of this \c BitMask.
    [[nodiscard]]
    constexpr auto value() const noexcept -> std::uint16_t {
        return m_mask;
    }

    /// \brief
    ///   Get index of the lowest bit 1 in this \c BitMask. This value is also the same as trailing
    ///   zero bits. Do not call this method if the mask value is 0.
    /// \return
    ///   Index of the lowest bit 1 in this \c BitMask.
    [[nodiscard]]
    constexpr auto indexOfLowestBit() const noexcept -> std::uint32_t {
        return std::countr_zero(m_mask);
    }

    /// \brief
    ///   Get index of the highest bit 1 in this \c BitMask. Do not call this method if the mask
    ///   value is 0.
    /// \return
    ///   Index of the highest bit 1 in this \c BitMask.
    [[nodiscard]]
    constexpr auto indexOfHighestBit() const noexcept -> std::uint32_t {
        return static_cast<std::uint32_t>(std::bit_width(m_mask) - 1);
    }

    /// \brief
    ///   Get number of trailing zero bit in this Mask. This value is also the same as index of the
    ///   lowest bit 1. Do not call this method if the mask value is 0.
    /// \return
    ///   Number of trailing zero bit in this Mask.
    [[nodiscard]]
    constexpr auto trailingZeroCount() const noexcept -> std::uint32_t {
        return indexOfLowestBit();
    }

    /// \brief
    ///   Get number of leading zeros of this mask.
    /// \return
    ///   Number of leading zeros of this mask.
    [[nodiscard]]
    constexpr auto leadingZeroCount() const noexcept -> std::uint32_t {
        constexpr std::uint32_t extraBits = sizeof(std::uint16_t) * 8 - GroupWidth;
        return std::countl_zero(static_cast<std::uint32_t>(m_mask) << extraBits);
    }

    /// \brief
    ///   Move to the next \c BitMask. Removes the least bit of this \c BitMask.
    /// \return
    ///   Reference to this \c BitMask after removing the least bit.
    constexpr auto operator++() noexcept -> BitMask & {
        m_mask &= (m_mask - 1);
        return *this;
    }

    /// \brief
    ///   Get index of lowest bit in this mask.
    /// \return
    ///   Index of lowest bit in this mask.
    [[nodiscard]]
    constexpr auto operator*() const noexcept -> std::uint32_t {
        return indexOfLowestBit();
    }

    /// \brief
    ///   Checks if this mask is 0.
    /// \retval true
    ///   This mask is not 0.
    /// \retval false
    ///   This mask is 0.
    constexpr explicit operator bool() const noexcept {
        return m_mask != 0;
    }

    /// \brief
    ///   Checks if the given two \c BitMask objects are the same.
    /// \param lhs
    ///   The first \c BitMask to compare.
    /// \param rhs
    ///   The second \c BitMask to compare.
    /// \retval true
    ///   \p lhs is the same as \p rhs.
    /// \retval false
    ///   \p lhs is different from \p rhs.
    [[nodiscard]]
    friend constexpr auto operator==(BitMask lhs, BitMask rhs) noexcept -> bool {
        return lhs.m_mask == rhs.m_mask;
    }

    /// \brief
    ///   Checks if the given two \c BitMask objects are different.
    /// \param lhs
    ///   The first \c BitMask to compare.
    /// \param rhs
    ///   The second \c BitMask to compare.
    /// \retval true
    ///   \p lhs is different from \p rhs.
    /// \retval false
    ///   \p lhs is the same as \p rhs.
    [[nodiscard]]
    friend constexpr auto operator!=(BitMask lhs, BitMask rhs) noexcept -> bool {
        return lhs.m_mask != rhs.m_mask;
    }

private:
    /// \brief
    ///   Value of this mask.
    std::uint16_t m_mask;
};

/// \class Group
/// \brief
///   Group of control flags for hash container slot status. Number of slots per group is set to 16
///   to make sure that the control bytes are aligned to 16.
class Group {
public:
    /// \brief
    ///   Load a group of control flags.
    /// \param[in] position
    ///   Pointer to the group of control flags to be loaded. Must be aligned with 16 bytes.
    explicit Group(const ControlFlag *position) noexcept
        : m_control{_mm_loadu_si128(reinterpret_cast<const __m128i *>(position))} {}

    /// \brief
    ///   Checks if there is any objects in current group that matches the specified H2 hash value.
    ///   This method checks 16 hash values at the same time with SIMD instructions.
    /// \return
    ///   A bit mask that represents whether each object in current group matches the specified hash
    ///   value.
    [[nodiscard]]
    auto match(std::uint8_t hash) const noexcept -> BitMask {
        // Fill XMM register with H2 hash value.
        __m128i match = _mm_set1_epi8(static_cast<char>(hash));
        // Compare with current group. Slots that matches will be stored as 0xFF.
        __m128i compare = _mm_cmpeq_epi8(match, m_control);
        // Gather the highest bit of each slot.
        return {static_cast<std::uint16_t>(_mm_movemask_epi8(compare))};
    }

    /// \brief
    ///   Get a mask that represents empty slots.
    /// \return
    ///   A mask that represents empty slots.
    [[nodiscard]]
    auto maskEmpty() const noexcept -> BitMask {
        // Empty slots.
        __m128i mask = _mm_set1_epi8(static_cast<char>(ControlFlag::Empty));
        // Get all slots that are equal to ControlFlag::Empty.
        __m128i compare = _mm_cmpeq_epi8(mask, m_control);
        // Convert to bit-fields.
        return {static_cast<std::uint16_t>(_mm_movemask_epi8(compare))};
    }

    /// \brief
    ///   Get a mask that represents slots that have values in this group.
    /// \return
    ///   A bit mask that represents whether each slot contains a value.
    [[nodiscard]]
    auto maskFull() const noexcept -> BitMask {
        // Slots with the highest bit set are non-filled slots.
        int emptys = _mm_movemask_epi8(m_control);
        // Reverse non-filled slots. We only care about the lowest 16 bits.
        return {static_cast<std::uint16_t>(emptys ^ 0xFFFF)};
    }

    /// \brief
    ///   Get a mask that represents slots that are not filled in this group.
    /// \return
    ///   A bit mask that represents whether each slot is not filled.
    [[nodiscard]]
    auto maskNonFull() const noexcept -> BitMask {
        // Slots with the highest bit set are non-filled slots.
        return {static_cast<std::uint16_t>(_mm_movemask_epi8(m_control))};
    }

    /// \brief
    ///   Get a mask that represents slots that are empty or deleted in this group.
    /// \return
    ///   A bit mask that represents whether each slot is empty or deleted.
    [[nodiscard]]
    auto maskEmptyOrDeleted() const noexcept -> BitMask {
        // Fill XMM register with 0xFF.
        __m128i sentinel = _mm_set1_epi8(static_cast<char>(ControlFlag::Sentinel));
        // Empty and deleted control flags are 0x80 and 0xFE which are less than -1.
        __m128i compare = _mm_cmpgt_epi8(sentinel, m_control);
        // Gather the highest bit of each slot.
        return {static_cast<std::uint16_t>(_mm_movemask_epi8(compare))};
    }

    /// \brief
    ///   Count the number of leading empty or deleted slots in this group.
    /// \return
    ///   Number of leading empty or deleted slots in this group.
    [[nodiscard]]
    auto countLeadingEmptyOrDeleted() const noexcept -> std::uint32_t {
        // Fill XMM register with 0xFF.
        __m128i sentinel = _mm_set1_epi8(static_cast<char>(ControlFlag::Sentinel));
        // Empty and deleted control flags are 0x80 and 0xFE which are less than -1.
        __m128i compare = _mm_cmpgt_epi8(sentinel, m_control);
        // Gather the highest bit of each slot and count.
        return std::countr_zero(static_cast<std::uint32_t>(_mm_movemask_epi8(compare) + 1));
    }

private:
    __m128i m_control;
};
#endif

/// \brief
///   Value mask for growth information.
inline constexpr std::size_t GrowthInfoValueMask = (~std::size_t{} >> 1);

/// \brief
///   Deleted bit for growth information.
inline constexpr std::size_t GrowthInfoDeletedBit = ~GrowthInfoValueMask;

/// \class GrowthInfo
/// \brief
///   Growth information for hash container. Stores number of slots to grow without having to rehash
///   the whole hash container.
class GrowthInfo {
public:
    /// \brief
    ///   Leave \c GrowthInfo uninitialized.
    GrowthInfo() noexcept = default;

    /// \brief
    ///   Initialize \c GrowthInfo with the specified growth info value.
    /// \param info
    ///   Initial growth info value.
    constexpr GrowthInfo(std::size_t info) noexcept : m_info{info} {}

    /// \brief
    ///   Marks that there is a full slot in the hash container converted into empty slot.
    constexpr auto overwriteFullAsEmpty() noexcept -> void {
        ++m_info;
    }

    /// \brief
    ///   Marks that there is an empty slot in the hash container converted into full slot.
    constexpr auto overwriteEmptyAsFull() noexcept -> void {
        --m_info;
    }

    /// \brief
    ///   Marks that there are multiple empty slots in the hash container converted into full slots.
    /// \param count
    ///   Number of empty slots converted into full slots.
    constexpr auto overwriteManyEmptyAsFull(std::size_t count) noexcept -> void {
        m_info -= count;
    }

    /// \brief
    ///   Convert a slot to full if the specified flag is empty.
    /// \param flag
    ///   Control flag of the slot to check.
    constexpr auto overwriteControlAsFull(ControlFlag flag) noexcept -> void {
        if (flag == ControlFlag::Empty)
            --m_info;
    }

    /// \brief
    ///   Convert a slot from full to deleted.
    constexpr auto overwriteFullAsDeleted() noexcept -> void {
        m_info |= GrowthInfoDeletedBit;
    }

    /// \brief
    ///   Checks if there is no deleted node and there is growth left.
    /// \retval true
    ///   There is no deleted node and there is at least one growth left.
    /// \retval false
    ///   There is at least a deleted node or there is no growth left.
    [[nodiscard]]
    constexpr auto hasNoDeletedAndGrowthLeft() const noexcept -> bool {
        return static_cast<std::make_signed_t<std::size_t>>(m_info) > 0;
    }

    /// \brief
    ///   Checks if there is no growth left and no deleted node.
    /// \retval true
    ///   There is no growth left and there is no deleted node.
    /// \retval false
    ///   There is at least a deleted node or there is growth left.
    [[nodiscard]]
    constexpr auto hasNoGrowthLeftAndNoDeleted() const noexcept -> bool {
        return m_info == 0;
    }

    /// \brief
    ///   Checks if there is at least one deleted node.
    /// \retval true
    ///   There is at least one deleted node.
    /// \retval false
    ///   There is no deleted node.
    [[nodiscard]]
    constexpr auto hasDeleted() const noexcept -> bool {
        return static_cast<std::make_signed_t<std::size_t>>(m_info) < 0;
    }

    /// \brief
    ///   Get number of slots that could be grown without rehashing the whole hash container.
    /// \return
    ///   Number of slots that could be grown without rehashing the whole hash container.
    [[nodiscard]]
    constexpr auto growthLeft() const noexcept -> std::size_t {
        return m_info & GrowthInfoValueMask;
    }

private:
    std::size_t m_info;
};

static_assert(std::is_trivial_v<GrowthInfo>);
static_assert(sizeof(GrowthInfo) == sizeof(std::size_t));
static_assert(alignof(GrowthInfo) == alignof(std::size_t));

/// \class Layout
/// \brief
///   Helper class for computing offsets and allocating memory for hash container fields.
class Layout {
public:
    /// \brief
    ///   Create a new layout with the specified capacity and slot alignment.
    /// \param capacity
    ///   Capacity of the hash container.
    /// \param slotAlignment
    ///   Alignment of each slot. Must be power of 2.
    constexpr Layout(std::size_t capacity, std::size_t slotAlignment) noexcept
        : m_capacity{capacity},
          m_controlOffset{sizeof(GrowthInfo)},
          m_slotOffset{(m_controlOffset + capacity + GroupWidth + slotAlignment - 1) &
                       ~(slotAlignment - 1)} {}

    /// \brief
    ///   Get capacity of current hash container.
    /// \return
    ///   Capacity of current hash container.
    [[nodiscard]]
    constexpr auto capacity() const noexcept -> std::size_t {
        return m_capacity;
    }

    /// \brief
    ///   Get pre-computed offset from start of the backing allocation of control data.
    /// \return
    ///   Offset from start of the backing allocation of control data.
    [[nodiscard]]
    constexpr auto controlOffset() const noexcept -> std::size_t {
        return m_controlOffset;
    }

    /// \brief
    ///   Given capacity of a table, computes offset from start of the backing allocation at which
    ///   the slots begin.
    /// \return
    ///   Offset from start of the backing allocation at which the slots begin.
    [[nodiscard]]
    constexpr auto slotOffset() const noexcept -> std::size_t {
        return m_slotOffset;
    }

    /// \brief
    ///   Given slot size, computes the total size required by the backing array.
    /// \param slotSize
    ///   Size of each slot.
    [[nodiscard]]
    constexpr auto allocateSize(std::size_t slotSize) const noexcept -> std::size_t {
        return m_slotOffset + m_capacity * slotSize;
    }

private:
    std::size_t m_capacity;
    std::size_t m_controlOffset;
    std::size_t m_slotOffset;
};

/// \class ProbeSequence
/// \brief
///   Used to generate a sequence of probe offsets for a given hash value. The use of \c Width
///   ensures that each probe step does not overlap group boundaries.
/// \remarks
///   Quadratic probing is used for \c ProbeSequence. It turns out that this probe sequence visits
///   every group element exactly once when \c GroupWidth is a power of 2.
class ProbeSequence {
public:
    /// \brief
    ///   Create a \c ProbeSequence with the specified \p hash as the initial value of the sequence
    ///   and \p mask as the mask to apply to each value in the progression.
    /// \param hash
    ///   Initial value of the sequence.
    /// \param mask
    ///   Mask to apply to each value in the progression. Must be 2^N - 1.
    constexpr ProbeSequence(std::size_t hash, std::size_t mask) noexcept
        : m_mask{mask},
          m_offset{hash & mask},
          m_index{0} {}

    /// \brief
    ///   Get offset of the current probe step.
    /// \return
    ///   Offset of the current probe step.
    [[nodiscard]]
    constexpr auto offset() const noexcept -> std::size_t {
        return m_offset;
    }

    /// \brief
    ///   Get offset of the probe step after \p after indices.
    /// \param after
    ///   Index of the probe step after the current probe step.
    /// \return
    ///   Offset of the probe step after \p after indices.
    [[nodiscard]]
    constexpr auto offset(std::size_t after) const noexcept -> std::size_t {
        return (m_offset + after) & m_mask;
    }

    /// \brief
    ///   Move to the next probe step.
    constexpr auto next() noexcept -> void {
        m_index += GroupWidth;
        m_offset += m_index;
        m_offset &= m_mask;
    }

    /// \brief
    ///   Get 0-based probe index. It is guaranteed that index is always a multiple of \c Width.
    /// \return
    ///   0-based probe index.
    [[nodiscard]]
    constexpr auto index() const noexcept -> std::size_t {
        return m_index;
    }

private:
    std::size_t m_mask;
    std::size_t m_offset;
    std::size_t m_index;
};

/// \struct FindResult
/// \brief
///   Result of probing operations.
struct FindResult {
    std::size_t offset;
    std::size_t probeLength;
};

/// \brief
///   Get next capacity for hash container.
/// \param capacity
///   Current capacity of the hash container. Must be 2^N - 1.
/// \return
///   Next capacity for hash container.
[[nodiscard]]
constexpr auto nextCapacity(std::size_t capacity) noexcept -> std::size_t {
    return (capacity << 1) | 1;
}

/// \brief
///   Convert the given capacity to a normalized capacity. The normalized capacity is always 2^N
///   - 1.
/// \param capacity
///   Capacity to normalize.
/// \return
///   Normalized capacity.
[[nodiscard]]
constexpr auto normalizeCapacity(std::size_t capacity) noexcept -> std::size_t {
    return capacity ? (~std::size_t{} >> std::countl_zero(capacity)) : 1;
}

/// \brief
///   Given \p capacity, apply the load factor. We use 7/8 as maximum load factor.
///
///   - For capacity + 1 >= \c GroupWidth, the growth is 7 / 8 * \p capacity.
///   - For capacity + 1 < \c GroupWidth, the growth is \p capacity.
/// \param capacity
///   Capacity of the hash container.
/// \return
///   Number of slots that we should grow.
[[nodiscard]]
constexpr auto capacityToGrowth(std::size_t capacity) noexcept -> std::size_t {
    if constexpr (GroupWidth == 8) {
        if (capacity == 7)
            return 6;
    }
    return capacity - (capacity / 8);
}

/// \brief
///   Given \p growth, unapplies the load factor to find how large the capacity should be to stay
///   within the load factor.
/// \note
///   The return value may not be a valid capacity. You should call \c normalizeCapacity to get a
///   valid capacity.
/// \param growth
///   Number of slots to grow.
/// \return
///   Capacity required to store the specified number of elements in the hash container.
[[nodiscard]]
constexpr auto growthToLowerboundCapacity(std::size_t growth) noexcept -> std::size_t {
    if constexpr (GroupWidth == 8) {
        if (growth == 7)
            return 8;
    }
    return growth + static_cast<std::size_t>((static_cast<std::uint64_t>(growth) - 1) / 7);
}

/// \struct AlignedStruct
/// \brief
///   Dummy struct to allocate aligned memory.
template <std::size_t Alignment>
struct alignas(Alignment) AlignedStruct {};

/// \brief
///   Used to allocate memory with alignment with the specified allocator.
/// \tparam Alignment
///   Alignment of the memory to allocate.
/// \tparam Allocator
///   Type of the allocator to allocate aligned memory.
/// \param[in] allocator
///   Allocator to allocate memory. Should not be null.
/// \param size
///   Expected number of blocks to allocate.
template <std::size_t Alignment, typename Allocator>
auto alignedAllocate(Allocator &allocator, std::size_t size) -> void * {
    using Aligned = AlignedStruct<Alignment>;

    using alloc_traits         = std::allocator_traits<Allocator>;
    using aligned_allocator    = typename alloc_traits::template rebind_alloc<Aligned>;
    using aligned_alloc_traits = typename alloc_traits::template rebind_traits<Aligned>;

    aligned_allocator alloc{allocator};
    // Allocate memory with aligned size rounded up.
    return aligned_alloc_traits::allocate(alloc, (size + sizeof(Aligned) - 1) / sizeof(Aligned));
}

/// \brief
///   Used to deallocate memory with alignment with the specified allocator.
/// \tparam Alignment
///   Alignment of the memory to deallocate.
/// \tparam Allocator
///   Type of the allocator to deallocate aligned memory.
/// \param[in] allocator
///   Allocator to deallocate memory. Should not be null.
/// \param[inout] pointer
///   Pointer to the memory to deallocate.
/// \param size
///   Expected number of blocks to deallocate.
template <std::size_t Alignment, typename Allocator>
auto alignedDeallocate(Allocator &allocator, void *pointer, std::size_t size) -> void {
    using Aligned = AlignedStruct<Alignment>;

    using alloc_traits         = std::allocator_traits<Allocator>;
    using aligned_allocator    = typename alloc_traits::template rebind_alloc<Aligned>;
    using aligned_alloc_traits = typename alloc_traits::template rebind_traits<Aligned>;

    aligned_allocator alloc{allocator};
    // Deallocate memory with aligned size rounded up.
    aligned_alloc_traits::deallocate(alloc, static_cast<Aligned *>(pointer),
                                     (size + sizeof(Aligned) - 1) / sizeof(Aligned));
}

/// \class Storage
/// \brief
///   Actual storage for hash container.
class Storage {
public:
    /// \brief
    ///   Create an empty storage.
    Storage() noexcept
        : m_capacity{0},
          m_size{0},
          m_control{const_cast<ControlFlag *>(EmptyGroup + 16)},
          m_slots{nullptr} {}

    /// \brief
    ///   \c Storage is not copyable.
    Storage(const Storage &other) = delete;

    /// \brief
    ///   Move constructor for \c Storage. \c Storage is trivially movable.
    /// \param[inout] other
    ///   The \c Storage to move from.
    Storage(Storage &&other) noexcept = default;

    /// \brief
    ///   \c Storage is trivially destructible.
    ~Storage() noexcept = default;

    /// \brief
    ///   \c Storage is not copyable.
    auto operator=(const Storage &other) = delete;

    /// \brief
    ///   Move assignment operator for \c Storage. \c Storage is trivially movable.
    /// \param[inout] other
    ///   The \c Storage to move from.
    auto operator=(Storage &&other) noexcept -> Storage & = default;

    /// \brief
    ///   Get pointer to control bytes.
    /// \return
    ///   Pointer to control bytes.
    [[nodiscard]]
    auto control() const noexcept -> ControlFlag * {
        return m_control;
    }

    /// \brief
    ///   Set control byte pointer.
    /// \param control
    ///   Pointer to control bytes.
    auto setControl(ControlFlag *control) noexcept -> void {
        m_control = control;
    }

    /// \brief
    ///   Get pointer to start of the backing array.
    /// \return
    ///   Pointer to start of the backing array.
    [[nodiscard]]
    auto backingArrayStart() const noexcept -> void * {
        return m_control - sizeof(std::size_t);
    }

    /// \brief
    ///   Get pointer to start of the slots.
    /// \return
    ///   Pointer to start of the slots.
    [[nodiscard]]
    auto slotArray() const noexcept -> void * {
        return m_slots;
    }

    /// \brief
    ///   Get pointer to start of the slots as a specific type.
    /// \tparam T
    ///   Type of the slots.
    /// \return
    ///   Pointer to start of the slots as a specific type.
    template <typename T>
    [[nodiscard]] auto slotArray() const noexcept -> T * {
        return static_cast<T *>(m_slots);
    }

    /// \brief
    ///   Set slot array pointer.
    /// \param data
    ///   Pointer to the slot array.
    auto setSlotArray(void *data) noexcept -> void {
        m_slots = data;
    }

    /// \brief
    ///   Get number of elements stored in the hash container.
    /// \return
    ///   Number of elements stored in the hash container.
    [[nodiscard]]
    auto size() const noexcept -> std::size_t {
        return m_size;
    }

    /// \brief
    ///   Set number of elements stored in the hash container.
    /// \param size
    ///   Number of elements stored in the hash container.
    auto setSize(std::size_t size) noexcept -> void {
        m_size = size;
    }

    /// \brief
    ///   Increase the size of the hash container by 1.
    auto increaseSize() noexcept -> void {
        ++m_size;
    }

    /// \brief
    ///   Decrease the size of the hash container by 1.
    auto decreaseSize() noexcept -> void {
        --m_size;
    }

    /// \brief
    ///   Get capacity of the hash container.
    /// \return
    ///   Capacity of the hash container.
    [[nodiscard]]
    auto capacity() const noexcept -> std::size_t {
        return m_capacity;
    }

    /// \brief
    ///   Set capacity of the hash container.
    /// \param capacity
    ///   Capacity of the hash container. The capacity must either be 0 or 2^N - 1.
    auto setCapacity(std::size_t capacity) noexcept -> void {
        m_capacity = capacity;
    }

    /// \brief
    ///   Get growth information of the hash container. This is used to indicate how many slots we
    ///   can grow without rehashing. Usually this method is not used directly.
    /// \return
    ///   Growth information of the hash container.
    [[nodiscard]]
    auto growthInfo() noexcept -> GrowthInfo & {
        return *reinterpret_cast<GrowthInfo *>(m_control - sizeof(GrowthInfo));
    }

    /// \brief
    ///   Get growth information of the hash container. This is used to indicate how many slots we
    ///   can grow without rehashing. Usually this method is not used directly.
    /// \return
    ///   Growth information of the hash container.
    [[nodiscard]]
    auto growthInfo() const noexcept -> GrowthInfo {
        return *reinterpret_cast<GrowthInfo *>(m_control - sizeof(GrowthInfo));
    }

    /// \brief
    ///   Get number of slots that we can still insert without rehashing.
    /// \return
    ///   Number of slots that we can still insert without rehashing.
    [[nodiscard]]
    auto growthLeft() const noexcept -> std::size_t {
        return growthInfo().growthLeft();
    }

    /// \brief
    ///   Reset number of slots that we can still insert without rehashing.
    auto resetGrowthLeft() noexcept -> void {
        std::size_t toGrow = capacityToGrowth(capacity()) - size();
        growthInfo()       = toGrow;
    }

    /// \brief
    ///   Set control byte at the specified index and mirror the value if necessary.
    /// \param index
    ///   Index of the control byte to set.
    /// \param hash
    ///   H2 hash value to set.
    auto setControl(std::size_t index, std::uint8_t hash) noexcept -> void {
        m_control[index] = static_cast<ControlFlag>(hash);
        m_control[((index - (GroupWidth - 1)) & m_capacity) + ((GroupWidth - 1) & m_capacity)] =
            static_cast<ControlFlag>(hash);
    }

    /// \brief
    ///   Set control byte at the specified index and mirror the value if necessary.
    /// \param index
    ///   Index of the control byte to set.
    /// \param flag
    ///   Control flag to set.
    auto setControl(std::size_t index, ControlFlag flag) noexcept -> void {
        setControl(index, static_cast<std::uint8_t>(flag));
    }

    /// \brief
    ///   Reset control bytes to empty state.
    auto resetControl() noexcept -> void {
        std::memset(m_control, static_cast<std::int8_t>(ControlFlag::Empty),
                    m_capacity + GroupWidth);
        m_control[m_capacity] = ControlFlag::Sentinel;
    }

    /// \brief
    ///   Clear metadata for the erased slot.
    /// \param index
    ///   Index of the slot to erase.
    auto eraseMetaOnly(std::size_t index) noexcept -> void {
        this->decreaseSize();

        this->setControl(index, ControlFlag::Deleted);
        this->growthInfo().overwriteFullAsDeleted();
    }

    /// \brief
    ///   Calculate size in bytes required to allocate a hash container for the given slot size and
    ///   slot alignment.
    /// \param slotSize
    ///   Size in byte of each slot.
    /// \param slotAlignment
    ///   Alignment of each slot. Must be power of 2.
    /// \return
    ///   Size in bytes required to allocate a hash container for the given slot size and slot
    ///   alignment.
    [[nodiscard]]
    constexpr auto allocateSize(std::size_t slotSize, std::size_t slotAlignment) const noexcept
        -> std::size_t {
        return Layout{capacity(), slotAlignment}.allocateSize(slotSize);
    }

    /// \brief
    ///   Start a probing operation on this storage using \p hash.
    /// \param hash
    ///   Hash value to probe.
    /// \return
    ///   Probe sequence for the given hash value.
    [[nodiscard]]
    auto probe(std::size_t hash) const noexcept -> ProbeSequence {
        std::size_t h1 = (hash >> 7) ^ (reinterpret_cast<std::size_t>(m_control) >> 12);
        return {h1, m_capacity};
    }

    /// \brief
    ///   Find the first non-full slot in the hash group. This method cannot be called on full hash
    ///   container.
    /// \param hash
    ///   Hash value to probe.
    /// \return
    ///   Result of the probing operation.
    [[nodiscard]]
    auto findFirstNonFull(std::size_t hash) const noexcept -> FindResult {
        ProbeSequence sequence = this->probe(hash);

        // The first probed slot in the hash group is not full. Return directly.
        if (m_control[sequence.offset()] < ControlFlag::Sentinel)
            return {.offset = sequence.offset(), .probeLength = 0};

        while (true) {
            Group group{m_control + sequence.offset()};
            auto mask = group.maskEmptyOrDeleted();

            if (mask) {
                return {
                    .offset      = sequence.offset(mask.indexOfLowestBit()),
                    .probeLength = sequence.index(),
                };
            }

            sequence.next();
        }
    }

    /// \brief
    ///   Walk through all filled slots in the hash container and call \p func for each filled slot.
    /// \tparam Slot
    ///   Type of the slot.
    /// \tparam Func
    ///   Type of the function to call for each filled slot.
    /// \param slot
    ///   Pointer to the slot array.
    /// \param func
    ///   Function to call for each filled slot.
    template <typename Slot, typename Func>
    auto iterateFilledSlots(Func &&func) const noexcept -> void {
        Slot *slot              = slotArray<Slot>();
        const ControlFlag *ctrl = control();
        std::size_t remaining   = size();
        while (remaining != 0) {
            for (std::uint32_t i : Group{ctrl}.maskFull()) {
                func(ctrl + i, slot + i);
                --remaining;
            }

            ctrl += GroupWidth;
            slot += GroupWidth;
        }
    }

    /// \brief
    ///   Release memory of the backing array.
    /// \tparam SlotSize
    ///   Size in byte of each slot object.
    /// \tparam SlotAlignment
    ///   Alignment of each slot. Must be power of 2.
    /// \param[in] allocator
    ///   Allocator used to deallocate memory.
    /// \param reuse
    ///   Whether to reuse the backing array.
    template <std::size_t SlotSize, std::size_t SlotAlignment, typename Allocator>
    auto clearBackingArray(Allocator &allocator, bool reuse) noexcept -> void {
        if (reuse) {
            setSize(0);
            resetControl();
            resetGrowthLeft();
        } else {
            constexpr std::size_t arrayAlign = std::max(SlotAlignment, alignof(GrowthInfo));
            alignedDeallocate<arrayAlign>(allocator, backingArrayStart(),
                                          allocateSize(SlotSize, SlotAlignment));

            m_capacity = 0;
            m_size     = 0;
            m_control  = const_cast<ControlFlag *>(EmptyGroup + 16);
            m_slots    = nullptr;
        }
    }

private:
    /// \brief
    ///   Number of slots in the backing array. This is always 2^N - 1.
    std::size_t m_capacity;

    /// \brief
    ///   Size of the hash container.
    std::size_t m_size;

    /// \brief
    ///   Pointer to the control bytes. This contains `capacity + GroupWidth` entries, even if the
    ///   table is empty.
    /// \note
    ///   The growth information is stored immediately before this pointer.
    ControlFlag *m_control;

    /// \brief
    ///   Pointer to beginning of the slots.
    void *m_slots;
};

/// \class ResizeHelper
/// \brief
///   Helper class to resize hash container.
class ResizeHelper {
public:
    /// \brief
    ///   Create a \c ResizeHelper for the specified \p storage.
    /// \param[in] storage
    ///   Storage to resize.
    ResizeHelper(Storage &storage) noexcept
        : m_oldControl{},
          m_oldSlots{},
          m_oldCapacity{storage.capacity()} {}

    /// \brief
    ///   Get old control array before resizing.
    /// \return
    ///   Old control array before resizing.
    [[nodiscard]]
    auto oldControl() const noexcept -> ControlFlag * {
        return m_oldControl;
    }

    /// \brief
    ///   Get old slot array before resizing.
    /// \return
    ///   Old slot array before resizing.
    [[nodiscard]]
    auto oldSlotArray() const noexcept -> void * {
        return m_oldSlots;
    }

    /// \brief
    ///   Get old slot array before resizing as a specific type.
    /// \tparam T
    ///   Type of the slot array.
    /// \return
    ///   Old slot array before resizing as a specific type.
    template <typename T>
    auto oldSlotArray() const noexcept -> T * {
        return static_cast<T *>(m_oldSlots);
    }

    /// \brief
    ///   Get old capacity before resizing.
    /// \return
    ///   Old capacity before resizing.
    [[nodiscard]]
    auto oldCapacity() const noexcept -> std::size_t {
        return m_oldCapacity;
    }

    /// \brief
    ///   Allocate memory for the new hash container and initialize the slots.
    /// \tparam SlotSize
    ///   Size in byte of each slot.
    /// \tparam SlotAlignment
    ///   Alignment of each slot. Must be power of 2.
    /// \tparam Allocator
    ///   Type of the allocator used to allocate memory for the new hash container.
    /// \param[inout] storage
    ///   Storage to resize.
    /// \param[in] allocator
    ///   Allocator used to allocate memory for the new hash container.
    template <std::size_t SlotSize, std::size_t SlotAlignment, typename Allocator>
    auto initSlots(Storage &storage, Allocator &allocator) noexcept -> void {
        Layout layout{storage.capacity(), SlotAlignment};

        // We assumes that objects stored in hash containers does not exceed default operator new
        // alignment __STDCPP_DEFAULT_NEW_ALIGNMENT__.
        const std::size_t memorySize      = layout.allocateSize(SlotSize);
        constexpr std::size_t memoryAlign = std::max(SlotAlignment, alignof(GrowthInfo));
        auto *memory = static_cast<char *>(alignedAllocate<memoryAlign>(allocator, memorySize));

        // Get elements in the backing array.
        auto *newCtrl  = reinterpret_cast<ControlFlag *>(memory + layout.controlOffset());
        void *newSlots = memory + layout.slotOffset();

        m_oldControl = storage.control();
        m_oldSlots   = storage.slotArray();

        storage.setControl(newCtrl);
        storage.setSlotArray(newSlots);
        storage.resetControl();
        storage.resetGrowthLeft();
    }

    /// \brief
    ///   Deallocate memory for the old hash container.
    /// \tparam SlotSize
    ///   Size in byte of each slot.
    /// \tparam SlotAlignment
    ///   Alignment of each slot. Must be power of 2.
    template <std::size_t SlotSize, std::size_t SlotAlignment, typename Allocator>
    auto deallocateOld(Allocator &allocator) noexcept -> void {
        constexpr std::size_t memoryAlign = std::max(SlotAlignment, alignof(GrowthInfo));
        Layout layout{m_oldCapacity, SlotAlignment};
        alignedDeallocate<memoryAlign>(allocator, m_oldControl - layout.controlOffset(),
                                       layout.allocateSize(SlotSize));
    }

private:
    ControlFlag *m_oldControl;
    void *m_oldSlots;
    std::size_t m_oldCapacity;
};

} // namespace hash

/// \class CompressedPairBase
/// \brief
///   Helper class for implementing compressed pair.
template <typename T, int Index, bool ShouldEBO = std::is_empty_v<T> && !std::is_final_v<T>>
class CompressedPairBase {
public:
    /// \brief
    ///   Construct the underlying value.
    /// \tparam Args
    ///   Types of the arguments to construct the underlying value.
    /// \param args
    ///   Arguments to construct the underlying value.
    template <typename... Args>
        requires(std::is_constructible_v<T, Args && ...>)
    CompressedPairBase(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args &&...>)
        : m_value{std::forward<Args>(args)...} {}

    /// \brief
    ///   Get the underlying value.
    /// \return
    ///   The underlying value.
    [[nodiscard]]
    auto value() noexcept -> T & {
        return m_value;
    }

    /// \brief
    ///   Get the underlying value.
    /// \return
    ///   The underlying value.
    [[nodiscard]]
    auto value() const noexcept -> const T & {
        return m_value;
    }

private:
    T m_value;
};

/// \class CompressedPairBase
/// \brief
///   Helper class for implementing compressed pair.
template <typename T, int Index>
class CompressedPairBase<T, Index, true> : private T {
public:
    /// \brief
    ///   Construct the underlying value.
    /// \tparam Args
    ///   Types of the arguments to construct the underlying value.
    /// \param args
    ///   Arguments to construct the underlying value.
    template <typename... Args>
        requires(std::is_constructible_v<T, Args && ...>)
    CompressedPairBase(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args &&...>)
        : T{std::forward<Args>(args)...} {}

    /// \brief
    ///   Get the underlying value.
    /// \return
    ///   The underlying value.
    [[nodiscard]]
    auto value() noexcept -> T & {
        return static_cast<T &>(*this);
    }

    /// \brief
    ///   Get the underlying value.
    /// \return
    ///   The underlying value.
    [[nodiscard]]
    auto value() const noexcept -> const T & {
        return static_cast<const T &>(*this);
    }
};

/// \struct is_transparent
/// \brief
///   Traits type to check if a type is transparent to comparison function.
template <typename T, typename = void>
struct is_transparent : std::false_type {};

/// \struct is_transparent
/// \brief
///   Traits type to check if a type is transparent to comparison function.
template <typename T>
struct is_transparent<T, std::void_t<typename T::is_transparent>> : std::true_type {};

/// \brief
///   Helper variable template to check if a type is transparent to comparison function.
template <typename T>
inline constexpr bool is_transparent_v = is_transparent<T>::value;

/// \class CompressedPair
/// \brief
///   Compressed pair that is used for containers to optimize 0-sized members.
template <typename First, typename Second>
class CompressedPair : CompressedPairBase<First, 0>,
                       CompressedPairBase<Second, 1> {
public:
    /// \brief
    ///   \c CompressedPair requires the member types to be default constructible.
    CompressedPair() noexcept(std::is_nothrow_default_constructible_v<First> &&
                              std::is_nothrow_default_constructible_v<Second>);

    /// \brief
    ///   Construct a \c CompressedPair with the specified \p first and \p second.
    /// \tparam FirstArg
    ///   Type of the first argument to construct the first member.
    /// \tparam SecondArg
    ///   Type of the second argument to construct the second member.
    /// \param first
    ///   First argument to construct the first member.
    /// \param second
    ///   Second argument to construct the second member.
    template <typename FirstArg = First, typename SecondArg = Second>
        requires(std::is_constructible_v<First, FirstArg &&> &&
                 std::is_constructible_v<Second, SecondArg &&>)
    CompressedPair(FirstArg &&first, SecondArg &&second) noexcept(
        std::is_nothrow_constructible_v<First, FirstArg &&> &&
        std::is_nothrow_constructible_v<Second, SecondArg &&>)
        : CompressedPairBase<First, 0>{std::forward<FirstArg>(first)},
          CompressedPairBase<Second, 1>{std::forward<SecondArg>(second)} {}

    /// \brief
    ///   Copy constructor of \c CompressedPair. This requires both members to be copy
    ///   constructible.
    /// \param other
    ///   The \c CompressedPair to copy from.
    CompressedPair(const CompressedPair &other) noexcept(
        std::is_nothrow_copy_constructible_v<First> &&
        std::is_nothrow_copy_constructible_v<Second>);

    /// \brief
    ///   Move constructor of \c CompressedPair. This requires both members to be move
    ///   constructible.
    /// \param[inout] other
    ///   The \c CompressedPair to move from.
    CompressedPair(CompressedPair &&other) noexcept(std::is_nothrow_move_constructible_v<First> &&
                                                    std::is_nothrow_move_constructible_v<Second>);

    /// \brief
    ///   Destroy this \c CompressedPair.
    ~CompressedPair() = default;

    /// \brief
    ///   Copy assignment operator of \c CompressedPair. This requires both members to be copy
    ///   assignable.
    /// \param other
    ///   The \c CompressedPair to copy from.
    /// \return
    ///   Reference to this \c CompressedPair.
    auto operator=(const CompressedPair &other) noexcept(std::is_nothrow_copy_assignable_v<First> &&
                                                         std::is_nothrow_copy_assignable_v<Second>)
        -> CompressedPair &;

    /// \brief
    ///   Move assignment operator of \c CompressedPair. This requires both members to be move
    ///   assignable.
    /// \param[inout] other
    ///   The \c CompressedPair to move from.
    /// \return
    ///   Reference to this \c CompressedPair.
    auto operator=(CompressedPair &&other) noexcept(std::is_nothrow_move_assignable_v<First> &&
                                                    std::is_nothrow_move_assignable_v<Second>)
        -> CompressedPair &;

    /// \brief
    ///   Get value of the first member.
    /// \return
    ///   Value of the first member.
    [[nodiscard]]
    auto first() noexcept -> First & {
        return this->CompressedPairBase<First, 0>::value();
    }

    /// \brief
    ///   Get value of the first member.
    /// \return
    ///   Value of the first member.
    [[nodiscard]]
    auto first() const noexcept -> const First & {
        return this->CompressedPairBase<First, 0>::value();
    }

    /// \brief
    ///   Get value of the second member.
    /// \return
    ///   Value of the second member.
    [[nodiscard]]
    auto second() noexcept -> Second & {
        return this->CompressedPairBase<Second, 1>::value();
    }

    /// \brief
    ///   Get value of the second member.
    /// \return
    ///   Value of the second member.
    [[nodiscard]]
    auto second() const noexcept -> const Second & {
        return this->CompressedPairBase<Second, 1>::value();
    }
};

template <typename First, typename Second>
CompressedPair<First, Second>::CompressedPair() noexcept(
    std::is_nothrow_default_constructible_v<First> &&
    std::is_nothrow_default_constructible_v<Second>) = default;

template <typename First, typename Second>
CompressedPair<First, Second>::CompressedPair(const CompressedPair &other) noexcept(
    std::is_nothrow_copy_constructible_v<First> &&
    std::is_nothrow_copy_constructible_v<Second>) = default;

template <typename First, typename Second>
CompressedPair<First, Second>::CompressedPair(CompressedPair &&other) noexcept(
    std::is_nothrow_move_constructible_v<First> &&
    std::is_nothrow_move_constructible_v<Second>) = default;

template <typename First, typename Second>
auto CompressedPair<First, Second>::operator=(const CompressedPair &other) noexcept(
    std::is_nothrow_copy_assignable_v<First> && std::is_nothrow_copy_assignable_v<Second>)
    -> CompressedPair & = default;

template <typename First, typename Second>
auto CompressedPair<First, Second>::operator=(CompressedPair &&other) noexcept(
    std::is_nothrow_move_assignable_v<First> && std::is_nothrow_move_assignable_v<Second>)
    -> CompressedPair & = default;

/// \class HashMapPointerProxy
/// \brief
///   Proxy type for \c HashMap pointers.
template <typename Key, typename Mapped>
class HashMapPointerProxy {
public:
    /// \brief
    ///   Create a new \c HashMapPointerProxy from a reference.
    HashMapPointerProxy(std::pair<const Key &, Mapped &> reference) noexcept
        : m_reference(reference) {}

    /// \brief
    ///   Dereference this proxy.
    /// \return
    ///   A reference to the key-value pair.
    [[nodiscard]]
    auto operator*() noexcept -> std::pair<const Key &, Mapped &> {
        return m_reference;
    }

    /// \brief
    ///   Dereference this proxy as a pointer.
    /// \return
    ///   A pointer to the key-value pair.
    [[nodiscard]]
    auto operator->() noexcept -> std::pair<const Key &, Mapped &> * {
        return &m_reference;
    }

private:
    std::pair<const Key &, Mapped &> m_reference;
};

} // namespace onion::detail

namespace onion {

/// \class HashMap
/// \brief
///   Swiss-table hash map implementation.
template <typename Key,
          typename Mapped,
          typename Hash      = onion::Hash<Key>,
          typename KeyEqual  = std::equal_to<Key>,
          typename Allocator = std::allocator<std::pair<Key, Mapped>>>
class HashMap {
public:
    using key_type        = Key;
    using mapped_type     = Mapped;
    using value_type      = std::pair<key_type, mapped_type>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using hasher          = Hash;
    using key_equal       = KeyEqual;
    using allocator_type  = Allocator;
    using reference       = std::pair<const key_type &, mapped_type &>;
    using const_reference = std::pair<const key_type &, const mapped_type &>;
    using pointer         = detail::HashMapPointerProxy<key_type, mapped_type>;
    using const_pointer   = detail::HashMapPointerProxy<const key_type, const mapped_type>;

    /// \class iterator
    /// \brief
    ///   Iterator type for the hash map.
    class iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = typename HashMap::value_type;
        using reference         = typename HashMap::reference;
        using pointer           = typename HashMap::pointer;
        using difference_type   = typename HashMap::difference_type;

        /// \brief
        ///   Create an empty iterator.
        iterator() noexcept
            : m_control{const_cast<detail::hash::ControlFlag *>(detail::hash::EmptyGroup + 16)},
              m_slot{nullptr} {}

        /// \brief
        ///   Create an iterator from the specified control flag and slot.
        /// \param control
        ///   Pointer to the control flag.
        /// \param value
        ///   Pointer to the slot.
        iterator(detail::hash::ControlFlag *control, value_type *value) noexcept
            : m_control{control},
              m_slot{value} {}

        /// \brief
        ///   Dereference the iterator to get the reference to the hash map element.
        /// \return
        ///   Reference to the hash map element.
        [[nodiscard]]
        auto operator*() const noexcept -> reference {
            return {m_slot->first, m_slot->second};
        }

        /// \brief
        ///   Dereference the iterator to get the pointer to the hash map element.
        /// \return
        ///   Pointer to the hash map element.
        [[nodiscard]]
        auto operator->() const noexcept -> pointer {
            return {this->operator*()};
        }

        /// \brief
        ///   Move to the next element.
        /// \return
        ///   Reference to the iterator after moving.
        auto operator++() noexcept -> iterator & {
            ++m_control;
            ++m_slot;
            skipEmptyOrDeleted();

            if (*m_control == detail::hash::ControlFlag::Sentinel)
                m_control = nullptr;

            return *this;
        }

        /// \brief
        ///   Move to the next element.
        /// \return
        ///   A copy of the iterator before moving.
        auto operator++(int) noexcept -> iterator {
            iterator copy = *this;
            ++(*this);
            return copy;
        }

        /// \brief
        ///   Checks if two iterators are equal.
        /// \param lhs
        ///   Left-hand side iterator to compare.
        /// \param rhs
        ///   Right-hand side iterator to compare.
        /// \retval true
        ///   The two iterators are equal.
        /// \retval false
        ///   The two iterators are not equal.
        [[nodiscard]]
        friend auto operator==(const iterator &lhs, const iterator &rhs) noexcept -> bool {
            return lhs.m_control == rhs.m_control;
        }

        /// \brief
        ///   Checks if two iterators are different.
        /// \param lhs
        ///   Left-hand side iterator to compare.
        /// \param rhs
        ///   Right-hand side iterator to compare.
        /// \retval true
        ///   The two iterators are different.
        /// \retval false
        ///   The two iterators are equal.
        [[nodiscard]]
        friend auto operator!=(const iterator &lhs, const iterator &rhs) noexcept -> bool {
            return !(lhs == rhs);
        }

        friend class HashMap;

    private:
        /// \brief
        ///   For internal usage. Skip empty and deleted slots.
        auto skipEmptyOrDeleted() noexcept -> void {
            while (*m_control < detail::hash::ControlFlag::Sentinel) {
                std::uint32_t shift = detail::hash::Group{m_control}.countLeadingEmptyOrDeleted();
                m_control += shift;
                m_slot += shift;
            }
        }

    private:
        detail::hash::ControlFlag *m_control;
        value_type *m_slot;
    };

    /// \class const_iterator
    /// \brief
    ///   Const iterator type for the hash map.
    class const_iterator {
    public:
        using iterator_category = typename iterator::iterator_category;
        using value_type        = typename HashMap::value_type;
        using reference         = typename HashMap::const_reference;
        using pointer           = typename HashMap::const_pointer;
        using difference_type   = typename HashMap::difference_type;

        /// \brief
        ///   Create an empty const iterator.
        const_iterator() noexcept = default;

        /// \brief
        ///   Allow implicit conversion from \c iterator.
        /// \param iter
        ///   Iterator to convert from.
        const_iterator(iterator iter) noexcept : m_internal{iter} {}

        /// \brief
        ///   Dereference the iterator to get the reference to the hash map element.
        /// \return
        ///   Reference to the hash map element.
        [[nodiscard]]
        auto operator*() const noexcept -> reference {
            return {*m_internal.first, *m_internal.second};
        }

        /// \brief
        ///   Dereference the iterator to get the pointer to the hash map element.
        /// \return
        ///   Pointer to the hash map element.
        [[nodiscard]]
        auto operator->() const noexcept -> pointer {
            return {this->operator*()};
        }

        /// \brief
        ///   Move to the next element.
        /// \return
        ///   Reference to the iterator after moving.
        auto operator++() noexcept -> const_iterator & {
            ++m_internal;
            return *this;
        }

        /// \brief
        ///   Move to the next element.
        /// \return
        ///   A copy of the iterator before moving.
        auto operator++(int) noexcept -> const_iterator {
            const_iterator copy = *this;
            ++(*this);
            return copy;
        }

        /// \brief
        ///   Checks if two iterators are equal.
        /// \param lhs
        ///   Left-hand side iterator to compare.
        /// \param rhs
        ///   Right-hand side iterator to compare.
        /// \retval true
        ///   The two iterators are equal.
        /// \retval false
        ///   The two iterators are not equal.
        [[nodiscard]]
        friend auto operator==(const const_iterator &lhs, const const_iterator &rhs) noexcept
            -> bool {
            return lhs.m_internal == rhs.m_internal;
        }

        /// \brief
        ///   Checks if two iterators are different.
        /// \param lhs
        ///   Left-hand side iterator to compare.
        /// \param rhs
        ///   Right-hand side iterator to compare.
        /// \retval true
        ///   The two iterators are different.
        /// \retval false
        ///   The two iterators are equal.
        [[nodiscard]]
        friend auto operator!=(const const_iterator &lhs, const const_iterator &rhs) noexcept
            -> bool {
            return !(lhs == rhs);
        }

        friend class HashMap;

    private:
        iterator m_internal;
    };

    /// \brief
    ///   Create an empty hash map.
    HashMap() noexcept(std::is_nothrow_default_constructible_v<hasher> &&
                       std::is_nothrow_default_constructible_v<key_equal> &&
                       std::is_nothrow_default_constructible_v<allocator_type>);

    /// \brief
    ///   Create a hash map with the specified \p bucketCount.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param equal
    ///   Key equality function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    explicit HashMap(size_type bucketCount,
                     const hasher &hash              = hasher{},
                     const key_equal &equal          = key_equal{},
                     const allocator_type &allocator = allocator_type{});

    /// \brief
    ///   Create a hash map with the specified \p bucketCount, \p hash and \p allocator.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(size_type bucketCount, const hasher &hash, const allocator_type &allocator);

    /// \brief
    ///   Create a hash map with the specified \p bucketCount and \p allocator.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(size_type bucketCount, const allocator_type &allocator);

    /// \brief
    ///   Create a hash map with the specified \p allocator.
    /// \param allocator
    ///   Allocator for this hash map.
    explicit HashMap(const allocator_type &allocator);

    /// \brief
    ///   Create a hash map from a range of elements.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param equal
    ///   Key equality function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    template <std::input_iterator InputIt>
    HashMap(InputIt first,
            InputIt last,
            size_type bucketCount           = 0,
            const hasher &hash              = hasher{},
            const key_equal &equal          = key_equal{},
            const allocator_type &allocator = allocator_type{});

    /// \brief
    ///   Create a hash map from a range of elements.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param allocator
    ///   Allocator for this hash map.
    template <std::input_iterator InputIt>
    HashMap(InputIt first, InputIt last, size_type bucketCount, const allocator_type &allocator);

    /// \brief
    ///   Create a hash map from a range of elements.
    /// \tparam InputIt
    ///   Type of the input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    template <std::input_iterator InputIt>
    HashMap(InputIt first,
            InputIt last,
            size_type bucketCount,
            const hasher &hash,
            const allocator_type &allocator);

    /// \brief
    ///   Create a hash map from an initializer list.
    /// \param init
    ///   Initializer list to create the hash map.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param equal
    ///   Key equality function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    explicit HashMap(std::initializer_list<value_type> init,
                     size_type bucketCount           = 0,
                     const hasher &hash              = hasher{},
                     const key_equal &equal          = {},
                     const allocator_type &allocator = allocator_type{});

    /// \brief
    ///   Create a hash map from an initializer list.
    /// \param init
    ///   Initializer list to create the hash map.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(std::initializer_list<value_type> init,
            size_type bucketCount,
            const allocator_type &allocator);

    /// \brief
    ///   Create a hash map from an initializer list.
    /// \param init
    ///   Initializer list to create the hash map.
    /// \param bucketCount
    ///   Expected initial number of buckets in the hash map. This value may be ignored.
    /// \param hash
    ///   Hash function for this hash map.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(std::initializer_list<value_type> init,
            size_type bucketCount,
            const hasher &hash,
            const allocator_type &allocator);

    /// \brief
    ///   Copy constructor of \c HashMap.
    /// \param other
    ///   The \c HashMap to copy from.
    HashMap(const HashMap &other);

    /// \brief
    ///   Copy constructor of \c HashMap with the specified allocator.
    /// \param other
    ///   The \c HashMap to copy from.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(const HashMap &other, const allocator_type &allocator);

    /// \brief
    ///   Move constructor of \c HashMap.
    /// \param[inout] other
    ///   The \c HashMap to move from. The moved \c HashMap is in a valid but unspecified state.
    HashMap(HashMap &&other) noexcept(std::is_nothrow_move_constructible_v<hasher> &&
                                      std::is_nothrow_move_constructible_v<key_equal> &&
                                      std::is_nothrow_move_constructible_v<allocator_type>);

    /// \brief
    ///   Move constructor of \c HashMap with the specified allocator.
    /// \param[inout] other
    ///   The \c HashMap to move from. The moved \c HashMap is in a valid but unspecified state.
    /// \param allocator
    ///   Allocator for this hash map.
    HashMap(HashMap &&other, const allocator_type &allocator);

    /// \brief
    ///   Destroy all elements and free memory allocated by this hash map.
    ~HashMap();

    /// \brief
    ///   Copy assignment of \c HashMap.
    /// \param other
    ///   The \c HashMap to copy from.
    /// \return
    ///   Reference to this \c HashMap.
    auto operator=(const HashMap &other) -> HashMap &;

    /// \brief
    ///   Move assignment of \c HashMap.
    /// \param[inout] other
    ///   The \c HashMap to move from. The moved \c HashMap is in a valid but unspecified state.
    /// \return
    ///   Reference to this \c HashMap.
    auto operator=(HashMap &&other) noexcept -> HashMap &;

    /// \brief
    ///   Get reference to allocator of this hash map.
    /// \return
    ///   Reference to allocator of this hash map.
    [[nodiscard]]
    auto get_allocator() noexcept -> allocator_type & {
        return m_storage.first();
    }

    /// \brief
    ///   Get reference to allocator of this hash map.
    /// \return
    ///   Reference to allocator of this hash map.
    [[nodiscard]]
    auto get_allocator() const noexcept -> const allocator_type & {
        return m_storage.first();
    }

    /// \brief
    ///   Get iterator to the first element in this hash map.
    /// \return
    ///   Iterator to the first element in this hash map.
    [[nodiscard]]
    auto begin() noexcept -> iterator {
        if (empty()) [[unlikely]]
            return end();

        auto &storage = this->storage();
        iterator iter{storage.control(), storage.template slotArray<value_type>()};
        iter.skipEmptyOrDeleted();
        return iter;
    }

    /// \brief
    ///   Get iterator to the first element in this hash map.
    /// \return
    ///   Iterator to the first element in this hash map.
    [[nodiscard]]
    auto begin() const noexcept -> const_iterator {
        if (empty()) [[unlikely]]
            return end();

        auto &storage = this->storage();
        iterator iter{storage.control(), storage.template slotArray<value_type>()};
        iter.skipEmptyOrDeleted();
        return iter;
    }

    /// \brief
    ///   Get iterator to the first element in this hash map.
    /// \return
    ///   Iterator to the first element in this hash map.
    [[nodiscard]]
    auto cbegin() const noexcept -> const_iterator {
        return begin();
    }

    /// \brief
    ///   Get iterator to the place after the last element in this hash map.
    /// \return
    ///   Iterator to the place after the last element in this hash map.
    [[nodiscard]]
    auto end() noexcept -> iterator {
        return {nullptr, nullptr};
    }

    /// \brief
    ///   Get iterator to the place after the last element in this hash map.
    /// \return
    ///   Iterator to the place after the last element in this hash map.
    [[nodiscard]]
    auto end() const noexcept -> const_iterator {
        return iterator{nullptr, nullptr};
    }

    /// \brief
    ///   Get iterator to the place after the last element in this hash map.
    /// \return
    ///   Iterator to the place after the last element in this hash map.
    [[nodiscard]]
    auto cend() const noexcept -> const_iterator {
        return end();
    }

    /// \brief
    ///   Checks if this hash map is empty.
    /// \retval true
    ///   This hash map is empty.
    /// \retval false
    ///   This hash map is not empty.
    [[nodiscard]]
    auto empty() const noexcept -> bool {
        return this->storage().size() == 0;
    }

    /// \brief
    ///   Get number of elements stored in this hash map.
    /// \return
    ///   Number of elements stored in this hash map.
    [[nodiscard]]
    auto size() const noexcept -> size_type {
        return this->storage().size();
    }

    /// \brief
    ///   Get maximum number of elements that could be stored in the memory allocated by this
    ///   \c HashSet.
    /// \return
    ///   maximum number of elements that could be stored in the memory allocated by this
    ///   \c HashSet.
    [[nodiscard]]
    auto capacity() const noexcept -> size_type {
        return this->storage().capacity();
    }

    /// \brief
    ///   Erase all elements in this hash map.
    auto clear() noexcept -> void {
        using detail::hash::Storage;

        const size_type cap = capacity();
        if (cap == 0)
            return;

        destroySlots();
        clearBackingArray(cap < 128);
    }

    /// \brief
    ///   Try to insert a new element into this hash map.
    /// \param value
    ///   Value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    auto insert(const value_type &value) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a new element into this hash map.
    /// \param[inout] value
    ///   Value to insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    auto insert(value_type &&value) -> std::pair<iterator, bool>;

    /// \brief
    ///   Inserts elements from range `[first, last)`. If multiple elements in the range have keys
    ///   that compare equivalent, it is unspecified which element is inserted.
    /// \tparam InputIt
    ///   Type of the iterator to the elements. Must be an input iterator.
    /// \param first
    ///   Iterator to the first element in the range.
    /// \param last
    ///   Iterator to the place after the last element in the range.
    template <std::input_iterator InputIt>
    auto insert(InputIt first, InputIt last) -> void;

    /// \brief
    ///   Inserts elements from initializer list \p list. If multiple elements in the range have
    ///   keys that compare equivalent, it is unspecified which element is inserted.
    /// \param list
    ///   Initializer list to insert elements from.
    auto insert(std::initializer_list<value_type> list) -> void;

    /// \brief
    ///   Try to insert a new element into this hash map if the element with the specified key does
    ///   not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    template <typename... Args,
              typename = std::enable_if_t<std::is_constructible_v<value_type, Args &&...>>>
    auto emplace(Args &&...args) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a new element into this hash map if the element with the specified key does
    ///   not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   Key of the new element to be inserted.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    template <typename... Args,
              typename = std::enable_if_t<std::is_constructible_v<mapped_type, Args &&...>>>
    auto try_emplace(const key_type &key, Args &&...args) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a new element into this hash map if the element with the specified key does
    ///   not exist.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   Key of the new element to be inserted.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    template <typename... Args,
              typename = std::enable_if_t<std::is_constructible_v<mapped_type, Args &&...>>>
    auto try_emplace(key_type &&key, Args &&...args) -> std::pair<iterator, bool>;

    /// \brief
    ///   Try to insert a new element into this hash map if the element with the specified key does
    ///   not exist.
    /// \tparam K
    ///   Type of the key to insert.
    /// \tparam Args
    ///   Types of arguments to construct the new element.
    /// \param key
    ///   Key of the new element to be inserted.
    /// \param args
    ///   Arguments to construct the new element.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found and the boolean value is false. Otherwise, the
    ///   iterator points to the newly inserted element and the boolean value is true.
    template <typename K,
              typename... Args,
              typename = std::enable_if_t<detail::is_transparent_v<hasher> &&
                                          detail::is_transparent_v<key_equal> &&
                                          std::is_constructible_v<mapped_type, Args &&...>>>
    auto try_emplace(K &&key, Args &&...args) -> std::pair<iterator, bool>;

    /// \brief
    ///   Erase the element pointed to by \p position. This method returns void to reduce the
    ///   algorithmic complexity to O(1).
    /// \param position
    ///   Iterator to the element to erase.
    auto erase(iterator position) noexcept -> void;

    /// \brief
    ///   Erase the element pointed to by \p position. This method returns void to reduce the
    ///   algorithmic complexity to O(1).
    /// \param position
    ///   Iterator to the element to erase.
    auto erase(const_iterator position) noexcept -> void {
        this->erase(position.m_internal);
    }

    /// \brief
    ///   Removes the elements in the range `[first, last)` from this hash map.
    /// \param first
    ///   Iterator to the first element to erase.
    /// \param last
    ///   Iterator to the place after the last element to erase.
    /// \return
    ///   Iterator to the element after the last element erased.
    auto erase(const_iterator first, const_iterator last) noexcept -> iterator;

    /// \brief
    ///   Removes all elements with key that compares equivalent to the value \p key.
    /// \param key
    ///   Key of the value to erase.
    /// \return
    ///   Number of elements erased. For this container, this is either 0 or 1.
    auto erase(const key_type &key) -> size_type;

    /// \brief
    ///   Removes all elements with key that compares equivalent to the value \p key.
    /// \tparam K
    ///   Type of the key to erase.
    /// \param key
    ///   Key of the value to erase.
    /// \return
    ///   Number of elements erased. For this container, this is either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto erase(K &&key) -> size_type {
        auto iter = this->find(key);
        if (iter == this->end())
            return 0;

        this->erase(iter);
        return 1;
    }

    /// \brief
    ///   Exchanges the contents of the container with those of other. Does not invoke any move,
    ///   copy, or swap operations on individual elements.
    /// \param[inout] other
    ///   Container to exchange the contents with.
    auto swap(HashMap &other) noexcept(std::is_nothrow_swappable_v<hasher> &&
                                       std::is_nothrow_swappable_v<key_equal> &&
                                       std::is_nothrow_swappable_v<allocator_type>) -> void;

    /// \brief
    ///   Get a reference to the mapped value of the element with specified key.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \throws std::out_of_range
    ///   Thrown if there is no such element exists.
    [[nodiscard]]
    auto at(const key_type &key) -> mapped_type &;

    /// \brief
    ///   Get a reference to the mapped value of the element with specified key.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \throws std::out_of_range
    ///   Thrown if there is no such element exists.
    [[nodiscard]]
    auto at(const key_type &key) const -> const mapped_type &;

    /// \brief
    ///   Get a reference to the mapped value of the element with specified key.
    /// \tparam K
    ///   Type of the key to get the mapped value.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \throws std::out_of_range
    ///   Thrown if there is no such element exists.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto at(const K &key) -> mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end())
            throw std::out_of_range("onion::HashMap::at");
        return iter->second;
    }

    /// \brief
    ///   Get a reference to the mapped value of the element with specified key.
    /// \tparam K
    ///   Type of the key to get the mapped value.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \throws std::out_of_range
    ///   Thrown if there is no such element exists.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto at(const K &key) const -> const mapped_type & {
        auto iter = this->find(key);
        if (iter == this->end())
            throw std::out_of_range("onion::HashMap::at");
        return iter->second;
    }

    /// \brief
    ///   Get a reference to the value that is mapped to a key equivalent to key or x respectively,
    ///   or perform an insertion if such key does not already exist.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \return
    ///   Reference to the mapped value.
    [[nodiscard]]
    auto operator[](const key_type &key) -> mapped_type &;

    /// \brief
    ///   Get a reference to the value that is mapped to a key equivalent to key or x respectively,
    ///   or perform an insertion if such key does not already exist.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \return
    ///   Reference to the mapped value.
    [[nodiscard]]
    auto operator[](key_type &&key) -> mapped_type &;

    /// \brief
    ///   Get a reference to the value that is mapped to a key equivalent to key or x respectively,
    ///   or perform an insertion if such key does not already exist.
    /// \tparam K
    ///   Type of the key to get the mapped value.
    /// \param key
    ///   Key of the element to get the mapped value.
    /// \return
    ///   Reference to the mapped value.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto operator[](K &&key) -> mapped_type & {
        auto result = this->try_emplace(std::forward<K>(key));
        return result.first->second;
    }

    /// \brief
    ///   Get the number of elements with the specified \p key.
    /// \param key
    ///   Key of elements to count.
    /// \return
    ///   Number of elements with the specified key. For this container, this is either 0 or 1.
    [[nodiscard]]
    auto count(const key_type &key) const noexcept -> size_type {
        return this->find(key) == this->end() ? 0 : 1;
    }

    /// \brief
    ///   Get the number of elements with the specified \p key.
    /// \tparam K
    ///   Type of the key to count.
    /// \param key
    ///   Key of elements to count.
    /// \return
    ///   Number of elements with the specified key. For this container, this is either 0 or 1.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto count(const K &key) const noexcept -> size_type {
        return this->find(key) == this->end() ? 0 : 1;
    }

    /// \brief
    ///   Find the element with the specified \p key.
    /// \param key
    ///   Key to find.
    /// \return
    ///   Iterator to the element with the specified key if found. Otherwise, an iterator to the
    ///   end of this hash map.
    [[nodiscard]]
    auto find(const key_type &key) noexcept -> iterator {
        return this->findImpl(key, this->hash(key));
    }

    /// \brief
    ///   Find the element with the specified \p key.
    /// \param key
    ///   Key to find.
    /// \return
    ///   Iterator to the element with the specified key if found. Otherwise, an iterator to the
    ///   end of this hash map.
    [[nodiscard]]
    auto find(const key_type &key) const noexcept -> const_iterator {
        return this->findImpl(key, this->hash(key));
    }

    /// \brief
    ///   Find the element with the specified \p key.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   Key to find.
    /// \return
    ///   Iterator to the element with the specified key if found. Otherwise, an iterator to the
    ///   end of this hash map.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto find(K &&key) noexcept -> iterator {
        return this->findImpl(std::forward<K>(key), this->hash(key));
    }

    /// \brief
    ///   Find the element with the specified \p key.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   Key to find.
    /// \return
    ///   Iterator to the element with the specified key if found. Otherwise, an iterator to the
    ///   end of this hash map.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    auto find(K &&key) const noexcept -> const_iterator {
        return this->findImpl(std::forward<K>(key), this->hash(key));
    }

    /// \brief
    ///   Checks if this hash map contains an element with the specified \p key.
    /// \param key
    ///   Key of the element to check.
    /// \retval true
    ///   This hash map contains an element with the specified key.
    /// \retval false
    ///   This hash map does not contain an element with the specified key.
    [[nodiscard]]
    auto contains(const key_type &key) const noexcept -> bool {
        return this->find(key) != this->end();
    }

    /// \brief
    ///   Checks if this hash map contains an element with the specified \p key.
    /// \tparam K
    ///   Type of the key to check.
    /// \param key
    ///   Key of the element to check.
    /// \retval true
    ///   This hash map contains an element with the specified key.
    /// \retval false
    ///   This hash map does not contain an element with the specified key.
    template <typename K>
        requires(detail::is_transparent_v<hasher> && detail::is_transparent_v<key_equal>)
    [[nodiscard]] auto contains(const K &key) const noexcept -> bool {
        return this->find(key) != this->end();
    }

    /// \brief
    ///   Changes the number of buckets to a value \p count and then rehashes the container.
    /// \param count
    ///   New number of buckets. If this is less than the current number of buckets, the function
    ///   may have no effect.
    auto rehash(size_type count) -> void;

    /// \brief
    ///   Sets the number of buckets to the number needed to accommodate at least \p count elements
    ///   without exceeding maximum load factor and rehashes the container.
    /// \param count
    ///   New capacity of the container.
    auto reserve(size_type count) -> void;

    /// \brief
    ///   Returns the function that hashes the keys.
    /// \return
    ///   The function that hashes the keys.
    [[nodiscard]]
    auto hash_function() const -> hasher {
        return m_storage.second().second().first();
    }

    /// \brief
    ///   Returns the function that compares keys for equality.
    /// \return
    ///   The function that compares keys for equality.
    [[nodiscard]]
    auto key_eq() const -> key_equal {
        return m_storage.second().first();
    }

private:
    /// \brief
    ///   Comprares the key with the other key using the equality function.
    /// \tparam First
    ///   Type of the first key to be compared with.
    /// \tparam Second
    ///   Type of the second key to be compared with.
    /// \param lhs
    ///   First key to be compared with.
    /// \param rhs
    ///   Second key to be compared with.
    /// \retval true
    ///   The two keys are equal.
    /// \retval false
    ///   The two keys are not equal
    template <typename First, typename Second>
    auto equal(const First &lhs, const Second &rhs) const -> bool {
        return m_storage.second().first()(lhs, rhs);
    }

    /// \brief
    ///   Calculate hash value for the given object.
    /// \tparam Object
    ///   Type of the object to calculate hash value for.
    /// \param object
    ///   Object to calculate hash value for.
    /// \return
    ///   Hash value for the given object.
    template <typename Object>
    [[nodiscard]] auto hash(const Object &object) const -> std::size_t {
        return m_storage.second().second().first()(object);
    }

    /// \brief
    ///   Get underlying storage object for this hash map.
    /// \return
    ///   Underlying storage object for this hash map.
    [[nodiscard]]
    auto storage() noexcept -> detail::hash::Storage & {
        return m_storage.second().second().second();
    }

    /// \brief
    ///   Get underlying storage object for this hash map.
    /// \return
    ///   Underlying storage object for this hash map.
    [[nodiscard]]
    auto storage() const noexcept -> const detail::hash::Storage & {
        return m_storage.second().second().second();
    }

    /// \brief
    ///   For internal usage only. Resize this hash map to contain \p count elements. This method
    ///   does not check parameters before doing resize.
    /// \note
    ///   There is no exception guarantee for this method.
    /// \param count
    ///   Number of elements to resize this hash map to.
    auto resize(size_type count) noexcept -> void;

    /// \brief
    ///   Find the element with the specified \p key or prepare to insert the element with the
    ///   specified \p key.
    /// \tparam K
    ///   Type of the key to find or insert.
    /// \param key
    ///   Key to find or insert.
    /// \return
    ///   A pair of iterator and a boolean value. The iterator points to the element with the
    ///   specified key if the element is found. Otherwise, the iterator points to the element that
    ///   is ready to insert the element with the specified key.
    template <typename K>
    auto findOrPrepareInsert(const K &key) -> std::pair<iterator, bool>;

    /// \brief
    ///   Prepare for inserting an element with the specified \p key.
    /// \param hash
    ///   Hash value of the key.
    /// \param target
    ///   Hint position to insert the element.
    /// \return
    ///   Index of the available slot to insert the element.
    auto prepareInsert(std::size_t hash, detail::hash::FindResult target) -> size_type;

    /// \brief
    ///   Destroy all values in this hash map.
    auto destroySlots() noexcept -> void;

    /// \brief
    ///   Deallocate memory used by this hash map.
    auto deallocate() noexcept -> void;

    /// \brief
    ///   Reset memory status of backing array of this hash map.
    /// \param reuse
    ///   Indicates whether to reuse the memory of the backing array.
    auto clearBackingArray(bool reuse) noexcept -> void;

    /// \brief
    ///   Actual implementation of finding an element with the specified \p key and \p hash.
    /// \tparam K
    ///   Type of the key to find.
    /// \param key
    ///   Key to find.
    /// \param hash
    ///   Hash value of the key.
    /// \return
    ///   Iterator to the element with the specified key if found. Otherwise, an iterator to the
    ///   end of this hash map.
    template <typename K>
    auto findImpl(const K &key, std::size_t hash) const noexcept -> iterator;

    /// \brief
    ///   Move elements from \p other to this hash map. This method assumes that the two hash maps
    ///   do not have the same allocator.
    /// \param[inout] other
    ///   The hash map to move elements from.
    auto moveElementsAllocsUnequal(HashMap &&other) -> void;

private:
    detail::CompressedPair<
        allocator_type,
        detail::CompressedPair<key_equal, detail::CompressedPair<hasher, detail::hash::Storage>>>
        m_storage;
};

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap() noexcept(
    std::is_nothrow_default_constructible_v<hasher> &&
    std::is_nothrow_default_constructible_v<key_equal> &&
    std::is_nothrow_default_constructible_v<allocator_type>) = default;

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(size_type bucketCount,
                                                         const hasher &hash,
                                                         const key_equal &equal,
                                                         const allocator_type &allocator)
    : m_storage{allocator, {equal, {hash, {}}}} {
    using detail::hash::normalizeCapacity;

    if (bucketCount != 0) [[likely]]
        this->resize(normalizeCapacity(bucketCount));
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(size_type bucketCount,
                                                         const hasher &hash,
                                                         const allocator_type &allocator)
    : HashMap(bucketCount, hash, key_equal{}, allocator) {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(size_type bucketCount,
                                                         const allocator_type &allocator)
    : HashMap(bucketCount, hasher{}, key_equal{}, allocator) {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(const allocator_type &allocator)
    : HashMap(0, hasher{}, key_equal{}, allocator) {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(InputIt first,
                                                         InputIt last,
                                                         size_type bucketCount,
                                                         const hasher &hash,
                                                         const key_equal &equal,
                                                         const allocator_type &allocator)
    : HashMap{detail::hash::growthToLowerboundCapacity(
                  std::forward_iterator<InputIt>
                      ? static_cast<size_type>(std::distance(first, last))
                      : bucketCount),
              hash, equal, allocator} {
    this->insert(first, last);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(InputIt first,
                                                         InputIt last,
                                                         size_type bucketCount,
                                                         const allocator_type &allocator)
    : HashMap{first, last, bucketCount, hasher{}, key_equal{}, allocator} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(InputIt first,
                                                         InputIt last,
                                                         size_type bucketCount,
                                                         const hasher &hash,
                                                         const allocator_type &allocator)
    : HashMap{first, last, bucketCount, hash, key_equal{}, allocator} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(std::initializer_list<value_type> init,
                                                         size_type bucketCount,
                                                         const hasher &hash,
                                                         const key_equal &equal,
                                                         const allocator_type &allocator)
    : HashMap{init.begin(), init.end(), bucketCount, hash, equal, allocator} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(std::initializer_list<value_type> init,
                                                         size_type bucketCount,
                                                         const allocator_type &allocator)
    : HashMap{init, bucketCount, hasher{}, key_equal{}, allocator} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(std::initializer_list<value_type> init,
                                                         size_type bucketCount,
                                                         const hasher &hash,
                                                         const allocator_type &allocator)
    : HashMap{init, bucketCount, hash, key_equal{}, allocator} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(const HashMap &other)
    : HashMap{other, std::allocator_traits<allocator_type>::select_on_container_copy_construction(
                         other.get_allocator())} {}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(const HashMap &other,
                                                         const allocator_type &allocator)
    : HashMap{other.size() ? detail::hash::growthToLowerboundCapacity(other.size()) : 0,
              other.m_storage.second().second().first(), other.m_storage.second().first(),
              allocator} {
    using detail::hash::ControlFlag;
    using detail::hash::FindResult;
    using detail::hash::Storage;

    using alloc_traits = std::allocator_traits<allocator_type>;

    const size_type sz = other.size();
    if (sz == 0)
        return;

    const size_type cap = capacity();
    size_type offset    = cap;

    Storage &storage            = this->storage();
    const Storage &otherStorage = other.storage();

    otherStorage.iterateFilledSlots<value_type>(
        [this, &offset, &storage](const ControlFlag *ctrl, value_type *value) noexcept -> void {
            const size_type h = this->hash(value->first);
            FindResult target = storage.findFirstNonFull(h);
            offset            = target.offset;

            const auto h2 = static_cast<std::uint8_t>(*ctrl);
            this->storage().setControl(offset, h2);

            value_type *dest = storage.slotArray<value_type>() + offset;
            alloc_traits::construct(this->get_allocator(), dest, *value);
        });

    storage.setSize(sz);
    storage.growthInfo().overwriteManyEmptyAsFull(sz);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(HashMap &&other) noexcept(
    std::is_nothrow_move_constructible_v<hasher> &&
    std::is_nothrow_move_constructible_v<key_equal> &&
    std::is_nothrow_move_constructible_v<allocator_type>)
    : m_storage{std::move(other.m_storage)} {
    other.m_storage = {};
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::HashMap(HashMap &&other,
                                                         const allocator_type &allocator)
    : m_storage{allocator,
                {std::move(other.m_storage.second().first()),
                 {std::move(other.m_storage.second().second().first()), {}}}} {
    if (allocator == other.get_allocator()) {
        using std::swap;
        swap(this->storage(), other.storage());
    } else {
        this->moveElementsAllocsUnequal(std::move(other));
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::~HashMap() {
    if (capacity() == 0)
        return;

    this->destroySlots();
    this->deallocate();
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::operator=(const HashMap &other) -> HashMap & {
    if (this == &other) [[unlikely]]
        return *this;

    // FIXME: Is this well-defined behavior?
    std::destroy_at(this);
    std::construct_at(this, other);

    return *this;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::operator=(HashMap &&other) noexcept
    -> HashMap & {
    if (this == &other) [[unlikely]]
        return *this;

    if (capacity() != 0) {
        this->destroySlots();
        this->deallocate();
    }

    m_storage       = std::move(other.m_storage);
    other.storage() = {};

    return *this;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::insert(const value_type &value)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    auto result = this->findOrPrepareInsert(value.first);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, value);
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::insert(value_type &&value)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    auto result = this->findOrPrepareInsert(value.first);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, std::move(value));
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::insert(InputIt first, InputIt last) -> void {
    for (; first != last; ++first)
        this->emplace(*first);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::insert(std::initializer_list<value_type> list)
    -> void {
    for (const value_type &value : list)
        this->insert(value);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename... Args, typename>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::emplace(Args &&...args)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    // Temporary object to be found or inserted.
    value_type temp{std::forward<Args>(args)...};

    auto result = this->findOrPrepareInsert(temp.first);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, std::move(temp));
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename... Args, typename>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::try_emplace(const key_type &key,
                                                                  Args &&...args)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    auto result = this->findOrPrepareInsert(key);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, std::piecewise_construct,
                                std::forward_as_tuple(key),
                                std::forward_as_tuple(std::forward<Args>(args)...));
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename... Args, typename>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::try_emplace(key_type &&key, Args &&...args)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    auto result = this->findOrPrepareInsert(key);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, std::piecewise_construct,
                                std::forward_as_tuple(std::forward<key_type>(key)),
                                std::forward_as_tuple(std::forward<Args>(args)...));
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename K, typename... Args, typename>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::try_emplace(K &&key, Args &&...args)
    -> std::pair<iterator, bool> {
    using alloc_traits = std::allocator_traits<allocator_type>;

    auto result = this->findOrPrepareInsert(key);
    if (result.second) {
        allocator_type &allocator = this->get_allocator();
        alloc_traits::construct(allocator, result.first.m_slot, std::piecewise_construct,
                                std::forward_as_tuple(std::forward<K>(key)),
                                std::forward_as_tuple(std::forward<Args>(args)...));
    }

    return result;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::erase(iterator position) noexcept -> void {
    using detail::hash::ControlFlag;
    using detail::hash::Storage;

    using alloc_traits = std::allocator_traits<allocator_type>;

    // Destroy the element.
    allocator_type &allocator = this->get_allocator();
    alloc_traits::destroy(allocator, position.m_slot);

    // Clear the metadata.
    Storage &storage = this->storage();
    storage.eraseMetaOnly(static_cast<std::size_t>(position.m_control - storage.control()));
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::erase(const_iterator first,
                                                            const_iterator last) noexcept
    -> iterator {
    if (this->empty()) [[unlikely]]
        return end();

    if (first == begin() && last == end()) {
        this->destroySlots();
        this->clearBackingArray(true);
        return end();
    }

    while (first != last)
        this->erase(first++);

    return last.m_internal;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::erase(const key_type &key) -> size_type {
    auto iter = this->find(key);
    if (iter == this->end())
        return 0;

    this->erase(iter);
    return 1;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::swap(HashMap &other) noexcept(
    std::is_nothrow_swappable_v<hasher> && std::is_nothrow_swappable_v<key_equal> &&
    std::is_nothrow_swappable_v<allocator_type>) -> void {
    using std::swap;

    using alloc_traits = std::allocator_traits<allocator_type>;
    if constexpr (alloc_traits::propagate_on_container_swap::value) {
        swap(this->m_storage.first(), other.m_storage.first());
    }

    swap(this->m_storage.second().first(), other.m_storage.second().first());
    swap(this->m_storage.second().second().first(), other.m_storage.second().second().first());
    swap(this->m_storage.second().second().second(), other.m_storage.second().second().second());
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::at(const key_type &key) -> mapped_type & {
    auto iter = this->find(key);
    if (iter == this->end())
        throw std::out_of_range("onion::HashMap::at");
    return iter->second;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::at(const key_type &key) const
    -> const mapped_type & {
    auto iter = this->find(key);
    if (iter == this->end())
        throw std::out_of_range("onion::HashMap::at");
    return iter->second;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::operator[](const key_type &key)
    -> mapped_type & {
    auto result = this->try_emplace(key);
    return result.first->second;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::operator[](key_type &&key) -> mapped_type & {
    auto result = this->try_emplace(std::move(key));
    return result.first->second;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::rehash(size_type count) -> void {
    using detail::hash::growthToLowerboundCapacity;
    using detail::hash::normalizeCapacity;

    if (count == 0) [[unlikely]]
        return;

    // Equal to normalizeCapacity(std::max(count, size())).
    size_type newCapacity = normalizeCapacity(count | growthToLowerboundCapacity(size()));
    if (newCapacity > capacity())
        this->resize(newCapacity);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::reserve(size_type count) -> void {
    using detail::hash::growthToLowerboundCapacity;
    using detail::hash::normalizeCapacity;
    using detail::hash::Storage;

    Storage &storage = this->storage();

    const size_type oldMaxSize = size() + storage.growthLeft();
    if (count > oldMaxSize) {
        size_type newCapacity = growthToLowerboundCapacity(count);
        this->resize(normalizeCapacity(newCapacity));
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::resize(size_type count) noexcept -> void {
    using detail::hash::ControlFlag;
    using detail::hash::ResizeHelper;
    using detail::hash::Storage;

    using alloc_traits = std::allocator_traits<allocator_type>;
    using char_alloc   = typename alloc_traits::template rebind_alloc<char>;

    Storage &storage          = this->storage();
    allocator_type &allocator = this->get_allocator();

    ResizeHelper helper{storage};
    storage.setCapacity(count);

    char_alloc charAlloc{allocator};
    helper.initSlots<sizeof(value_type), alignof(value_type)>(storage, charAlloc);

    // No need to move objects.
    if (helper.oldCapacity() == 0)
        return;

    // Insert the specified element into this new map.
    const auto insertValue = [&](value_type *value) noexcept -> void {
        std::size_t hash = this->hash(value->first);
        auto result      = storage.findFirstNonFull(hash);

        storage.setControl(result.offset, static_cast<std::uint8_t>(hash & 0x7F));
        value_type *dest = storage.slotArray<value_type>() + result.offset;

        alloc_traits::construct(allocator, dest, std::move(*value));
        alloc_traits::destroy(allocator, value);
    };

    // Relocate old elements.
    auto *oldValues         = helper.oldSlotArray<value_type>();
    ControlFlag *oldControl = helper.oldControl();

    for (std::size_t i = 0; i != helper.oldCapacity(); ++i) {
        if (oldControl[i] >= ControlFlag::Zero)
            insertValue(oldValues + i);
    }

    // Free old memory.
    helper.deallocateOld<sizeof(value_type), alignof(value_type)>(charAlloc);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::findOrPrepareInsert(const K &key)
    -> std::pair<iterator, bool> {
    using detail::hash::BitMask;
    using detail::hash::ControlFlag;
    using detail::hash::FindResult;
    using detail::hash::Group;
    using detail::hash::ProbeSequence;
    using detail::hash::Storage;

#if defined(__clang__) || defined(__GNUC__)
    __builtin_prefetch(this->storage().control(), 0, 1);
#endif

    Storage &storage = this->storage();

    std::size_t hash       = this->hash(key);
    ProbeSequence sequence = storage.probe(hash);
    ControlFlag *ctrl      = storage.control();

    while (true) {
        // Try to find the key in the hash group.
        Group group{ctrl + sequence.offset()};
        for (std::uint32_t i : group.match(static_cast<std::uint8_t>(hash & 0x7F))) {
            std::size_t index = sequence.offset(i);
            auto *slotArray   = storage.slotArray<value_type>();
            // Found the element.
            if (this->equal(slotArray[index].first, key)) [[likely]]
                return {iterator{ctrl + index, slotArray + index}, false};
        }

        BitMask emptyMask = group.maskEmpty();
        if (emptyMask) [[likely]] {
            std::size_t target = sequence.offset(emptyMask.indexOfLowestBit());
            size_type index    = this->prepareInsert(hash, {target, sequence.index()});

            // Possible iterator invalidation.
            return {
                iterator{storage.control() + index, storage.slotArray<value_type>() + index},
                true,
            };
        }

        sequence.next();
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::prepareInsert(std::size_t hash,
                                                                    detail::hash::FindResult target)
    -> size_type {
    using detail::hash::GroupWidth;
    using detail::hash::nextCapacity;
    using detail::hash::Storage;

    Storage &storage = this->storage();
    // Prepare for at least one free slot to insert the object.
    // There are deleted slots or current slot is full.
    if (!storage.growthInfo().hasNoDeletedAndGrowthLeft()) [[likely]] {
        if (storage.growthInfo().hasNoGrowthLeftAndNoDeleted()) [[likely]] {
            const size_type oldCap = storage.capacity();
            this->resize(nextCapacity(oldCap));
            target = storage.findFirstNonFull(hash);
        } else {
            if (storage.growthLeft() > 0) {
                target = storage.findFirstNonFull(hash);
            } else {
                const size_type cap = storage.capacity();
                this->resize(nextCapacity(cap));
                target = storage.findFirstNonFull(hash);
            }
        }
    }

    storage.increaseSize();
    storage.growthInfo().overwriteControlAsFull(storage.control()[target.offset]);
    storage.setControl(target.offset, static_cast<std::uint8_t>(hash & 0x7F));

    return target.offset;
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::destroySlots() noexcept -> void {
    if constexpr (std::is_trivially_destructible_v<value_type>) {
        return;
    } else {
        using detail::hash::ControlFlag;
        using detail::hash::Storage;
        using alloc_traits = std::allocator_traits<allocator_type>;

        allocator_type &allocator = this->get_allocator();
        Storage &storage          = this->storage();
        storage.iterateFilledSlots<value_type>([&](const ControlFlag *, value_type *value) -> void {
            alloc_traits::destroy(allocator, value);
        });
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::deallocate() noexcept -> void {
    using detail::hash::alignedDeallocate;
    using detail::hash::GrowthInfo;
    using detail::hash::Storage;

    allocator_type &allocator = this->get_allocator();
    Storage &storage          = this->storage();

    constexpr size_type memoryAlign = std::max(alignof(value_type), alignof(GrowthInfo));
    alignedDeallocate<memoryAlign>(allocator, storage.backingArrayStart(),
                                   storage.allocateSize(sizeof(value_type), alignof(value_type)));
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::clearBackingArray(bool reuse) noexcept
    -> void {
    using detail::hash::Storage;
    using alloc_traits = std::allocator_traits<allocator_type>;
    using char_alloc   = typename alloc_traits::template rebind_alloc<char>;

    Storage &storage = this->storage();
    char_alloc allocator{this->get_allocator()};
    storage.clearBackingArray<sizeof(value_type), alignof(value_type)>(allocator, reuse);
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::findImpl(const K &key,
                                                               std::size_t hash) const noexcept
    -> iterator {
    using detail::hash::ControlFlag;
    using detail::hash::Group;
    using detail::hash::ProbeSequence;
    using detail::hash::Storage;

#if defined(__clang__) || defined(__GNUC__)
    __builtin_prefetch(this->storage().control(), 0, 1);
#endif

    const Storage &storage = this->storage();
    ProbeSequence sequence{storage.probe(hash)};
    ControlFlag *ctrl = storage.control();
    auto *slotArray   = storage.slotArray<value_type>();

    while (true) {
        Group group{ctrl + sequence.offset()};
        for (std::uint32_t i : group.match(static_cast<std::uint8_t>(hash & 0x7F))) {
            std::size_t index = sequence.offset(i);
            // Found the element.
            if (this->equal(slotArray[index].first, key)) [[likely]]
                return {ctrl + index, slotArray + index};
        }

        if (group.maskEmpty()) [[likely]]
            return cend().m_internal;

        sequence.next();
    }
}

template <typename Key, typename Mapped, typename Hash, typename KeyEqual, typename Allocator>
auto HashMap<Key, Mapped, Hash, KeyEqual, Allocator>::moveElementsAllocsUnequal(HashMap &&other)
    -> void {
    using alloc_traits = std::allocator_traits<allocator_type>;

    const size_type size = other.size();
    if (size == 0)
        return;

    this->reserve(size);
    for (iterator iter = other.begin(); iter != other.end(); ++iter) {
        this->insert(std::move(*iter.m_slot));
        alloc_traits::destroy(other.get_allocator(), iter.m_slot);
    }

    other.deallocate();
    other.storage() = {};
}

} // namespace onion
