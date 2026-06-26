#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <span>

namespace psafe3 {
// Deduce the unsigned integer type based from the size.
template <size_t N>
struct uint_from;
template <>
struct uint_from<1> {
    using type = uint8_t;
};
template <>
struct uint_from<2> {
    using type = uint16_t;
};
template <>
struct uint_from<4> {
    using type = uint32_t;
};
template <>
struct uint_from<8> {
    using type = uint64_t;
};
template <size_t N>
using uint_from_t = typename uint_from<N>::type;

template <size_t N, typename T>
bool ptr_alignment_is(T* ptr)
{
    return (reinterpret_cast<std::uintptr_t>(ptr) & ((1 << N) - 1)) == 0;
}

template <typename TT, typename TP>
bool ptr_is_aligned_for(TP* ptr)
{
    return ptr_alignment_is<sizeof(TT)>(ptr);
}

template <std::endian E, size_t N>
uint_from_t<N> load(std::span<const std::byte, N> mem)
{
    using uint_type = uint_from_t<N>;
    if (E == std::endian::native && ptr_alignment_is<N>(mem.data())) {
        return *reinterpret_cast<const uint_type*>(mem.data());
    }
    auto shift_add = [](const uint_type a, const std::byte b) {
        return (a << 8) | static_cast<uint_type>(b);
    };
    if (E == std::endian::big) {
        return std::accumulate(mem.begin(), mem.end(), uint_from_t<N>(0),
            shift_add);
    }
    return std::accumulate(mem.rbegin(), mem.rend(), uint_from_t<N>(0),
        shift_add);
}

template <std::unsigned_integral T>
constexpr T align_up(T n, T m) noexcept
{
    return (n + m - 1) / m * m;
}

template <typename T, std::size_t N>
inline bool operator==(const std::array<T, N>& a,
    std::span<const T, N> b) noexcept
{
    return memcmp(a.data(), b.data(), N * sizeof(T)) == 0;
}

template <typename T, std::size_t N>
inline bool operator!=(const std::array<T, N>& a,
    std::span<const T, N> b) noexcept
{
    return !(a == b);
}

template <typename T, std::size_t N>
inline bool operator==(std::span<const T, N> a,
    const std::array<T, N>& b) noexcept
{
    return b == a;
}

template <typename T, std::size_t N>
inline bool operator!=(std::span<const T, N> a,
    const std::array<T, N>& b) noexcept
{
    return !(b == a);
}
static constexpr size_t TWOFISH_SIZE = 16;

} // namespace psafe3
