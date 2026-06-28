#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace psafe3 {
// Infer the unsigned integer type based from the size.
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

template <std::endian E, size_t N>
uint_from_t<N> load(std::span<const std::byte, N> mem) noexcept
{
    using uint_type = uint_from_t<N>;
    uint_type value;
    std::memcpy(&value, mem.data(), N);
    if constexpr (E != std::endian::native)
        value = std::byteswap(value);
    return value;
}

template <std::unsigned_integral T>
constexpr T round_up_to(T n, T m) noexcept
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
