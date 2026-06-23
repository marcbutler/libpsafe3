#pragma once
// TODO License

#include <array>
#include <bit>
#include <cassert>
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
    auto shift_add = [](uint_type a, std::byte b) {
        return (a << 8) | static_cast<uint_type>(b);
    };
    if (E == std::endian::big) {
        return std::accumulate(mem.begin(), mem.end(), uint_from_t<N>(0),
            shift_add);
    }
    return std::accumulate(mem.rbegin(), mem.rend(), uint_from_t<N>(0),
        shift_add);
}

template <typename T, auto F>
struct Handle {
    bool holding = false;
    T actual;
    void acquire()
    {
        holding = true;
    }
    void release()
    {
        holding = false;
        actual = T();
    }
    T operator()()
    {
        return actual;
    }
    ~Handle()
    {
    }
};

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
} // namespace psafe3
