#pragma once

#include <climits>
#include <memory>      // std::to_address
#include <type_traits> // std::remove_reference

static_assert(CHAR_BIT == 8);

namespace bizwen
{

enum class rfc4648_kind : unsigned char
{
    base64,
    base64_url,
    base32,
    base32_lower,
    base32_mixed,
    base32_hex,
    base32_hex_lower,
    base32_hex_mixed,
    base32_crockford,
    base32_crockford_lower,
    base32_crockford_mixed,
    base16,
    base16_lower,
    base16_mixed,
    hex = base16,
    hex_lower = base16_lower,
    hex_mixed = base16_mixed
};

namespace detail
{
template <typename T>
auto to_address_const(T t)
{
    auto ptr = std::to_address(t);
    using const_pointer = std::add_const_t<std::remove_reference_t<decltype(*t)>> *;
    return const_pointer(ptr);
}

template <rfc4648_kind Kind>
inline consteval auto get_family()
{
    if constexpr (Kind == rfc4648_kind::base64 || Kind == rfc4648_kind::base64_url)
        return rfc4648_kind::base64;
    if constexpr (Kind == rfc4648_kind::base16 || Kind == rfc4648_kind::base16_lower ||
                  Kind == rfc4648_kind::base16_mixed)
        return rfc4648_kind::base16;
    else
        return rfc4648_kind::base32;
}

using buf_ref = unsigned char (&)[4];
using sig_ref = unsigned char &;

} // namespace detail

template <typename End, typename Out>
struct rfc4648_decode_result
{
    End end;
    Out out;

    operator std::tuple<End &, Out &>() && noexcept
    {
        return {end, out};
    }
};

class rfc4648_context
{
    // 0 - 2 for base64 encode, buf_[0 - 2] is significant
    // 0 - 4 for base32 encode, buf_[0 - 4] is significant
    // base16 encoding does not need ctx
    // 0 - 4 for base64 decode, only buf_[0] is significant
    // 0 - 8 for base32 decode, only buf_[0] is significant
    // 0 - 2 for base16 decode, only buf_[0] is significant
    alignas(int) unsigned char sig_{};
    alignas(int) unsigned char buf_[4];

    template <rfc4648_kind Kind, bool Padding, typename In, typename Out>
    friend inline constexpr Out rfc4648_encode(In begin, In end, Out first);
    template <rfc4648_kind Kind, bool Padding, typename R, typename Out>
    friend inline constexpr Out rfc4648_encode(R &&r, Out first);
    template <rfc4648_kind Kind, typename In, typename Out>
    friend inline constexpr Out rfc4648_encode(rfc4648_context &ctx, In begin, In end, Out first);
    template <rfc4648_kind Kind, typename R, typename Out>
    friend inline constexpr Out rfc4648_encode(rfc4648_context &ctx, R &&r, Out first);
    template <rfc4648_kind Kind, bool Padding, typename Out>
    friend inline constexpr Out rfc4648_encode(rfc4648_context &ctx, Out first);

    template <rfc4648_kind Kind, bool Padding, typename In, typename Out>
    friend inline constexpr rfc4648_decode_result<In, Out> rfc4648_decode(In begin, In end, Out first);
    template <rfc4648_kind Kind, bool Padding, typename R, typename Out>
    friend inline constexpr auto rfc4648_decode(R &&r, Out first);
    template <rfc4648_kind Kind, typename In, typename Out>
    friend inline constexpr rfc4648_decode_result<In, Out> rfc4648_decode(rfc4648_context &ctx, In begin, In end,
                                                                          Out first);
    template <rfc4648_kind Kind, typename R, typename Out>
    friend inline constexpr auto rfc4648_decode(rfc4648_context &ctx, R &&r, Out first);
    template <rfc4648_kind Kind, bool Padding, typename In>
    friend inline constexpr In rfc4648_decode(rfc4648_context &ctx, In begin, In end);
};

template <rfc4648_kind kind = rfc4648_kind::base64>
inline constexpr std::size_t rfc4648_encode_length(std::size_t input) noexcept
{
    if constexpr (detail::get_family<kind>() == rfc4648_kind::base64)
        return (input + 5) / 6 * 8;
    else if constexpr (detail::get_family<kind>() == rfc4648_kind::base32)
        return (input + 4) / 5 * 8;
    else
        return (input + 3) / 4 * 8;
}

template <rfc4648_kind kind = rfc4648_kind::base64>
inline constexpr std::size_t rfc4648_decode_length(std::size_t input) noexcept
{
    if constexpr (detail::get_family<kind>() == rfc4648_kind::base64)
        return (input + 7) / 8 * 6;
    else if constexpr (detail::get_family<kind>() == rfc4648_kind::base32)
        return (input + 7) / 8 * 5;
    else
        return (input + 7) / 8 * 4;
}

} // namespace bizwen
