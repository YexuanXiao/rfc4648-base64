#pragma once

#include <memory> // std::to_address
#include <type_traits> // std::remove_reference
#include <climits>

static_assert(CHAR_BIT == 8);

namespace bizwen
{

enum class rfc4648_kind : unsigned char
{
    base64,
    base64_url,
    base32,
    base32_lower,
    base32_hex,
    base32_hex_lower,
    base32_crockford,
    base32_crockford_lower,
    base16,
    base16_lower,
    hex = base16,
    hex_lower = base16_lower
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
    if constexpr (Kind == rfc4648_kind::base16 || Kind == rfc4648_kind::base16_lower)
        return rfc4648_kind::base16;
    else
        return rfc4648_kind::base32;
}

using buf_ref = unsigned char (&)[4];
using sig_ref = unsigned char &;

} // namespace detail

namespace encode_impl
{
// forward declaration for friend
struct rfc4648_encode_fn;
} // namespace encode_impl

namespace decode_impl
{
// forward declaration for friend
struct rfc4648_decode_fn;
} // namespace decode_impl

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

    friend encode_impl::rfc4648_encode_fn;
    friend decode_impl::rfc4648_decode_fn;
};

} // namespace bizwen