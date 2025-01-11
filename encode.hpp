#pragma once

#include <algorithm>
#include <bit>
#include <concepts>
#include <cstring>
#include <iterator>

#include "./common.hpp"

namespace bizwen
{
namespace encode_impl
{
namespace pattern
{
// u8"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline constexpr char8_t base64[] = {
    u8'A', u8'B', u8'C', u8'D', u8'E', u8'F', u8'G', u8'H', u8'I', u8'J', u8'K', u8'L', u8'M', u8'N', u8'O', u8'P',
    u8'Q', u8'R', u8'S', u8'T', u8'U', u8'V', u8'W', u8'X', u8'Y', u8'Z', u8'a', u8'b', u8'c', u8'd', u8'e', u8'f',
    u8'g', u8'h', u8'i', u8'j', u8'k', u8'l', u8'm', u8'n', u8'o', u8'p', u8'q', u8'r', u8's', u8't', u8'u', u8'v',
    u8'w', u8'x', u8'y', u8'z', u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'+', u8'/'};
// u8"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
inline constexpr char8_t base64_url[] = {
    u8'A', u8'B', u8'C', u8'D', u8'E', u8'F', u8'G', u8'H', u8'I', u8'J', u8'K', u8'L', u8'M', u8'N', u8'O', u8'P',
    u8'Q', u8'R', u8'S', u8'T', u8'U', u8'V', u8'W', u8'X', u8'Y', u8'Z', u8'a', u8'b', u8'c', u8'd', u8'e', u8'f',
    u8'g', u8'h', u8'i', u8'j', u8'k', u8'l', u8'm', u8'n', u8'o', u8'p', u8'q', u8'r', u8's', u8't', u8'u', u8'v',
    u8'w', u8'x', u8'y', u8'z', u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'-', u8'_'};
// u8"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
inline constexpr char8_t base32[] = {u8'A', u8'B', u8'C', u8'D', u8'E', u8'F', u8'G', u8'H', u8'I', u8'J', u8'K',
                                     u8'L', u8'M', u8'N', u8'O', u8'P', u8'Q', u8'R', u8'S', u8'T', u8'U', u8'V',
                                     u8'W', u8'X', u8'Y', u8'Z', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7'};
// u8"abcdefghijklmnopqrstuvwxyz234567"
inline constexpr char8_t base32_lower[] = {u8'a', u8'b', u8'c', u8'd', u8'e', u8'f', u8'g', u8'h', u8'i', u8'j', u8'k',
                                           u8'l', u8'm', u8'n', u8'o', u8'p', u8'q', u8'r', u8's', u8't', u8'u', u8'v',
                                           u8'w', u8'x', u8'y', u8'z', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7'};
// u8"0123456789ABCDEFGHIJKLMNOPQRSTUV"
inline constexpr char8_t base32_hex[] = {u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'A',
                                         u8'B', u8'C', u8'D', u8'E', u8'F', u8'G', u8'H', u8'I', u8'J', u8'K', u8'L',
                                         u8'M', u8'N', u8'O', u8'P', u8'Q', u8'R', u8'S', u8'T', u8'U', u8'V'};
// u8"0123456789abcdefghijklmnopqrstuv"
inline constexpr char8_t base32_hex_lower[] = {
    u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'a', u8'b', u8'c', u8'd', u8'e', u8'f',
    u8'g', u8'h', u8'i', u8'j', u8'k', u8'l', u8'm', u8'n', u8'o', u8'p', u8'q', u8'r', u8's', u8't', u8'u', u8'v'};
// u8"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
inline constexpr char8_t base32_crockford[] = {
    u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'A', u8'B', u8'C', u8'D', u8'E', u8'F',
    u8'G', u8'H', u8'J', u8'K', u8'M', u8'N', u8'P', u8'Q', u8'R', u8'S', u8'T', u8'V', u8'W', u8'X', u8'Y', u8'Z'};
// u8"0123456789abcdefghjkmnpqrstvwxyz"
inline constexpr char8_t base32_crockford_lower[] = {
    u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7', u8'8', u8'9', u8'a', u8'b', u8'c', u8'd', u8'e', u8'f',
    u8'g', u8'h', u8'j', u8'k', u8'm', u8'n', u8'p', u8'q', u8'r', u8's', u8't', u8'v', u8'w', u8'x', u8'y', u8'z'};
// u8"0123456789ABCDEF"
inline constexpr char8_t base16[] = {u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7',
                                     u8'8', u8'9', u8'A', u8'B', u8'C', u8'D', u8'E', u8'F'};
// u8"0123456789abcdef"
inline constexpr char8_t base16_lower[] = {u8'0', u8'1', u8'2', u8'3', u8'4', u8'5', u8'6', u8'7',
                                           u8'8', u8'9', u8'a', u8'b', u8'c', u8'd', u8'e', u8'f'};
}; // namespace pattern

template <typename T>
inline constexpr unsigned char to_uc(T t) noexcept
{
    // T is char, unsigned char or std::byte
    return static_cast<unsigned char>(t);
}

template <rfc4648_kind Kind>
inline consteval decltype(auto) get_alphabet() noexcept
{
    if constexpr (Kind == rfc4648_kind::base64)
        return (pattern::base64);
    if constexpr (Kind == rfc4648_kind::base64_url)
        return (pattern::base64_url);
    if constexpr (Kind == rfc4648_kind::base32)
        return (pattern::base32);
    if constexpr (Kind == rfc4648_kind::base32_lower)
        return (pattern::base32_lower);
    if constexpr (Kind == rfc4648_kind::base32_hex)
        return (pattern::base32_hex);
    if constexpr (Kind == rfc4648_kind::base32_hex_lower)
        return (pattern::base32_hex_lower);
    if constexpr (Kind == rfc4648_kind::base32_crockford)
        return (pattern::base32_crockford);
    if constexpr (Kind == rfc4648_kind::base32_crockford_lower)
        return (pattern::base32_crockford_lower);
    if constexpr (Kind == rfc4648_kind::base16)
        return (pattern::base16);
    if constexpr (Kind == rfc4648_kind::base16_lower)
        return (pattern::base16_lower);
}

template <std::size_t Count, typename T>
inline constexpr auto chars_to_int_big_endian(T begin)
{
    static_assert(Count < 9);
    static_assert(std::endian::native == std::endian::big || std::endian::native == std::endian::little);

    constexpr auto size = Count <= 4 ? 4 : 8;

    using int32_type = std::conditional_t<sizeof(int) == 4, unsigned int, unsigned long>;
    using data_type = std::conditional_t<size == 4, int32_type, unsigned long long>;

#if defined(__cpp_if_consteval) && (__cpp_if_consteval >= 202106L)
    if consteval
#else
    if (::std::is_constant_evaluated())
#endif
    {
        unsigned char buf[size]{};

        for (std::size_t i{}; i != Count; ++i, ++begin)
            buf[i] = to_uc(*begin);

        if constexpr (std::endian::native == std::endian::little)
            return std::byteswap(std::bit_cast<data_type>(buf));
        else
            return std::bit_cast<data_type>(buf);
    }
    else
    {
        data_type buf{};

        std::memcpy(&buf, begin, Count);

        if constexpr (std::endian::native == std::endian::little)
            return std::byteswap(buf);
        else
            return buf;
    }
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b64_6(I begin, O &first)
{
    auto data = chars_to_int_big_endian<6>(begin);

    *first = Alphabet[(data >> 58) & 63];
    ++first;
    *first = Alphabet[(data >> 52) & 63];
    ++first;
    *first = Alphabet[(data >> 46) & 63];
    ++first;
    *first = Alphabet[(data >> 40) & 63];
    ++first;
    *first = Alphabet[(data >> 34) & 63];
    ++first;
    *first = Alphabet[(data >> 28) & 63];
    ++first;
    *first = Alphabet[(data >> 22) & 63];
    ++first;
    *first = Alphabet[(data >> 16) & 63];
    ++first;
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b64_3(I begin, O &first)
{
    auto data = chars_to_int_big_endian<3>(begin);

    *first = Alphabet[(data >> 26) & 63];
    ++first;
    *first = Alphabet[(data >> 20) & 63];
    ++first;
    *first = Alphabet[(data >> 14) & 63];
    ++first;
    *first = Alphabet[(data >> 8) & 63];
    ++first;
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b64_2(I begin, O &first)
{
    auto data = chars_to_int_big_endian<2>(begin);

    *first = Alphabet[(data >> 26) & 63];
    ++first;
    *first = Alphabet[(data >> 20) & 63];
    ++first;
    *first = Alphabet[(data >> 14) & 63];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'=';
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b64_1(I begin, O &first)
{
    auto a = to_uc(*begin);
    auto b = a >> 2;        // XXXXXX
    auto c = (a << 4) & 63; // XX0000

    *first = Alphabet[b];
    ++first;
    *first = Alphabet[c];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'='; // pad1
        ++first;
        *first = u8'='; // pad2
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b64(I begin, I end, O &first)
{
    if constexpr (sizeof(std::size_t) == 8)
    {
        for (; end - begin > 5; begin += 6)
            encode_impl_b64_6<Alphabet>(begin, first);
    }

    for (; end - begin > 2; begin += 3)
        encode_impl_b64_3<Alphabet>(begin, first);

    if (end - begin == 2)
        encode_impl_b64_2<Alphabet, Padding>(begin, first);
    else if (end - begin) // == 1
        encode_impl_b64_1<Alphabet, Padding>(begin, first);

    // == 0  fallthrough
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b64_ctx(detail::buf_ref buf, detail::sig_ref sig, I begin, I end, O &first)
{
    if (sig == 2) // 0, 1, 2
    {
        if (begin == end)
            return;
        // assume(end - begin >= 1)
        unsigned char lbuf[3];

        lbuf[0] = buf[0];
        lbuf[1] = buf[1];
        lbuf[2] = to_uc(*(begin++));

        encode_impl_b64_3<Alphabet>(std::begin(lbuf), first);
    }
    else if (sig) // == 1
    {
        if (begin == end)
            return;
        // assume(end - begin >= 1)
        if (end - begin == 1)
        {
            buf[1] = to_uc(*(begin++));
            sig = 2;

            return;
        }
        else // >= 2
        {
            unsigned char lbuf[3];

            lbuf[0] = buf[0];
            lbuf[1] = to_uc(*(begin++));
            lbuf[2] = to_uc(*(begin++));

            encode_impl_b64_3<Alphabet>(std::begin(lbuf), first);
        }
    }

    if constexpr (sizeof(std::size_t) == 8)
    {
        for (; end - begin > 5; begin += 6)
            encode_impl_b64_6<Alphabet>(begin, first);
    }

    for (; end - begin > 3; begin += 3)
        encode_impl_b64_3<Alphabet>(begin, first);

    if (end - begin == 2)
    {
        buf[0] = to_uc(*(begin++));
        buf[1] = to_uc(*(begin));
        sig = 2;
    }
    else if (end - begin) // == 1
    {
        buf[0] = to_uc(*begin);
        sig = 1;
    }
    else // NB: clear ctx
    {
        sig = 0;
    }
}

template <auto Alphabet, bool Padding, typename O>
inline constexpr void encode_impl_b64_ctx(detail::buf_ref buf, detail::sig_ref sig, O &first)
{
    if (sig == 2)
        encode_impl::encode_impl_b64_2<Alphabet, Padding>(std::begin(buf), first);
    else if (sig) // == 1
        encode_impl::encode_impl_b64_1<Alphabet, Padding>(std::begin(buf), first);
    // == 0  fallthrough

    // clear ctx
    sig = 0;
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b32_5(I begin, O &first)
{
    auto data = chars_to_int_big_endian<5>(begin);

    *first = Alphabet[(data >> 59) & 31];
    ++first;
    *first = Alphabet[(data >> 54) & 31];
    ++first;
    *first = Alphabet[(data >> 49) & 31];
    ++first;
    *first = Alphabet[(data >> 44) & 31];
    ++first;
    *first = Alphabet[(data >> 39) & 31];
    ++first;
    *first = Alphabet[(data >> 34) & 31];
    ++first;
    *first = Alphabet[(data >> 29) & 31];
    ++first;
    *first = Alphabet[(data >> 24) & 31];
    ++first;
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b32_4(I begin, O &first)
{
    auto data = chars_to_int_big_endian<4>(begin);

    *first = Alphabet[(data >> 27) & 31];
    ++first;
    *first = Alphabet[(data >> 22) & 31];
    ++first;
    *first = Alphabet[(data >> 17) & 31];
    ++first;
    *first = Alphabet[(data >> 12) & 31];
    ++first;
    *first = Alphabet[(data >> 7) & 31];
    ++first;
    *first = Alphabet[(data >> 2) & 31];
    ++first;
    // NB: left shift
    *first = Alphabet[(data << 3) & 31];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'=';
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b32_3(I begin, O &first)
{
    auto data = chars_to_int_big_endian<3>(begin);

    *first = Alphabet[(data >> 27) & 31];
    ++first;
    *first = Alphabet[(data >> 22) & 31];
    ++first;
    *first = Alphabet[(data >> 17) & 31];
    ++first;
    *first = Alphabet[(data >> 12) & 31];
    ++first;
    *first = Alphabet[(data >> 7) & 31];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b32_2(I begin, O &first)
{
    auto data = chars_to_int_big_endian<2>(begin);

    *first = Alphabet[(data >> 27) & 31];
    ++first;
    *first = Alphabet[(data >> 22) & 31];
    ++first;
    *first = Alphabet[(data >> 17) & 31];
    ++first;
    *first = Alphabet[(data >> 12) & 31];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b32_1(I begin, O &first)
{
    auto a = to_uc(*(begin));

    *first = Alphabet[a >> 3];
    ++first;
    *first = Alphabet[(a << 2) & 31];
    ++first;

    if constexpr (Padding)
    {
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
        *first = u8'=';
        ++first;
    }
}

template <auto Alphabet, bool Padding, typename I, typename O>
inline constexpr void encode_impl_b32(I begin, I end, O &first)
{
    for (; end - begin > 4; begin += 5)
        encode_impl_b32_5<Alphabet>(begin, first);

    if (end - begin == 4)
        encode_impl_b32_4<Padding, Alphabet>(begin, first);
    else if (end - begin == 3)
        encode_impl_b32_3<Padding, Alphabet>(begin, first);
    else if (end - begin == 2)
        encode_impl_b32_2<Padding, Alphabet>(begin, first);
    else if (end - begin) // == 1
        encode_impl_b32_1<Padding, Alphabet>(begin, first);
    // == 0  fallthrough
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b32_ctx(detail::buf_ref buf, detail::sig_ref sig, I begin, I end, O &first)
{
#if __has_cpp_attribute(assume)
    [[assume(sig < 5)]];
    [[assume(end - begin >= 0)]];
#endif

    if (end - begin + sig < 5)
    {
        for (; begin != end; ++begin, ++sig)
            buf[sig] = to_uc(*begin);

        return;
    }

    if (sig)
    {
        unsigned char lbuf[5];

        std::copy(std::begin(buf), std::begin(buf) + sig, std::begin(lbuf));
        std::copy(begin, begin + (5 - sig), std::begin(lbuf) + sig);
        begin += (5 - sig);

        encode_impl_b32_5<Alphabet>(std::begin(lbuf), first);
    }

    for (; end - begin > 4; begin += 5)
        encode_impl_b32_5<Alphabet>(begin, first);

    sig = static_cast<unsigned char>(end - begin);

    for (std::size_t i{}; i != sig; ++i, ++begin)
        buf[i] = to_uc(*begin);
}

template <auto Alphabet, bool Padding, typename O>
inline constexpr void encode_impl_b32_ctx(detail::buf_ref buf, detail::sig_ref sig, O &first)
{
    if (sig == 1)
        encode_impl_b32_1<Padding, Alphabet>(std::begin(buf), first);
    else if (sig == 2)
        encode_impl_b32_2<Padding, Alphabet>(std::begin(buf), first);
    else if (sig == 3)
        encode_impl_b32_3<Padding, Alphabet>(std::begin(buf), first);
    else if (sig == 4)
        encode_impl_b32_4<Padding, Alphabet>(std::begin(buf), first);

    sig = 0;
}

template <auto Alphabet, typename I, typename O>
inline constexpr void encode_impl_b16(I begin, I end, O &first)
{
    if constexpr (sizeof(size_t) == 8)
    {
        for (; end - begin > 7; begin += 8)
        {
            auto data = chars_to_int_big_endian<8>(begin);

            for (std::size_t i{}; i < 16; ++i)
                *(first++) = Alphabet[(data >> (64 - (i + 1) * 4)) & 15];
        }
    }
    else // 32-bit machine
    {
        for (; end - begin > 3; begin += 4)
        {
            auto data = chars_to_int_big_endian<4>(begin);

            for (std::size_t i{}; i < 8; ++i)
                *(first++) = Alphabet[(data >> (32 - (i + 1) * 4)) & 15];
        }
    }

    for (; begin != end; ++begin)
    {
        auto data = to_uc(*begin);

        *first = Alphabet[data >> 4];
        ++first;
        *first = Alphabet[data & 15];
        ++first;
    }
}

} // namespace encode_impl

template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename In, typename Out>
inline constexpr Out rfc4648_encode(In begin, In end, Out first)
{
    using in_char = std::iterator_traits<In>::value_type;

    static_assert(std::contiguous_iterator<In>);
    static_assert(std::is_same_v<in_char, char> || std::is_same_v<in_char, unsigned char> ||
                  std::is_same_v<in_char, std::byte>);

    auto begin_ptr = detail::to_address_const(begin);
    auto end_ptr = detail::to_address_const(end);

    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base64)
        encode_impl::encode_impl_b64<encode_impl::get_alphabet<Kind>(), Padding>(begin_ptr, end_ptr, first);
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base32)
        encode_impl::encode_impl_b32<encode_impl::get_alphabet<Kind>(), Padding>(begin_ptr, end_ptr, first);
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base16)
        encode_impl::encode_impl_b16<encode_impl::get_alphabet<Kind>()>(begin_ptr, end_ptr, first);

    return first;
}

template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename R, typename Out>
inline constexpr Out rfc4648_encode(R &&r, Out first)
{
    return rfc4648_encode<Kind, Padding>(std::ranges::begin(r), std::ranges::end(r), first);
}

// NB: don't need padding
template <rfc4648_kind Kind = rfc4648_kind::base64, typename In, typename Out>
inline constexpr Out rfc4648_encode(rfc4648_context &ctx, In begin, In end, Out first)
{
    using in_char = std::iterator_traits<In>::value_type;

    static_assert(std::contiguous_iterator<In>);
    static_assert(std::is_same_v<in_char, char> || std::is_same_v<in_char, unsigned char> ||
                  std::is_same_v<in_char, std::byte>);

    auto begin_ptr = detail::to_address_const(begin);
    auto end_ptr = detail::to_address_const(end);

    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base64)
        encode_impl::encode_impl_b64_ctx<encode_impl::get_alphabet<Kind>()>(ctx.buf_, ctx.sig_, begin_ptr, end_ptr,
                                                                            first);
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base32)
        encode_impl::encode_impl_b32_ctx<encode_impl::get_alphabet<Kind>()>(ctx.buf_, ctx.sig_, begin_ptr, end_ptr,
                                                                            first);
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base16)
        encode_impl::encode_impl_b16<encode_impl::get_alphabet<Kind>()>(begin_ptr, end_ptr, first);

    return first;
}

template <rfc4648_kind Kind = rfc4648_kind::base64, typename R, typename Out>
inline constexpr Out rfc4648_encode(rfc4648_context &ctx, R &&r, Out first)

{
    return rfc4648_encode<Kind>(ctx, std::ranges::begin(r), std::ranges::end(r), first);
}

template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename Out>
inline constexpr Out rfc4648_encode(rfc4648_context &ctx, Out first)
{
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base64)
        encode_impl::encode_impl_b64_ctx<encode_impl::get_alphabet<Kind>(), Padding>(ctx.buf_, ctx.sig_, first);
    if constexpr (detail::get_family<Kind>() == rfc4648_kind::base32)
        encode_impl::encode_impl_b32_ctx<encode_impl::get_alphabet<Kind>(), Padding>(ctx.buf_, ctx.sig_, first);
    // no effect when family is base16 and CHAR_BIT is 8

    return first;
}
} // namespace bizwen
