# rfc4648/base64/base32/base16-hex

A plain header-only [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) encoding/decoding library, but with the most modern C++ API design.

This repository uses NTTP to select encoding/decoding schemes and control padding characters. [Another way](https://github.com/YexuanXiao/rfc4648-afo) is to use function parameters, which allows it to be implemented as [Algorithm Function Objects](https://en.cppreference.com/w/cpp/algorithm/ranges#Algorithm_function_objects) (AFOs).

All variants of RFC 4648 are supported and the Crockford variant is available.

Support input from discontinuous multiple buffers.

Support non-padding for secure base64 url variant.

Support `constexpr` compile-time caculation.

C++23 required (`std::byteswap`).

## Synopsis

```cpp
// All functions are constexpr
enum class rfc4648_kind
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
// All special member functions are trivial and has non-trivial but noexcept default constructor
class rfc4648_context;
//
template <typename In, typename Out>
struct rfc4648_decode_result
{
    In end;
    Out out;
    // For rebinding via std::tie
    operator std::tuple<End &, Out &>() && noexcept;
};
// Encode
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename In, typename Out>
Out rfc4648_encode(In begin, In end, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename R, typename Out>
Out rfc4648_encode(R&& r, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, typename In, typename Out>
Out rfc4648_encode(rfc4648_context& ctx, In begin, In end, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, typename R, typename Out>
Out rfc4648_encode(rfc4648_context& ctx, R&& r, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename Out>
Out rfc4648_encode(rfc4648_context& ctx, Out first);
// Decode
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename In, typename Out>
rfc4648_decode_result<In, Out> rfc4648_decode(In begin, In end, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename R, typename Out>
rfc4648_decode_result<In, Out> rfc4648_decode(R&& r, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, typename In, typename Out>
rfc4648_decode_result<In, Out> rfc4648_decode(rfc4648_context& ctx, In begin, In end, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, typename R, typename Out>
rfc4648_decode_result<In, Out> rfc4648_decode(rfc4648_context& ctx, R&& r, Out first);
template <rfc4648_kind Kind = rfc4648_kind::base64, bool Padding = true, typename In>
In rfc4648_decode(rfc4648_context& ctx, In begin, In end);
// Helper functions
template <rfc4648_kind kind = rfc4648_kind::base64>
std::size_t rfc4648_encode_length(std::size_t input) noexcept;
template <rfc4648_kind kind = rfc4648_kind::base64>
std::size_t rfc4648_decode_length(std::size_t input) noexcept;
```

`R` must model `std::contiguous_range` , `In` must satisfy *ContinuousIterator* and `Out` must satisfy *OutputIterator*.

Let `n - 1` is the length of the output as specified by RFC 4648.

If [`begin`, `end`) is not a valid range, or [`first`, `first + n`) is not a valid range, or if [`begin`, `end`) and [`first`, `first + n`) overlap, or if `r` and [`first`, `first + n`) overlap, the behavior is undefined.

If the template parameter `Padding` is `false` then the padding character `=` is not written.

The decode functions will return immediately if there are invalid characters (including `=`) within the range [`begin`, `end`), then `rfc4648_decode_result<In, Out>::end` points to the first invalid character.

Throws any exceptions from increments and dereferences `begin`, `end` or `first`, no other exceptions will be thrown. After an exception is thrown, `ctx` will be in an unspecified state.

The `rfc4648_encode_length` and `rfc4648_decode_length` functions calculate the maximum number of characters/bytes needed for a given input length. The actual output number will be less than or equal to the returned number.

## Example

```cpp
#include "decode.hpp"
#include "encode.hpp"
#include <cassert>
#include <string>
#include <string_view>

#define test_str "ABCDEFGHIJKLMN"

int main()
{
    std::string_view src1{test_str};

    std::string encoded1;
    encoded1.resize(bizwen::rfc4648_encode_length(src1.size()));
    bizwen::rfc4648_encode(src1.begin(), src1.end(), encoded1.begin());

    std::string decoded1;
    decoded1.resize(src1.size());
    bizwen::rfc4648_decode(encoded1.begin(), encoded1.end(), decoded1.begin());

    assert(src1 == decoded1);

    std::string_view src2{test_str test_str test_str};
    std::string encoded2;
    encoded2.resize(bizwen::rfc4648_encode_length(src2.size()));
    bizwen::rfc4648_context ctx;

    auto eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), encoded2.begin());
    eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), eit);
    eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), eit);
    // This overload handles remaining bits and outputs the padding characters
    bizwen::rfc4648_encode(ctx, eit);

    std::string decoded2;
    decoded2.resize(src2.size());
    auto [end, dit] = bizwen::rfc4648_decode(ctx, encoded2.begin(), encoded2.begin() + encoded2.size() / 3, decoded2.begin());
    // If there is an error in decoding, then the assertion fails
    assert(end == encoded2.begin() + encoded2.size() / 3);
    std::tie(end, dit) = bizwen::rfc4648_decode(ctx, end, end + encoded2.size() / 3, dit);
    // If it is the last input data, then the returned end may point to the first padding character
    // even if the input data is correct
    std::tie(end, dit) = bizwen::rfc4648_decode(ctx, end, end + (encoded2.size() - encoded2.size() / 3 * 2), dit);
    // It should not be asserted that the returned end is equal to the input end
    // This overload is used to check the padding characters
    end = bizwen::rfc4648_decode(ctx, end, encoded2.end());
    // The assertion can only be true when the last check is complete
    assert(end == encoded2.end());

    assert(src2 == decoded2);

    std::string encoded3;
    encoded3.resize(bizwen::rfc4648_encode_length(src1.size()));
    bizwen::rfc4648_encode(src1, encoded3.begin());

    std::wstring dest3;
    dest3.resize(bizwen::rfc4648_encode_length(src1.size()));
    bizwen::rfc4648_encode((std::byte *)src1.data(), (std::byte *)src1.data() + src1.size(), dest3.begin());
}
```
