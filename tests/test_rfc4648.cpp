#include "decode.hpp"
#include "encode.hpp"
#include "tests/generated_vectors.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{
using rfc4648_test_vectors::vector;

template <bizwen::rfc4648_kind Kind>
inline constexpr bool encoding_supported =
    !(Kind == bizwen::rfc4648_kind::base32_mixed || Kind == bizwen::rfc4648_kind::base32_hex_mixed ||
      Kind == bizwen::rfc4648_kind::base32_crockford_mixed || Kind == bizwen::rfc4648_kind::base16_mixed);

[[nodiscard]] std::string invert_ascii_alpha_case(std::string_view s)
{
    std::string out{s};
    for (char &c : out)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
        else if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 'a' + 'A');
    }
    return out;
}

template <bizwen::rfc4648_kind Kind, bool Padding>
void check_vector_once(vector const &v)
{
    std::span<unsigned char const> input{v.input, v.input_size};
    std::string_view expected = v.encoded;

    if constexpr (encoding_supported<Kind>)
    {
        std::string encoded(expected.size(), '\0');
        auto encoded_end = bizwen::rfc4648_encode<Kind, Padding>(input.begin(), input.end(), encoded.begin());
        assert(encoded_end == encoded.end());
        assert(encoded == expected);

        std::string encoded_range(expected.size(), '\0');
        auto encoded_range_end = bizwen::rfc4648_encode<Kind, Padding>(input, encoded_range.begin());
        assert(encoded_range_end == encoded_range.end());
        assert(encoded_range == expected);

        assert(bizwen::rfc4648_encode_length<Kind>(input.size()) >= expected.size());
    }

    assert(bizwen::rfc4648_decode_length<Kind>(expected.size()) >= input.size());

    std::vector<unsigned char> decoded(input.size());
    auto [end1, out1] = bizwen::rfc4648_decode<Kind, Padding>(expected.begin(), expected.end(), decoded.begin());
    assert(end1 == expected.end());
    assert(out1 == decoded.end());
    if (!std::equal(decoded.begin(), decoded.end(), input.begin(), input.end()))
    {
        std::fprintf(stderr,
                     "decode mismatch: kind=%d padding=%d input_size=%zu encoded=\"%.*s\"\n",
                     static_cast<int>(Kind), static_cast<int>(Padding), input.size(), static_cast<int>(expected.size()),
                     expected.data());
        std::abort();
    }

    std::vector<unsigned char> decoded_range(input.size());
    auto [end2, out2] = bizwen::rfc4648_decode<Kind, Padding>(expected, decoded_range.begin());
    assert(end2 == expected.end());
    assert(out2 == decoded_range.end());
    if (!std::equal(decoded_range.begin(), decoded_range.end(), input.begin(), input.end()))
    {
        std::fprintf(stderr,
                     "decode(range) mismatch: kind=%d padding=%d input_size=%zu encoded=\"%.*s\"\n",
                     static_cast<int>(Kind), static_cast<int>(Padding), input.size(), static_cast<int>(expected.size()),
                     expected.data());
        std::abort();
    }
}

template <bizwen::rfc4648_kind Kind, bool Padding>
void check_vector_with_context(vector const &v)
{
    std::span<unsigned char const> input{v.input, v.input_size};
    std::string_view expected = v.encoded;

    if constexpr (encoding_supported<Kind>)
    {
        {
            std::string encoded(expected.size(), '\0');
            bizwen::rfc4648_context ctx;

            auto out = encoded.begin();
            auto const *p = input.data();
            auto n = input.size();

            auto n1 = std::min<std::size_t>(1, n);
            auto n2 = std::min<std::size_t>(2, n - n1);

            out = bizwen::rfc4648_encode<Kind>(ctx, p, p + n1, out);
            out = bizwen::rfc4648_encode<Kind>(ctx, p + n1, p + n1 + n2, out);
            out = bizwen::rfc4648_encode<Kind>(ctx, p + n1 + n2, p + n, out);
            out = bizwen::rfc4648_encode<Kind, Padding>(ctx, out);

            assert(out == encoded.end());
            if (encoded != expected)
            {
                std::fprintf(stderr,
                             "context encode mismatch: kind=%d padding=%d input_size=%zu expected=\"%.*s\" actual=\"%.*s\"\n",
                             static_cast<int>(Kind), static_cast<int>(Padding), input.size(),
                             static_cast<int>(expected.size()), expected.data(), static_cast<int>(encoded.size()),
                             encoded.data());
                std::abort();
            }
        }
    }

    {
        std::vector<unsigned char> decoded(input.size());
        bizwen::rfc4648_context ctx;

        auto out = decoded.begin();

        auto begin = expected.begin();
        auto end = expected.end();

        auto first_pad = expected.find('=');
        if (first_pad == std::string_view::npos)
            first_pad = expected.size();

        auto c1 = std::min<std::size_t>(1, first_pad);
        auto c2 = std::min<std::size_t>(2, first_pad - c1);

        auto mid1 = begin + static_cast<std::ptrdiff_t>(c1);
        auto mid2 = mid1 + static_cast<std::ptrdiff_t>(c2);

        auto [it1, out1] = bizwen::rfc4648_decode<Kind>(ctx, begin, mid1, out);
        assert(it1 == mid1);
        std::tie(it1, out1) = bizwen::rfc4648_decode<Kind>(ctx, it1, mid2, out1);
        assert(it1 == mid2);
        auto [it3, out3] = bizwen::rfc4648_decode<Kind>(ctx, it1, end, out1);

        auto it4 = bizwen::rfc4648_decode<Kind, Padding>(ctx, it3, end);
        assert(it4 == end);

        assert(out3 == decoded.end());
        assert(std::equal(decoded.begin(), decoded.end(), input.begin(), input.end()));
    }
}

template <template <bizwen::rfc4648_kind, bool> class Fn>
void dispatch_kind_padding(vector const &v)
{
    auto const call = [&]<bizwen::rfc4648_kind Kind>() {
        if (v.padding)
            Fn<Kind, true>::run(v);
        else
            Fn<Kind, false>::run(v);
    };

    switch (v.kind)
    {
    case bizwen::rfc4648_kind::base64:
        return call.template operator()<bizwen::rfc4648_kind::base64>();
    case bizwen::rfc4648_kind::base64_url:
        return call.template operator()<bizwen::rfc4648_kind::base64_url>();
    case bizwen::rfc4648_kind::base32:
        return call.template operator()<bizwen::rfc4648_kind::base32>();
    case bizwen::rfc4648_kind::base32_lower:
        return call.template operator()<bizwen::rfc4648_kind::base32_lower>();
    case bizwen::rfc4648_kind::base32_mixed:
        return call.template operator()<bizwen::rfc4648_kind::base32_mixed>();
    case bizwen::rfc4648_kind::base32_hex:
        return call.template operator()<bizwen::rfc4648_kind::base32_hex>();
    case bizwen::rfc4648_kind::base32_hex_lower:
        return call.template operator()<bizwen::rfc4648_kind::base32_hex_lower>();
    case bizwen::rfc4648_kind::base32_hex_mixed:
        return call.template operator()<bizwen::rfc4648_kind::base32_hex_mixed>();
    case bizwen::rfc4648_kind::base32_crockford:
        return call.template operator()<bizwen::rfc4648_kind::base32_crockford>();
    case bizwen::rfc4648_kind::base32_crockford_lower:
        return call.template operator()<bizwen::rfc4648_kind::base32_crockford_lower>();
    case bizwen::rfc4648_kind::base32_crockford_mixed:
        return call.template operator()<bizwen::rfc4648_kind::base32_crockford_mixed>();
    case bizwen::rfc4648_kind::base16:
        return call.template operator()<bizwen::rfc4648_kind::base16>();
    case bizwen::rfc4648_kind::base16_lower:
        return call.template operator()<bizwen::rfc4648_kind::base16_lower>();
    case bizwen::rfc4648_kind::base16_mixed:
        return call.template operator()<bizwen::rfc4648_kind::base16_mixed>();
    }
    assert(false);
}

template <bizwen::rfc4648_kind Kind, bool Padding>
struct check_once
{
    static void run(vector const &v)
    {
        check_vector_once<Kind, Padding>(v);
    }
};

template <bizwen::rfc4648_kind Kind, bool Padding>
struct check_ctx
{
    static void run(vector const &v)
    {
        check_vector_with_context<Kind, Padding>(v);
    }
};

template <bizwen::rfc4648_kind Kind, bool Padding>
void check_mixed_decode(std::string_view encoded, std::span<unsigned char const> expected_plain)
{
    std::string flipped = invert_ascii_alpha_case(encoded);

    if (flipped == encoded)
        return;

    std::vector<unsigned char> decoded(expected_plain.size());
    auto [end, out] = bizwen::rfc4648_decode<Kind, Padding>(flipped.begin(), flipped.end(), decoded.begin());
    assert(end == flipped.end());
    assert(out == decoded.end());
    assert(std::equal(decoded.begin(), decoded.end(), expected_plain.begin(), expected_plain.end()));
}
} // namespace

int main()
{
    for (vector const &v : rfc4648_test_vectors::vectors)
    {
        dispatch_kind_padding<check_once>(v);
        dispatch_kind_padding<check_ctx>(v);

        std::span<unsigned char const> input{v.input, v.input_size};

        // Case-insensitive decode variants.
        if (v.kind == bizwen::rfc4648_kind::base32_mixed)
        {
            if (v.padding)
                check_mixed_decode<bizwen::rfc4648_kind::base32_mixed, true>(v.encoded, input);
            else
                check_mixed_decode<bizwen::rfc4648_kind::base32_mixed, false>(v.encoded, input);
        }
        else if (v.kind == bizwen::rfc4648_kind::base32_hex_mixed)
        {
            if (v.padding)
                check_mixed_decode<bizwen::rfc4648_kind::base32_hex_mixed, true>(v.encoded, input);
            else
                check_mixed_decode<bizwen::rfc4648_kind::base32_hex_mixed, false>(v.encoded, input);
        }
        else if (v.kind == bizwen::rfc4648_kind::base32_crockford_mixed)
        {
            if (v.padding)
                check_mixed_decode<bizwen::rfc4648_kind::base32_crockford_mixed, true>(v.encoded, input);
            else
                check_mixed_decode<bizwen::rfc4648_kind::base32_crockford_mixed, false>(v.encoded, input);
        }
        else if (v.kind == bizwen::rfc4648_kind::base16_mixed)
        {
            check_mixed_decode<bizwen::rfc4648_kind::base16_mixed, true>(v.encoded, input);
        }
    }

    // Base64-url must round-trip '-' and '_' correctly.
    {
        std::array<unsigned char, 2> data{0xFB, 0xFF};
        std::string encoded(4, '\0');
        bizwen::rfc4648_encode<bizwen::rfc4648_kind::base64_url, true>(data.begin(), data.end(), encoded.begin());
        assert(encoded.find('-') != std::string::npos || encoded.find('_') != std::string::npos);

        std::array<unsigned char, 2> decoded{};
        auto [end, out] =
            bizwen::rfc4648_decode<bizwen::rfc4648_kind::base64_url, true>(encoded.begin(), encoded.end(), decoded.begin());
        assert(end == encoded.end());
        assert(out == decoded.end());
        assert(decoded == data);
    }

    // Crockford lower/mixed must reject non-alphabet junk.
    {
        std::string_view junk = "{";
        std::array<unsigned char, 8> out{};
        auto [end1, _] = bizwen::rfc4648_decode<bizwen::rfc4648_kind::base32_crockford_lower, true>(junk.begin(), junk.end(), out.begin());
        assert(end1 == junk.begin());
        auto [end2, __] = bizwen::rfc4648_decode<bizwen::rfc4648_kind::base32_crockford_mixed, true>(junk.begin(), junk.end(), out.begin());
        assert(end2 == junk.begin());
    }

    return 0;
}
