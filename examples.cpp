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
    encoded1.resize((src1.size() + 2) / 3 * 4);
    bizwen::rfc4648_encode(src1.begin(), src1.end(), encoded1.begin());

    std::string decoded1;
    decoded1.resize(src1.size());
    bizwen::rfc4648_decode(encoded1.begin(), encoded1.end(), decoded1.begin());

    assert(src1 == decoded1);

    std::string_view src2{test_str test_str test_str};
    std::string encoded2;
    encoded2.resize((src2.size() + 2) / 3 * 4);
    bizwen::rfc4648_context ctx;

    auto eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), encoded2.begin());
    eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), eit);
    eit = bizwen::rfc4648_encode(ctx, src1.begin(), src1.end(), eit);
    // This function outputs the padding characters
    bizwen::rfc4648_encode(ctx, eit);

    std::string decoded2;
    decoded2.resize(src2.size());
    auto [end, dit] =
        bizwen::rfc4648_decode(ctx, encoded2.begin(), encoded2.begin() + encoded2.size() / 3, decoded2.begin());
    // If there is an error in decoding, then the assertion fails
    assert(end == encoded2.begin() + encoded2.size() / 3);
    std::tie(end, dit) = bizwen::rfc4648_decode(ctx, end, end + encoded2.size() / 3, dit);
    // If it is the last input data, then the returned end may point to the first padding character
    // even if the input data is correct
    std::tie(end, dit) = bizwen::rfc4648_decode(ctx, end, end + (encoded2.size() - encoded2.size() / 3 * 2), dit);
    // It should not be asserted that the returned end is equal to the input end
    // This function uses to check the padding characters
    end = bizwen::rfc4648_decode(ctx, end, encoded2.end());
    // The assertion can only be true when the last check is complete
    assert(end == encoded2.end());

    assert(src2 == decoded2);

    std::string encoded3;
    encoded3.resize((src1.size() + 2) / 3 * 4);
    bizwen::rfc4648_encode(src1, encoded3.begin());

    std::wstring dest3;
    dest3.resize((src1.size() + 2) / 3 * 4);
    bizwen::rfc4648_encode((std::byte *)src1.data(), (std::byte *)src1.data() + src1.size(), dest3.begin());
}
