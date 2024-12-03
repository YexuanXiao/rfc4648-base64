#include "encode.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <string_view>

using namespace std::string_view_literals;

constexpr auto src =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam mollis imperdiet massa, at dapibus elit "
    "interdumac. In eget sollicitudin mi. Nam at tellus at sapien tincidunt sollicitudin vel non eros. Pellentesque "
    "nunc nunc,ullamcorper eu accumsan at, pulvinar non turpis. Quisque vel mauris pulvinar, pretium purus vel, "
    "ultricies erat.Curabitur a magna in ligula tristique ornare. Quisque commodo, massa viverra laoreet luctus, sem "
    "nisi aliquamvelit, fermentum pulvinar velit leo eget justo. Suspendisse vel erat efficitur, pulvinar eros "
    "volutpat, vulputateex. Phasellus non purus vel velit tristique tristique id at ligula. Quisque mollis sodales "
    "magna. Mauris et quameu quam viverra tempus. Nullam tempus maximus porta. Nunc mattis eleifend fermentum. Nullam "
    "aliquam liberoaccumsan velit elementum, eu laoreet metus convallis. Donec pellentesque lacus ut iaculis iaculis. "
    "Curabitur orcielit, bibendum sit amet feugiat at, iaculis sit amet massa. Maecenas imperdiet lacus at vehicula "
    "iaculis. Donecvolutpat nunc sit amet accumsan tempor. Quisque pretium vestibulum ultricies. Suspendisse potenti. "
    "Aenean at diamiaculis, condimentum felis venenatis, condimentum erat. Nam quis elit dui. Duis quis odio vitae "
    "metus hendreritrhoncus ut et magna. Cras ac augue quis nibh pharetra sagittis. Donec ullamcorper vel eros semper "
    "pretium. Proinvel sollicitudin eros. Nulla sollicitudin mattis turpis id suscipit. Aliquam sed risus velit. "
    "Aliquam iaculis necnibh ac egestas. Duis finibus semper est sed consequat. Sed in sapien quis nibh dignissim "
    "mattis. Vestibulum necmetus sodales, euismod mauris ac, sollicitudin libero. Maecenas non arcu ac velit "
    "ullamcorper fringilla et quisnulla. Curabitur posuere leo eget ipsum tincidunt dignissim. Cras ultricies suscipit "
    "neque, quis suscipit tortorvenenatis non. Cras nisl mi, bibendum in vulputate quis, vestibulum ornare enim. Nunc "
    "hendrerit placerat dui,aliquam mollis sem convallis et. Integer vitae urna diam. Phasellus et imperdiet est. "
    "Maecenas auctor facilisisnibh non commodo. Suspendisse iaculis quam "sv;

int main()
{
    std::string dest;
    dest.resize((src.size() + 3) / 3 * 4);

    auto pre = std::chrono::steady_clock::now();

    for (std::size_t x{}; x < 100000; ++x)
        auto it = bizwen::rfc4648_encode(src.begin(), src.end(), dest.begin());

    auto now = std::chrono::steady_clock::now();

    std::cout << "bizwen::rfc4648_encode: " << std::chrono::duration_cast<std::chrono::milliseconds>((now - pre))
              << '\n'
              << dest << '\n';
}

/* simd base64 library:
https://github.com/WojciechMula/base64simd
*/