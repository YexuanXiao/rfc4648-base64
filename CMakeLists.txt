cmake_minimum_required(VERSION 3.29)

project(base64)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(benchmark benchmark.cpp)
add_executable(examples examples.cpp)

enable_testing()
add_executable(test_rfc4648 tests/test_rfc4648.cpp)
target_include_directories(test_rfc4648 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_rfc4648 COMMAND test_rfc4648)
