cmake_minimum_required(VERSION 3.20)
project(TestTask LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found!")
endif()

add_library(common STATIC
    src/common/crypto_utils.cpp
    src/common/net_utils.cpp
    src/common/packet_flags.cpp
)

target_include_directories(common PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(common PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(common PRIVATE compile_flags)

add_subdirectory(src/stx-send)
add_subdirectory(src/stx-recv)

add_library(compile_flags INTERFACE)
target_compile_options(compile_flags INTERFACE -g -Wall -Wextra -Werror)
