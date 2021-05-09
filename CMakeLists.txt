cmake_minimum_required(VERSION 3.16)
project(ethAddressGenerator)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

include_directories(BEFORE SYSTEM ${CMAKE_SOURCE_DIR}/mbedtls/include)

add_subdirectory(mbedtls/library)

find_package(OpenMP REQUIRED)
list(APPEND CMAKE_C_FLAGS ${OpenMP_C_FLAGS})
list(APPEND CMAKE_CXX_FLAGS ${OpenMP_CXX_FLAGS})

add_executable(ethAddressGenerator main.cpp keccak-tiny-unrolled.c keccak-tiny.h)
target_link_options(ethAddressGenerator PRIVATE ${OpenMP_EXE_LINKER_FLAGS})
target_link_libraries(ethAddressGenerator ${GNUTLS_LIBRARIES} ${mbedtls_target})
