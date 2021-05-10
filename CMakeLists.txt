cmake_minimum_required(VERSION 3.16)
project(ethAddressGenerator)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -xHost" CACHE STRING "Flags used by the compiler during release builds." FORCE)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

add_subdirectory(secp256k1)

find_package(IPPCrypto REQUIRED MODULE)

if (NOT IPPCRYPTO_FOUND)
    message(FATAL_ERROR "No Intel IPP Cryptography library found on the system.")
endif()

find_package(OpenMP REQUIRED)
list(APPEND CMAKE_C_FLAGS ${OpenMP_C_FLAGS})
list(APPEND CMAKE_CXX_FLAGS ${OpenMP_CXX_FLAGS})

add_executable(ethAddressGenerator main.cpp keccak-tiny-unrolled.c keccak-tiny.h)
target_include_directories(ethAddressGenerator PRIVATE secp256k1 ${IPPCRYPTO_INCLUDE_DIRS})
target_link_options(ethAddressGenerator PRIVATE ${OpenMP_EXE_LINKER_FLAGS})
target_link_libraries(ethAddressGenerator secp256k1 ${IPPCRYPTO_LIBRARIES})
