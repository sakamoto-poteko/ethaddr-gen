cmake_minimum_required(VERSION 3.16)
project(ethAddressGenerator)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 11)

find_package(OpenMP REQUIRED)

list(APPEND CMAKE_C_FLAGS ${OpenMP_C_FLAGS})
list(APPEND CMAKE_CXX_FLAGS ${OpenMP_CXX_FLAGS})

# find_package(GnuTLS REQUIRED)
find_package(MbedTLS REQUIRED)

# set(BLA_VENDOR Intel10_64lp_seq)
# find_package(BLAS REQUIRED)

# find_package(IPPCrypto REQUIRED MODULE)

# if (NOT IPPCRYPTO_FOUND)
#    message(FATAL_ERROR "No Intel IPP Cryptography library found on the system.")
# endif()

# If Intel IPP Cryptography is found, the following variables will be defined:
#     `IPPCRYPTO_LIBRARIES` - static library name
#     `IPPCRYPTO_INCLUDE_DIRS` - path to Intel IPP Cryptography headers
#     `IPPCRYPTO_ROOT_DIR` - library root dir (a folder with 'include' and 'lib' directories)

add_compile_options(-mrdrnd)

add_executable(ethAddressGenerator main.cpp keccak-tiny-unrolled.c keccak-tiny.h)
target_include_directories(ethAddressGenerator SYSTEM PRIVATE ${GNUTLS_INCLUDE_DIR})
target_link_options(ethAddressGenerator PRIVATE ${OpenMP_EXE_LINKER_FLAGS})
target_link_libraries(ethAddressGenerator ${GNUTLS_LIBRARIES} ${MBEDTLS_LIBRARIES})
