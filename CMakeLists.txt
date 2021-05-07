cmake_minimum_required(VERSION 3.16)
project(ethAddressGenerator)

set(CMAKE_CXX_STANDARD 20)

set(BLA_VENDOR Intel10_64lp_seq)
find_package(BLAS)

add_executable(ethAddressGenerator main.cpp)
target_link_libraries(ethAddressGenerator ${BLAS_LIBRARIES})
