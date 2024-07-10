cmake_minimum_required(VERSION 3.10)
project(Craperv2)

set(MSVC True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCE_BASE_DIR "${CMAKE_SOURCE_DIR}/src")

# Output files to bin directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(test
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${SOURCE_BASE_DIR}/main.cc
)