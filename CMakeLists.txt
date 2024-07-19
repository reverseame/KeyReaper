cmake_minimum_required(VERSION 3.10)
project(Craperv2)

set(MSVC True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCE_BASE_DIR "${CMAKE_SOURCE_DIR}/src")

# Output files to bin directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(EXECUTABLE_NAME "test")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/scanners.cc
    #${SOURCE_BASE_DIR}/key_scanner.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${SOURCE_BASE_DIR}/main.cc
)

add_executable(cifrar3 
    ${SOURCE_BASE_DIR}/cifrar3.cpp
)