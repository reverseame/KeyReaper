cmake_minimum_required(VERSION 3.10)
project(Craperv2)

set(MSVC True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin) 

add_executable(test src/main.cc)