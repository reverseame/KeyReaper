cmake_minimum_required(VERSION 3.10)

set(CMAKE_SYSTEM_NAME Windows)
project(Craperv2)

set(MSVC True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCE_BASE_DIR "${CMAKE_SOURCE_DIR}/src")

# Output files to bin directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(${CMAKE_GENERATOR_PLATFORM} STREQUAL "Win32")
    set(ARCHITECTURE_APPEND "x86")
else()
    set(ARCHITECTURE_APPEND "x64")
endif()

set(EXECUTABLE_NAME "craper")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/scanners.cc
    #${SOURCE_BASE_DIR}/key_scanner.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${SOURCE_BASE_DIR}/main.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME} ${ARCHITECTURE_APPEND}")

add_executable("ransy"
    ${SOURCE_BASE_DIR}/cifrar3.cpp
)
set_target_properties(ransy PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")
