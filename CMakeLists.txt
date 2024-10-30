cmake_minimum_required(VERSION 3.10)

set(CMAKE_SYSTEM_NAME Windows)
project(Craperv2)

set(MSVC True)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCE_BASE_DIR "${CMAKE_SOURCE_DIR}/src")

# Output files to bin directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(${CMAKE_GENERATOR_PLATFORM} STREQUAL "Win32")
    set(ARCHITECTURE_APPEND "x86")
else()
    set(ARCHITECTURE_APPEND "x64")
endif()

# 3rd parties
include(FetchContent)

# Interrogate
FetchContent_Declare(
    interrogate
    URL https://sourceforge.net/projects/interrogate/files/interrogate/0.0.4/interrogate-0.0.4-source.tar.gz/download
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(interrogate)

# JSON library
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

set(EXECUTABLE_NAME "craper")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/scanners.cc
    #${SOURCE_BASE_DIR}/key_scanner.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${SOURCE_BASE_DIR}/main.cc
)

# Link nlohmann/json to your executable
target_link_libraries(${EXECUTABLE_NAME} PRIVATE nlohmann_json)
# Executable output
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "ransy")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/custom-ransomware/basic-ransomware.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")


# --- Cryptography: Next Generation Dummy Ransomware -----
set(EXECUTABLE_NAME "next_gen_ransy")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/custom-ransomware/basic-CNG-ransomware.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")


# --- Injected DLL -----------------
set(LIBRARY_NAME "evil")
add_library(${LIBRARY_NAME} SHARED
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/cryptoapi_key_exporter.cc
)

set_target_properties(${LIBRARY_NAME} PROPERTIES OUTPUT_NAME "${LIBRARY_NAME}_${ARCHITECTURE_APPEND}")

# --- Test Injector ----------------
set(EXECUTABLE_NAME "injector")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/injector.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "test_client")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/test/test_client.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "test_server")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/test/test_server.cc
)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")