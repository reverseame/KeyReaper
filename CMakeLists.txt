cmake_minimum_required(VERSION 3.10)

set(CMAKE_SYSTEM_NAME Windows)
project(Craperv2 VERSION 1.0.1)
set(PROGRAM_NAME "CRAPER")

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

# Optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif()


## Ease for includes
add_library(common_includes INTERFACE)
target_include_directories(common_includes INTERFACE ${PROJECT_SOURCE_DIR}/include/craper)
target_include_directories(interrogate_include INTERFACE ${PROJECT_SOURCE_DIR}/include/interrogate)

# 3rd parties
include(FetchContent)

# Interrogate
FetchContent_Declare(
    interrogate
    URL https://sourceforge.net/projects/interrogate/files/interrogate/0.0.4/interrogate-0.0.4-source.tar.gz/download
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(interrogate)
set(FILE_PATH "${interrogate_SOURCE_DIR}/aes.c")
file(READ ${FILE_PATH} FILE_CONTENT)
string(REPLACE "interrogate.h" "aes.h" FILE_CONTENT "${FILE_CONTENT}")
file(WRITE ${FILE_PATH} "${FILE_CONTENT}")

# JSON library
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

FetchContent_Declare(
  cli11_proj
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.4.2
)
FetchContent_MakeAvailable(cli11_proj)

# TitanEngine
set(TITAN_ENGINE_DIR "${CMAKE_SOURCE_DIR}/TitanEngine")
set(TITAN_ENGINE_DLL "${TITAN_ENGINE_DIR}/TitanEngine_${ARCHITECTURE_APPEND}.dll")
set(TITAN_ENGINE_LIB "${TITAN_ENGINE_DIR}/TitanEngine_${ARCHITECTURE_APPEND}.lib")
include_directories(${TITAN_ENGINE_DIR})

### Binaries #############

set(EXECUTABLE_NAME "craper")

# Set version number
configure_file(
    ${SOURCE_BASE_DIR}/main.cc
    ${CMAKE_CURRENT_BINARY_DIR}/main.cc
    @ONLY
)

add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/key.cc
    ${interrogate_SOURCE_DIR}/aes.c
    ${SOURCE_BASE_DIR}/scanners.cc
    ${SOURCE_BASE_DIR}/key_scanner.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${CMAKE_CURRENT_BINARY_DIR}/main.cc
)

# Link nlohmann/json to your executable
target_link_libraries(${EXECUTABLE_NAME} PRIVATE nlohmann_json CLI11::CLI11 common_includes interrogate_include ${TITAN_ENGINE_LIB})
# Executable output
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")
# TitanEngine DLL dependency
add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${TITAN_ENGINE_DLL}
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/TitanEngine.dll
)

set(EXECUTABLE_NAME "ransy")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/custom-ransomware/basic-ransomware.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE common_includes )
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "ransy_decryptor")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/decryptors/PoCDcryptor/poc-decryptor.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE nlohmann_json CLI11::CLI11 common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

# --- Cryptography: Next Generation Dummy Ransomware -----
set(EXECUTABLE_NAME "next_gen_ransy")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/custom-ransomware/basic-CNG-ransomware.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")


# --- Injected DLL -----------------
set(LIBRARY_NAME "evil")
add_library(${LIBRARY_NAME} SHARED
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/cryptoapi_key_exporter.cc
)
target_link_libraries(${LIBRARY_NAME} PRIVATE common_includes)
set_target_properties(${LIBRARY_NAME} PROPERTIES OUTPUT_NAME "${LIBRARY_NAME}_${ARCHITECTURE_APPEND}")

# --- Test Injector ----------------
set(EXECUTABLE_NAME "injector")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/injector.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "test_client")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/test/test_client.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")

set(EXECUTABLE_NAME "test_server")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/interproc_coms.cc
    ${SOURCE_BASE_DIR}/injection/test/test_server.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")
