cmake_minimum_required(VERSION 3.15)

set(CMAKE_SYSTEM_NAME Windows)
project(KeyReaper VERSION 1.6.0)
set(PROGRAM_NAME "KeyReaper")

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
add_library(interrogate_include INTERFACE)
target_include_directories(common_includes INTERFACE ${PROJECT_SOURCE_DIR}/include/ntdll)
target_include_directories(common_includes INTERFACE ${PROJECT_SOURCE_DIR}/include/keyreaper)
target_include_directories(interrogate_include INTERFACE ${PROJECT_SOURCE_DIR}/include/interrogate)

# 3rd parties
include(FetchContent)

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

FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

FetchContent_Declare(
    nng
    GIT_REPOSITORY https://github.com/nanomsg/nng.git
    GIT_TAG        v1.10.1
)
FetchContent_MakeAvailable(nng)
target_include_directories(common_includes INTERFACE ${nng_SOURCE_DIR}/include)

# TitanEngine
set(TITAN_ENGINE_DIR "${CMAKE_SOURCE_DIR}/TitanEngine")
set(TITAN_ENGINE_DLL "${TITAN_ENGINE_DIR}/TitanEngine_${ARCHITECTURE_APPEND}.dll")
set(TITAN_ENGINE_LIB "${TITAN_ENGINE_DIR}/TitanEngine_${ARCHITECTURE_APPEND}.lib")
include_directories(${TITAN_ENGINE_DIR})

### Binaries #############

set(EXECUTABLE_NAME "KeyReaper")

# Set version number
configure_file(
    ${SOURCE_BASE_DIR}/main.cc
    ${CMAKE_CURRENT_BINARY_DIR}/main.cc
    @ONLY
)

add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/config.cc
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/key.cc
    ${SOURCE_BASE_DIR}/interrogate/aes.cc
    ${SOURCE_BASE_DIR}/scanners.cc
    ${SOURCE_BASE_DIR}/key_scanner.cc
    ${SOURCE_BASE_DIR}/injection/custom_ipc.cc
    ${SOURCE_BASE_DIR}/injection/injector.cc
    ${SOURCE_BASE_DIR}/process_capturer.cc
    ${CMAKE_CURRENT_BINARY_DIR}/main.cc
)

# Link nlohmann/json to your executable
target_link_libraries(${EXECUTABLE_NAME} PRIVATE nng nlohmann_json CLI11::CLI11 tomlplusplus::tomlplusplus interrogate_include common_includes ${TITAN_ENGINE_LIB})
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
    ${SOURCE_BASE_DIR}/cryptoapi.cc
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
set(LIBRARY_NAME "injectable_server")
add_library(${LIBRARY_NAME} SHARED
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/cryptoapi.cc
    ${SOURCE_BASE_DIR}/injection/custom_ipc.cc
    ${SOURCE_BASE_DIR}/injection/cryptoapi_key_exporter.cc
)
target_link_libraries(${LIBRARY_NAME} PRIVATE nng common_includes)
set_target_properties(${LIBRARY_NAME} PROPERTIES OUTPUT_NAME "${LIBRARY_NAME}_${ARCHITECTURE_APPEND}")

# --- Test Injector ----------------
set(EXECUTABLE_NAME "injector")
add_executable(${EXECUTABLE_NAME}
    ${SOURCE_BASE_DIR}/program_result.cc
    ${SOURCE_BASE_DIR}/injection/custom_ipc.cc
    ${SOURCE_BASE_DIR}/injection/injector_program.cc
)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE nng common_includes)
set_target_properties(${EXECUTABLE_NAME} PROPERTIES OUTPUT_NAME "${EXECUTABLE_NAME}_${ARCHITECTURE_APPEND}")
