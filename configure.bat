@echo off

set CMAKE_ARCH=Win32

:: Create build directory if it doesn't exist
if not exist "build" (
    mkdir build
)

:: Navigate into the build directory
cd build

:: Run CMake to configure the project
cmake -A %CMAKE_ARCH% "-DCMAKE_TOOLCHAIN_FILE=C:/Users/Leon/Documents/vcpkg/scripts/buildsystems/vcpkg.cmake" ..

:: Optionally build the project
cmake --build .

echo ---
echo [!] Output files in build/bin