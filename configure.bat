@echo off

:: Create build directory if it doesn't exist
if not exist "build" (
    mkdir build
)

:: Navigate into the build directory
cd build

:: Run CMake to configure the project
cmake ..

:: Optionally build the project
cmake --build .

echo ---
echo [!] Output files in build/bin