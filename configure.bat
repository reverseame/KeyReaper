@echo off

:: Create build directory if it doesn't exist
if not exist "build" (
    mkdir build
)

cd build

if not exist "build32" (
    mkdir build32
)

if not exist "build64" (
    mkdir build64
)

:: 32 bit build
echo [!] Creating 32 bit build
cd build32
:: Run CMake to configure the project
cmake -G "Visual Studio 17 2022" -A Win32 ../..
cmake --build .
cd ..

echo [!] Creating 64 bit build
cd build64
cmake -G "Visual Studio 17 2022" -A x64 ../..
cmake --build .
cd ../..

echo ---
echo [!] Output files in build/bin