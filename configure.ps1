param (
    [Int32]$build = 0
)

# Create build directory if it doesn't exist
if (-not (Test-Path -Path "build")) {
    New-Item -ItemType Directory -Path "build"
}
Set-Location "build"

if ($build -eq 0 -or $build -eq 32) {
    # 32 bit build
    if (-not (Test-Path -Path "build32")) {
        New-Item -ItemType Directory -Path "build32"
    }

    Write-Host "[!] Creating 32 bit build"
    Set-Location "build32"
    # Run CMake to configure the project
    cmake -G "Visual Studio 17 2022" -A Win32 ../..
    cmake --build .
    Set-Location ..
}

if ($build -eq 0 -or $build -eq 64) {
    Write-Host "[!] Creating 64 bit build"
    if (-not (Test-Path -Path "build64")) {
        New-Item -ItemType Directory -Path "build64"
    }
    Set-Location "build64"
    cmake -G "Visual Studio 17 2022" -A x64 ../..
    cmake --build .
    Set-Location ..
}

Set-Location ..

Write-Host "---"
Write-Host "[!] Output files in build/bin"