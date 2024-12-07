param (
    [Int32]$build = 0,
    [String]$release = "Debug"
)

if ((${release} -ne "Release") -and (${release} -ne "Debug")) {
    Write-Host "[x] Build mode must be Release or Debug"
    Exit
}

# Create build directory if it doesn't exist
if (-not (Test-Path -Path "build")) {
    New-Item -ItemType Directory -Path "build"
}
Set-Location "build"

if ($build -eq 0 -or $build -eq 32) {
    # 32 bit build
    Write-Host "[!] Creating 32 bit build"
    if (-not (Test-Path -Path "build32")) {
        New-Item -ItemType Directory -Path "build32"
    }

    Set-Location "build32"
    Write-Host "Build type: $release"
    # Run CMake to configure the project
    cmake -DCMAKE_GENERATOR_PLATFORM=Win32 -DCMAKE_BUILD_TYPE=$release -G "Visual Studio 17 2022" -A Win32 ../..
    cmake --build . --config ${release}
    Set-Location ..
}

if ($build -eq 0 -or $build -eq 64) {
    Write-Host "[!] Creating 64 bit build"
    if (-not (Test-Path -Path "build64")) {
        New-Item -ItemType Directory -Path "build64"
    }
    Set-Location "build64"
    cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DCMAKE_BUILD_TYPE=$release -G "Visual Studio 17 2022" -A x64 ../..
    cmake --build . --config ${release}
    Set-Location ..
}

Set-Location ..

Write-Host "---"
Write-Host "[!] Output files in build/bin"