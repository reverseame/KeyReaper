# craper-v2
Repositorio temporal para craper

## Dependencias

* CMake
* MS Visual Studio Tools: [Offical page](https://visualstudio.microsoft.com/downloads/#tools-for-visual-studio-2022-family)
    * Install as individual component: [MSBuild support for LLVM](https://learn.microsoft.com/en-us/visualstudio/msbuild/walkthrough-using-msbuild?view=vs-2022#install-msbuild)
    * MSBuild Tools
    * Desktop development with C++
        * Windows 10 SDK 10.0.20348.0 (latest)
        * MSVC v143 (latest)
        * C++ CMake Tools for Windows
        * Testing tools core features - Build Tools
        * C++ AddressSantitizer

### Troubleshooting
* CMake, through Visual Studio, tries to use MSBuild amd64 in 32 bit architecture. Solved by deleting the whole amd64 folder (the one that appears in the error) [read here](https://developercommunity.visualstudio.com/t/Visual-Studio-2022-Build-Tools-on-32-bit/10560841?space=8&q=80-bit+floating)

```powershell
rm C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64
```

## Compilar
```powershell
cd build
cmake ..
cmake --build .
cd bin/Debug
.\test.exe
```