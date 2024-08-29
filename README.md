# craper-v2
Repositorio temporal para craper

## Important notice
This program is very architecture dependant. The compilation produces two slightly version for 32 and 64 bit where, for the most part, changes the pointer sizes, but also some important constants of the scanners. Take this into account when analyzing a program, since you will need the corresponding application: for example, WannaCry, which is a 32 bit ransomware, needs to be analyzed with the x86 (32 bit) version of this program. On the other hand, a 64 bit ransomware needs to be analyzed with the 64 bit version of this program, otherwise it will fail.

## Dependencies

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

## Compile
The output directory for all builds is `.\build`. Inside will be both `build32\bin\` and `build64\bin\` folders, when compiled.

### Either 64 o 32 bit
The user can choose either to generate only the 32 or 64 bit build.
```powershell
# only 64 bit build
.\configure.ps1 64
# or only the 32 bit build
.\configure.ps1 32
# or both
.\configure.ps1 0 
```

### Debug and release
The architecture is not optional when specifying the build mode. When not specified, `Debug` is assumed.

```powershell
# only 64 bit in debug mode
.\configure.ps1 64 Debug
# or both 32 and 64 in release mode
.\configure.ps1 0 Release
```

### Default
The default compilation settings assume that the user wants to compile for both 32 and 64 bit in Debug mode.
```powershell
# 32 and 64 in debug mode
.\configure.ps1
# 64 only in debug mode
.\configure.ps1 64
```
