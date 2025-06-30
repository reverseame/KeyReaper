# KeyReaper
Harvest cryptographic keys before ransomware takes hold

This tool is able to make a copy of the heap of a remote process and scan it looking for cryptographic keys. It is also able to manage the execution
of the remote process. It is meant to be paired with an AV or EDR system for early ransomware response.

At the moment it supports any `CryptoAPI` generated key (with some limitations over asymmetric keys), as well as AES keys.

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

> [!WARNING] 
> This program is architecture dependant. The compilation produces two different versions, one for 32 bit and another 64 bit where, for the most part, the pointer sizes change, but also some important constants of the scanners. Take this into account when analyzing a program, since you will need the corresponding application: for example, WannaCry, which is a 32 bit ransomware, needs to be analyzed with the x86 (32 bit) version of this program. On the other hand, a 64 bit ransomware needs to be analyzed with the 64 bit version of this program, otherwise it will fail.

## Dependencies
You will need [Microsoft Visual C++ Redistributables](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170) in order to run this program.

## Build Dependencies

* CMake (using 3.30.1)
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

## CLI
The program offers an interface for easily managing processes and extracting keys.
It is split into two main subcommands (so far) which allows us to scan for keys (`scan`) 
and managing processes' execution `proc`. You can invoke the program with the help
flag for further information.
```
PS C:\> .\KeyReaper_x86.exe --help
KeyReaper: cryptographic key recovery for live processes
Usage: C:\KeyReaper_x86.exe [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit

Subcommands:
  scan                        Scan for keys in the process
  proc                        For manipulating all threads of the target process
```

Subcommands have also a help menu with information.

```
PS C:\> .\KeyReaper_x86.exe scan --help
Scan for keys in the process
Usage: C:\KeyReaper_x86.exe scan [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -b,--before ENUM:Actions (kill, nothing, ntpause, pause, resume)
                              Action to perform before the scan over all the threads of the process
  -a,--after ENUM:Actions (kill, nothing, ntpause, pause, resume)
                              Action to perform after the scan over all the threads of the process
  -o,--output TEXT REQUIRED   Output file for the keys JSON. If not specified, no file is exported. If a file exists with the same name, it gets overwritten.
  -p,--pid UINT:NONNEGATIVE REQUIRED
                              PID of the target process
  --scanners ENUM:Scanners (crapi, roundkey) ... REQUIRED
                              Scanners to extract keys with. You can pick one or more.
```

An example execution:
```
PS C:\> .\KeyReaper_x86.exe scan -p 1717 -b ntpause -o "keys.json" --scanners crapi roundkey
```

## Funding support
Part of this research was supported by the Spanish National Cybersecurity Institute (INCIBE) under *Proyectos Estratégicos de Ciberseguridad -- CIBERSEGURIDAD EINA UNIZAR* and by the Recovery, Transformation and Resilience Plan funds, financed by the European Union (Next Generation).

![INCIBE_logos](misc/img/BandaINCIBEcolor.jpg)