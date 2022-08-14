# This spdm-emu is a sample SPDM emulator implementation using [libspdm](https://github.com/DMTF/libspdm)

## Feature

1) An SPDM requester emulator and a SPDM responder emulator that can run in OS environment.

## Document

1) User guide

   The user guide can be found at [user_guide](https://github.com/DMTF/spdm-emu/blob/main/doc/spdm_emu.md)

## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (VS2015 or VS2019 or VS2022)

2) [GCC](https://gcc.gnu.org/) (above GCC5)

3) [LLVM](https://llvm.org/) (LLVM9)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

## Build

### Git Submodule

   spdm_emu uses submodules for libspdm.

   To get a full buildable repo, please use `git submodule update --init --recursive`.
   If there is an update for submodules, please use `git submodule update`.

### Windows Build with CMake

   Use x86 command prompt for ARCH=ia32 and x64 command prompt for ARCH=x64. (TOOLCHAIN=VS2022|VS2019|VS2015|CLANG)
   ```
   cd spdm_emu
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

### Linux Build with CMake

   (TOOLCHAIN=GCC|CLANG)
   ```
   cd spdm_emu
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

## Run Test

### Run spdm_emu

   The spdm_emu output is at spdm_emu/build/bin.
   Open one command prompt at output dir to run `spdm_responder_emu` and another command prompt to run `spdm_requester_emu`.

   Please refer to [spdm_emu](https://github.com/DMTF/spdm-emu/blob/main/doc/spdm_emu.md) for detail.

## Feature not implemented yet

1) Please refer to [issues](https://github.com/DMTF/spdm-emu/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

