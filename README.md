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

### Optional: TPM Support

TPM-backed SPDM flows require additional dependencies.

**Required packages**
- swtpm (for software TPM emulation)
- tpm2-tools
- OpenSSL with TPM provider support

## Build

### Git Submodule

   spdm_emu uses submodules for libspdm.

   To get a full buildable repo, please use `git submodule update --init --recursive`.
   If there is an update for submodules, please use `git submodule update`.

### Windows Build with CMake

   Use x86 command prompt for ARCH=ia32 and x64 command prompt for ARCH=x64. (TOOLCHAIN=VS2022|VS2019|VS2015|CLANG)
   ```
   cd spdm-emu
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

### Linux Build with CMake

   (TOOLCHAIN=GCC|CLANG)
   ```
   cd spdm-emu
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

### Optional: Use System libspdm

By default, spdm-emu builds libspdm from the submodule. To use a system-installed libspdm instead:

```
  -DUSE_SYSTEM_LIBSPDM=ON
```

This requires libspdm to be installed and available via pkg-config.

### Optional: Enable TPM Support

To build spdm-emu with TPM-backed device secret support:

```
  -DDEVICE=tpm
  -DLIBSPDM_TPM_SUPPORT=ON
```

### Optional: Build SPDM Validator Samples

The SPDM-Responder-Validator submodule provides conformance testing tools (`spdm_device_validator_sample` and `spdm_device_attester_sample`). These are **enabled by default** and require the SPDM-Responder-Validator submodule to be initialized.

**To build with validator samples (default):**
```bash
# Ensure the SPDM-Responder-Validator submodule is initialized
git submodule update --init SPDM-Responder-Validator

cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
make
# Builds: spdm_requester_emu, spdm_responder_emu, spdm_device_validator_sample, spdm_device_attester_sample
```

**To build without validator samples:**
```bash
# No need to initialize the SPDM-Responder-Validator submodule
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl -DBUILD_VALIDATOR_SAMPLES=OFF ..
make
# Builds: spdm_requester_emu, spdm_responder_emu
```

**Note:** The validator samples are primarily used for SPDM responder conformance testing and are not required for basic SPDM emulator functionality. Disable them with `-DBUILD_VALIDATOR_SAMPLES=OFF` (e.g. in submodule-free build environments like Yocto).

### TPM Setup (Optional)

A helper script is provided to initialize a software TPM:

```
cd build/bin
../../scripts/setup-tpm.sh --cleanup --start-swtpm
```

Please refer to [spdm_emu](https://github.com/DMTF/spdm-emu/blob/main/doc/tpm.md) for detail.

## Run Test

### Run spdm_emu

   The spdm_emu output is at spdm-emu/build/bin.
   Open one command prompt at output dir to run `spdm_responder_emu` and another command prompt to run `spdm_requester_emu`.

   Please refer to [spdm_emu](https://github.com/DMTF/spdm-emu/blob/main/doc/spdm_emu.md) for detail.

## Systemd Service (Linux)

On Linux systems with systemd, spdm_responder_emu can be installed as a system service. By default, it's disabled.

### Build with systemd support
```bash
cmake -DENABLE_SYSTEMD=ON ...
make
sudo make install
```

### Service configuration

The service file is installed to the systemd system unit directory (typically `/lib/systemd/system/`).

Runtime arguments can be configured via environment file:
```bash
# /etc/default/spdm-responder-emu
SPDM_RESPONDER_EMU_ARGS="--trans TCP"
```

### Service management
```bash
# Start the service
sudo systemctl start spdm-responder-emu

# Enable at boot
sudo systemctl enable spdm-responder-emu

# Check status
sudo systemctl status spdm-responder-emu

# View logs
sudo journalctl -u spdm-responder-emu
```

**Note:** The service expects certificates in `/usr/share/spdm-emu/`. Ensure sample keys are installed before starting the service.

## Feature not implemented yet

1) Please refer to [issues](https://github.com/DMTF/spdm-emu/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.
