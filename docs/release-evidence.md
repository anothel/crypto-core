# Release Evidence

Evidence captured for the P0 CI/install gate.

## Remote CI

First recorded green GitHub Actions run:

- Workflow: CI
- Run: 24
- Commit: `5b8d2a2b9f759b67ab8c78f61b5c3de1c1534af2`
- Title: `docs: close P0 security and capability gates`
- Status: success
- Started: 2026-06-26T21:19:37Z
- Completed: 2026-06-26T21:29:24Z
- Run URL: https://github.com/anothel/crypto-core/actions/runs/28265900192

Recorded successful jobs:

| Job | Completed | URL |
|---|---:|---|
| native-windows-msvc | 2026-06-26T21:23:16Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418184 |
| native-ubuntu-gcc | 2026-06-26T21:21:01Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418199 |
| native-ubuntu-clang | 2026-06-26T21:21:17Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418194 |
| native-macos-clang | 2026-06-26T21:21:17Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418188 |
| openssl-windows-msvc | 2026-06-26T21:29:23Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418190 |
| openssl-ubuntu-gcc | 2026-06-26T21:21:26Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418197 |
| openssl-macos-clang | 2026-06-26T21:21:47Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418173 |
| sanitizers-ubuntu-clang | 2026-06-26T21:23:14Z | https://github.com/anothel/crypto-core/actions/runs/28265900192/job/83752418183 |

## Local Native Build

Environment:

- Host: Windows PowerShell from `D:\project\crypto-core`
- Dev shell: Visual Studio 2026 Developer Command Prompt v18.6.2, `-arch=amd64`
- Compiler: MSVC 19.51.36246.0
- CMake: 4.4.0
- Generator: Ninja

Command:

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake -G Ninja -S . -B build-p0-native-ninja -DCRYPTO_CORE_ENABLE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Debug && cmake --build build-p0-native-ninja --parallel && ctest --test-dir build-p0-native-ninja --output-on-failure
```

Result:

- Configure: success
- Build: success; Ninja printed transient `.ninja_lock` permission warnings
- Tests: 27/27 passed
- Total test time: 209.17 sec

## Local OpenSSL Build

Environment:

- Host: Windows PowerShell from `D:\project\crypto-core`
- Dev shell: Visual Studio 2026 Developer Command Prompt v18.6.2, `-arch=amd64`
- Compiler: MSVC 19.51.36246.0
- CMake: 4.4.0
- Generator: Ninja
- OpenSSL: vcpkg `x64-windows`, OpenSSL 3.6.3
- OpenSSL DLL path for tests: `C:\vcpkg\installed\x64-windows\bin`

Commands:

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake -G Ninja -S . -B build-p0-openssl-ninja -DCRYPTO_CORE_ENABLE_OPENSSL=ON -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Debug && cmake --build build-p0-openssl-ninja --parallel
```

```powershell
$env:Path = 'C:\vcpkg\installed\x64-windows\bin;' + $env:Path; ctest --test-dir build-p0-openssl-ninja --output-on-failure
```

Result:

- Configure: success
- Build: success; Ninja printed transient `.ninja_lock` permission warnings
- Tests: 28/28 passed
- Total test time: 214.69 sec

## Install-Tree Consumer Smoke

Environment:

- Built from `build-p0-native-ninja`
- Installed to `build-p0-install-native`
- Consumer configured from `tests/install_package_smoke`
- Consumer prefix path: `D:/project/crypto-core/build-p0-install-native`

Command:

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake --install build-p0-native-ninja --prefix build-p0-install-native && cmake -G Ninja -S tests/install_package_smoke -B build-p0-install-smoke-native-p0 -DCMAKE_PREFIX_PATH=D:/project/crypto-core/build-p0-install-native -DCMAKE_BUILD_TYPE=Debug && cmake --build build-p0-install-smoke-native-p0 --parallel && build-p0-install-smoke-native-p0\crypto_core_install_package_smoke.exe
```

Result:

- Install: success
- Consumer configure: success through `find_package(crypto_core CONFIG REQUIRED)`
- Consumer build: success
- Smoke executable: exit code 0
