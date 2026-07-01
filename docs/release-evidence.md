# Release Evidence

This is Historical evidence for the exact run and commit named below. It is not
proof that current `main` is green after later commits. Each release candidate
must add fresh evidence or create a versioned evidence file.

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

## Current Local Evidence Refresh

Evidence captured for the active malformed-corpus hardening slice on
2026-06-29. This is local Windows/MSVC evidence only.

Environment:

- Host: Windows PowerShell from `D:\project\crypto-core`
- Dev shell: Visual Studio 2026 Developer Command Prompt v18.6.2, `-arch=amd64`
- Generator: Ninja
- Build tree: `build-p0-native-ninja`

Commands:

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake --build build-p0-native-ninja --target crypto_core_fuzz_boundary_smoke_tests && ctest --test-dir build-p0-native-ninja -R crypto_core.fuzz_boundary_smoke --output-on-failure
```

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake --build build-p0-native-ninja --target crypto_core_provider_api_tests && ctest --test-dir build-p0-native-ninja -R crypto_core.provider_api --output-on-failure
```

```powershell
ctest --test-dir build-p0-native-ninja --output-on-failure
```

Result:

- `crypto_core.fuzz_boundary_smoke`: passed
- `crypto_core.provider_api`: passed
- Full native CTest: 28/28 passed
- Total test time: 269.56 sec

## Current Remote CI Refresh

Evidence captured for current `main` after the malformed-corpus hardening
slice.

- Workflow: CI
- Run: 28367629034
- Commit: `30ae38ec1506a0281a9314976a8362c5982df537`
- Title: `test: grow rsa oaep invalid corpus`
- Status: success
- Started: 2026-06-29T11:08:01Z
- Completed: 2026-06-29T11:22:09Z
- Run URL: https://github.com/anothel/crypto-core/actions/runs/28367629034

Recorded successful jobs:

| Job | Completed | URL |
|---|---:|---|
| native-windows-msvc | 2026-06-29T11:11:56Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324144 |
| native-ubuntu-gcc | 2026-06-29T11:09:35Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324148 |
| native-ubuntu-clang | 2026-06-29T11:10:50Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324273 |
| native-macos-clang | 2026-06-29T11:09:59Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324205 |
| openssl-windows-msvc | 2026-06-29T11:22:08Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324162 |
| openssl-ubuntu-gcc | 2026-06-29T11:09:53Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324141 |
| openssl-macos-clang | 2026-06-29T11:10:24Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324243 |
| sanitizers-ubuntu-clang | 2026-06-29T11:12:04Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324202 |
| static-analysis-ubuntu-clang | 2026-06-29T11:10:04Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324152 |
| coverage-ubuntu-clang | 2026-06-29T11:09:35Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324156 |
| fuzzing-ubuntu-clang | 2026-06-29T11:09:12Z | https://github.com/anothel/crypto-core/actions/runs/28367629034/job/84037324167 |

## Current Local Install-Tree Smoke Refresh

Evidence captured for the install-tree CI gate update on 2026-07-01. This is
local Windows/MSVC evidence only; the new `install-smoke-ubuntu-gcc` workflow
job needs fresh remote evidence after this change reaches GitHub Actions.

Environment:

- Host: Windows PowerShell from `D:\project\crypto-core`
- Dev shell: Visual Studio 2026 Developer Command Prompt v18.6.2, `-arch=amd64`
- Compiler: MSVC 19.51.36246.0
- Generator: Ninja
- Producer build tree: `build-p0-native-ninja`
- Install prefix: `build-codex-install-native`
- Consumer build tree: `build-codex-install-smoke-native`

Command:

```cmd
C:\PROGRA~1\MICROS~4\18\Community\Common7\Tools\VsDevCmd.bat -arch=amd64 && cmake --install build-p0-native-ninja --prefix build-codex-install-native && cmake -G Ninja -S tests/install_package_smoke -B build-codex-install-smoke-native -DCMAKE_PREFIX_PATH=D:/project/crypto-core/build-codex-install-native -DCMAKE_BUILD_TYPE=Debug && cmake --build build-codex-install-smoke-native --parallel && build-codex-install-smoke-native\crypto_core_install_package_smoke.exe
```

Result:

- Install: success
- Consumer configure: success through `find_package(crypto_core CONFIG REQUIRED)`
- Consumer build: success
- Smoke executable: exit code 0

## Current Local Source Archive Checksum Preflight

Evidence captured for the release artifact integrity command path on
2026-07-01. This is a local preflight for the committed `HEAD` only, not final
release-candidate evidence. It excludes uncommitted working-tree changes.

Environment:

- Host: Windows PowerShell from `D:\project\crypto-core`
- Commit: `ac12b50ae4897467a0ea3d739305fa99ebbbfad4`
- Archive: `build-release-preflight/crypto-core-v0.1.0-alpha.1-preflight.tar`

Commands:

```powershell
New-Item -ItemType Directory -Force build-release-preflight
git archive --format=tar --prefix=crypto-core-v0.1.0-alpha.1-preflight/ -o build-release-preflight/crypto-core-v0.1.0-alpha.1-preflight.tar HEAD
Get-FileHash -Algorithm SHA256 build-release-preflight\crypto-core-v0.1.0-alpha.1-preflight.tar
```

Result:

- Archive generation: success
- SHA-256:
  `9BA54F6660A483985E46B99523D21E77996A923716E22BD9A13594B2EDF1CF33`
