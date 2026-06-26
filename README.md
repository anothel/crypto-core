# crypto-core

Native-first cryptographic engine written in modern C++.

`crypto-core` is not just an algorithm library. It is a provider-backed crypto
engine covering primitives, key material, public APIs, backend providers, and
encoding.

## Direction

- `NativeProvider` is the default backend and proof target.
- `OpenSSLProvider` is optional and used as compatibility backend and
  differential test oracle.
- Public convenience APIs use `default_provider()`.
- Core APIs accept explicit `ICryptoProvider&` injection.
- 0.x does not support runtime replacement of the default provider.
- APIs are exception-free through `Result<T>` and `ErrorCode`.
- Secret-owning types are move-only where ownership matters.

## Layers

1. Foundation
   - `ByteBuffer`
   - `SecureBuffer`
   - `Error`
   - `Result<T>`
2. Crypto primitives
   - Hash
   - Cipher
   - MAC
   - Signature
   - KDF
   - RNG
3. Key management
   - `SecretKey`
   - `PublicKey`
   - `PrivateKey`
   - `KeyPair`
   - `KeyStore`
4. Provider framework
   - `ICryptoProvider`
   - `NativeProvider`
   - `OpenSSLProvider`
   - future PKCS#11/PQC providers
5. Encoding
   - Base64/Base64url
   - PEM
   - future ASN.1 DER and CSR parsing

## Current Capability

Implemented native/default-provider surface:

- Foundation: `ByteBuffer`, `SecureBuffer`, `Error`, `Result<T>`,
  zeroization, constant-time equality/select helpers
- Hash: SHA-256, SHA-512, one-shot and streaming
- MAC: HMAC-SHA256, HMAC-SHA512, one-shot and streaming
- KDF: PBKDF2-HMAC-SHA256/SHA512, HKDF-SHA256/SHA512
- RNG: OS RNG on Windows, Linux, Apple platforms, and BSD family systems
- Cipher/AEAD: AES-128/192/256 block, AES-CBC, AES-GCM
- Keys: symmetric key material, RSA/ECDSA public/private key containers,
  move-only private keys, in-memory `KeyStore`
- RSA: DER key parsing, RSA-PSS sign/verify, RSA-OAEP encrypt/decrypt, CRT
  private operation, blinding, Montgomery private exponent path, fixed
  provider-level reference-vector tests
- ECDSA P-256: DER key/signature parsing, native verify, deterministic native
  signing, RFC6979, fixed-limb P-256 backend, base-point windowing
- Ed25519: raw public key/private seed import, deterministic native sign/verify
- Encoding: Base64, Base64url, PEM armor shell
- Optional OpenSSL provider for SHA/HMAC/KDF/AES/RSA/ECDSA reference and
  differential tests where enabled

The active plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Security Status

- 0.x is experimental and not production-certified.
- Constant-time helper primitives exist, but algorithm-level constant-time
  certification is not claimed.
- Current algorithm and hardening status is tracked in
  [docs/algorithm-status.md](docs/algorithm-status.md),
  [docs/security-model.md](docs/security-model.md),
  [docs/constant-time-notes.md](docs/constant-time-notes.md),
  [SECURITY.md](SECURITY.md), and
  [docs/ROADMAP.md](docs/ROADMAP.md).

## CI

GitHub Actions runs native Debug builds on Windows, Ubuntu, and macOS, plus
OpenSSL-enabled and Linux Clang sanitizer jobs.

## Build

Native-only build:

```powershell
cmake -S . -B build -DCRYPTO_CORE_ENABLE_OPENSSL=OFF
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

OpenSSL-enabled build with `vcpkg`:

```powershell
cmake -S . -B build-openssl `
  -DCRYPTO_CORE_ENABLE_OPENSSL=ON `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

cmake --build build-openssl --config Debug
ctest --test-dir build-openssl -C Debug --output-on-failure
```

If OpenSSL is installed outside `vcpkg`, set `OPENSSL_ROOT_DIR` or provide
`OPENSSL_INCLUDE_DIR` and `OPENSSL_CRYPTO_LIBRARY`.

Install-tree smoke check:

```powershell
cmake --install build --config Debug --prefix build-install
cmake -S tests/install_package_smoke -B build-install-smoke `
  -DCMAKE_PREFIX_PATH=$PWD\build-install
cmake --build build-install-smoke --config Debug
.\build-install-smoke\Debug\crypto_core_install_package_smoke.exe
```

For OpenSSL-enabled installs, pass the same `vcpkg` toolchain file or
`OPENSSL_ROOT_DIR` hint to the consumer configure step.

## Windows Shell Setup

If `cmake`, `ctest`, or `cl` are not found in PowerShell, install CMake and
launch a Visual Studio developer shell:

```powershell
$env:Path = "C:\Program Files\CMake\bin;$env:Path"
& "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64
```

For OpenSSL DLL lookup with `vcpkg`, include:

```powershell
$env:Path = "C:\vcpkg\installed\x64-windows\bin;$env:Path"
```

## Roadmap

Near-term queue:

1. CI evidence, install/export smoke, and OpenSSL ON/OFF coverage
2. Ed25519 OpenSSL differential checks and optional key generation
3. RSA and P-256 hardening, malformed vectors, and fuzz-style coverage
4. KeyStore provider-backed handles, ASN.1 DER, PEM, CSR, PKCS#11, and PQC

See [docs/ROADMAP.md](docs/ROADMAP.md) for quantified remaining work.

## License

License not selected yet.
