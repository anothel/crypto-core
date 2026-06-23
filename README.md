# crypto-core

Production-oriented cryptographic engine written in modern C++.

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

Current focus:

1. RSA hardening and completion
   - RSA-2048 fixed-width BigInt design
   - fixed-width arithmetic and Montgomery core
   - fixed-width private exponent path
   - private-operation timing-risk boundary
2. ECDSA P-256 hardening
3. Ed25519
4. KeyStore provider-backed handles
5. ASN.1 DER, stricter PEM, CSR parsing
6. PKCS#11 and PQC provider work

See [docs/ROADMAP.md](docs/ROADMAP.md) for quantified remaining work.

## License

License not selected yet.
