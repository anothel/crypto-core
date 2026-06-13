# crypto-core

Production-oriented cryptographic engine written in modern C++.

`crypto-core` is not just an algorithm collection. The project is intended to
own:

- cryptographic primitives
- key management
- cryptographic APIs
- provider framework
- encoding formats

The default backend target is `NativeProvider`: cryptographic primitives are
implemented in this project and exposed through a provider-backed API.
`OpenSSLProvider` is an optional reference backend used for compatibility and
differential testing.

## Layers

1. Foundation
   - `ByteBuffer`
   - `SecureBuffer`
   - `Error`
   - `Result<T>`
2. Crypto Primitive
   - Hash
   - Cipher
   - MAC
   - Signature
   - KDF
   - RNG
3. Key Management
   - Key
   - PublicKey
   - PrivateKey
   - KeyStore
   - KeyPair
4. Provider
   - `ICryptoProvider`
   - NativeProvider
   - OpenSSLProvider
   - PKCS11Provider
   - PQCProvider
5. Encoding
   - ASN.1
   - DER
   - PEM
   - Base64

## Phase KPI

### Phase 1

- SHA256
- SHA512
- HMAC
- AES-CBC
- AES-GCM
- PBKDF2
- HKDF

Phase 1 default implementation target:

- `NativeProvider` is the default backend.
- `OpenSSLProvider` is opt-in and used as a reference backend.
- Native outputs must pass known-answer tests.
- When OpenSSL is enabled, Native outputs must match OpenSSL outputs for the
  same public API.

### Phase 2

- RSA
- ECDSA
- Ed25519

### Phase 3

- ASN.1 DER
- PEM
- CSR Parser

### Phase 4

- PKCS#11
- PQC

## Current State

0.4 development state:

- Foundation types are implemented: `ByteBuffer`, `SecureBuffer`, `Error`,
  `Result<T>`.
- Provider API is implemented: `ICryptoProvider`, `IHashContext`,
  `IMacContext`, `default_provider()`, and one-shot helpers.
- `NativeProvider` is the default backend.
- Native SHA256 and SHA512 are implemented with streaming support.
- Native HMAC-SHA256 and HMAC-SHA512 are implemented with streaming support.
- `OpenSSLProvider` is optional and disabled by default. It is intended for
  reference and differential testing.

## Near-Term Milestones

### 0.1 Foundation

- `Error` and exception-free `Result<T>`
- `ByteBuffer` as a thin owned public byte container
- move-only `SecureBuffer` for secret material
- secure zeroization helper
- constant-time equality helper

### 0.2 Provider API

- `ICryptoProvider`
- streaming hash context API
- fixed `default_provider()` returning the NativeProvider singleton
- one-shot hash convenience API using `default_provider()`

### 0.3 Hash Providers

- Native SHA256 and SHA512
- optional OpenSSL SHA256 and SHA512
- known-answer tests
- Native-vs-OpenSSL differential tests when OpenSSL is enabled

### 0.4 HMAC Providers

- `MacAlgorithm`
- streaming `IMacContext`
- one-shot HMAC convenience API
- Native HMAC-SHA256 and HMAC-SHA512
- optional OpenSSL HMAC-SHA256 and HMAC-SHA512
- RFC 4231 known-answer tests
- Native-vs-OpenSSL differential tests when OpenSSL is enabled

### 0.5 KDF Providers

- PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
- HKDF-SHA256 and HKDF-SHA512
- Native implementation using existing HMAC
- optional OpenSSL differential tests

### 0.6 RNG

- OS RNG API
- Windows `BCryptGenRandom` backend
- deterministic test seam for provider tests
- Native DRBG is not part of 0.6

### 0.7 AES Block

- Native AES-128/192/256 block encrypt/decrypt
- test vectors for raw block operations
- raw ECB block primitive kept internal/test-only

### 0.8 AES-CBC

- CBC encrypt/decrypt contexts
- explicit padding policy
- known-answer tests
- optional OpenSSL differential tests

### 0.9 AES-GCM

- AEAD API shape
- nonce, AAD, tag, ciphertext handling
- authentication failure behavior
- optional OpenSSL differential tests

## Build

```sh
cmake -S . -B build
cmake --build build
```

OpenSSL support is optional and disabled by default:

```sh
cmake -S . -B build -DCRYPTO_CORE_ENABLE_OPENSSL=ON
```

On Windows with Visual Studio generators, pass the build configuration to
CTest:

```powershell
cmake -S . -B build -DCRYPTO_CORE_ENABLE_OPENSSL=OFF
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

To verify `OpenSSLProvider`, install OpenSSL development headers and libraries.
With `vcpkg`:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install openssl:x64-windows
```

Then configure with the vcpkg toolchain:

```powershell
cmake -S . -B build-openssl `
  -DCRYPTO_CORE_ENABLE_OPENSSL=ON `
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

cmake --build build-openssl --config Debug
ctest --test-dir build-openssl -C Debug --output-on-failure
```

If OpenSSL is installed outside `vcpkg`, set `OPENSSL_ROOT_DIR` or provide
`OPENSSL_INCLUDE_DIR` and `OPENSSL_CRYPTO_LIBRARY` for CMake.

## Test

```sh
ctest --test-dir build
```

## License

License not selected yet.
