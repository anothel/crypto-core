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

0.x development state:

- Foundation types are implemented: `ByteBuffer`, `SecureBuffer`, `Error`,
  `Result<T>`.
- Provider API is implemented: `ICryptoProvider`, `IHashContext`,
  `IMacContext`, `IRng`, `ICipherContext`, KDF provider methods, RNG provider
  methods, cipher provider methods, AEAD provider methods,
  `default_provider()`, and one-shot helpers.
- `NativeProvider` is the default backend.
- Native SHA256 and SHA512 are implemented with streaming support.
- Native HMAC-SHA256 and HMAC-SHA512 are implemented with streaming support.
- Native PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512, HKDF-SHA256, and
  HKDF-SHA512 are implemented.
- Native OS-backed RNG is implemented on Windows using `BCryptGenRandom`.
- Native AES-128/192/256 single-block encrypt/decrypt is implemented as an
  internal/test-only primitive.
- Native AES-128/192/256-CBC encrypt/decrypt is implemented with no-padding
  and PKCS#7 padding support.
- Native AES-128/192/256-GCM encrypt/decrypt is implemented with nonce, AAD,
  tag generation, and authentication failure handling.
- Key material base is implemented: `KeyAlgorithm`, `KeyUsage`, `Key`, and
  move-only `SecretKey` backed by `SecureBuffer` with raw import/export.
- Asymmetric API base is implemented: `AsymmetricKeyAlgorithm`,
  `SignatureAlgorithm`, `PublicKey`, move-only `PrivateKey`, `KeyPair`,
  provider sign/verify hooks, asymmetric encrypt/decrypt hooks, shared-secret
  derivation hook, and deterministic invalid-signature result modeling.
- RSA parameter API base is implemented: generic `RSA-PSS` and `RSA-OAEP`
  algorithm selectors plus explicit `RsaPssParams` and `RsaOaepParams` for
  message hash, MGF1 hash, salt length, and OAEP label ownership.
- `OpenSSLProvider` supports RSA-PSS sign/verify for DER RSA keys when
  OpenSSL is enabled. Invalid RSA-PSS signatures return
  `VerifyResult::invalid()`.
- Native internal RSA DER parsing boundary is implemented for PKCS#1 public
  keys, SubjectPublicKeyInfo public keys, PKCS#1 private keys, and PKCS#8
  private keys.
- Native internal unsigned `BigInt` core is implemented for RSA work: big-endian
  import/export, comparison, modular multiplication, and modular exponentiation.
- Native internal raw RSA public/private operations are implemented over parsed
  RSA material and `BigInt` modular exponentiation.
- Encoding base is implemented: Base64, Base64url, and PEM armor shell with
  strict malformed-input errors.
- Test vector helper support includes NIST-style key/value parsing, bracketed
  metadata labels, deterministic malformed hex errors, required-field helpers,
  and reusable vector builders for digest, MAC, KDF, CBC, and GCM tests.
- 0.x API stabilization review is complete: algorithm-name return types are
  consistent, provider default unsupported contracts are tested, and streaming
  contexts reject repeated finalization deterministically.
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

### 0.10 Key Material

- `KeyAlgorithm`
- `KeyUsage`
- `Key`
- move-only `SecretKey`
- raw symmetric key import/export through `SecureBuffer`
- exact AES key-size validation

### 0.11 Encoding Base

- Base64 encode/decode
- Base64url encode/decode
- PEM armor encode/decode shell
- strict malformed input errors

### 0.12 API Stabilization

- provider default unsupported contract tests
- algorithm-name return type consistency
- streaming repeated-finalization tests
- self-test and validated-mode deferred to Phase 2+ unless required

### 1.0 Asymmetric API Base

- `AsymmetricKeyAlgorithm`
- `PublicKey`
- move-only `PrivateKey`
- `KeyPair`
- `SignatureAlgorithm`
- provider sign/verify interfaces
- provider-neutral parameter structs for sign, verify, encrypt, decrypt, and
  shared-secret derivation
- invalid signatures represented as successful `VerifyResult::invalid()`, not
  as provider errors
- actual RSA, ECDSA, and Ed25519 implementations deferred to 1.1+

### 1.1 RSA API Parameters

- generic `SignatureAlgorithm::rsa_pss`
- generic `AsymmetricEncryptionAlgorithm::rsa_oaep`
- `RsaPssParams`
- `RsaOaepParams`
- explicit message hash and MGF1 hash selection
- explicit PSS salt length
- OAEP label copied into owned `ByteBuffer`
- RSA math, DER key parsing, and key generation deferred to later 1.1 slices

### 1.1 RSA OpenSSL Reference

- `OpenSSLProvider` supports `SignatureAlgorithm::rsa_pss`
- `OpenSSLProvider` supports legacy `SignatureAlgorithm::rsa_pss_sha256`
- DER RSA private keys are parsed inside the provider for signing
- DER RSA public keys are parsed inside the provider for verification
- invalid signatures and tampered messages return `VerifyResult::invalid()`
- Native RSA implementation is still deferred

### 1.1 Native RSA DER Boundary

- internal `RsaPublicKeyMaterial`
- internal `RsaPrivateKeyMaterial`
- parse PKCS#1 `RSAPublicKey`
- parse SubjectPublicKeyInfo RSA public keys
- parse PKCS#1 `RSAPrivateKey`
- parse PKCS#8 RSA private keys
- reject trailing data, malformed lengths, negative integers, and non-RSA
  algorithm identifiers
- Native RSA math/sign/verify is still deferred

### 1.1 Native BigInt Core

- internal unsigned `BigInt`
- big-endian byte import/export
- normalized zero handling
- unsigned comparison
- modular multiplication
- modular exponentiation
- zero modulus rejection
- optimized/constant-time big integer arithmetic and RSA-PSS are still deferred

### 1.1 Native RSA Primitive

- internal raw RSA public operation
- internal raw RSA private operation
- parsed RSA DER material flows into `BigInt::mod_exp`
- representatives greater than or equal to modulus are rejected
- outputs are left-padded to modulus width
- RSA-PSS encoding and provider wiring are still deferred

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
