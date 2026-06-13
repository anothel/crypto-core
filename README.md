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

Initial scaffold only. No cryptographic algorithm is implemented yet.

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

## Build

```sh
cmake -S . -B build
cmake --build build
```

OpenSSL support is optional and disabled by default:

```sh
cmake -S . -B build -DCRYPTO_CORE_ENABLE_OPENSSL=ON
```

## Test

```sh
ctest --test-dir build
```

## License

License not selected yet.
