# crypto-core

Production-oriented cryptographic engine written in modern C++.

`crypto-core` is not just an algorithm collection. The project is intended to
own:

- cryptographic primitives
- key management
- cryptographic APIs
- provider framework
- encoding formats

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

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Test

```sh
ctest --test-dir build
```

## License

License not selected yet.
