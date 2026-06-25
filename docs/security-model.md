# Security Model

## Status

`crypto-core` 0.x is experimental and not production-certified. It has not had
an external security audit, FIPS validation, or formal side-channel review.

## Protected Assets

- private keys and symmetric keys
- key-derived material
- plaintext handled by cipher and AEAD APIs
- RNG output
- password input to KDF APIs

Public keys, signatures, ciphertexts, nonces, salts, and algorithm identifiers
are public inputs unless an API says otherwise.

## Provider Boundary

`NativeProvider` is the default backend and proof target.

`OpenSSLProvider` is optional. It is a compatibility backend and differential
test oracle when `CRYPTO_CORE_ENABLE_OPENSSL=ON`. Enabling it adds trust in the
linked OpenSSL build and its local configuration.

0.x does not support runtime replacement of `default_provider()`. APIs that need
a different backend should pass an explicit `ICryptoProvider&`.

## Key Material Boundary

Raw key material and DER/SPKI/PKCS#8 containers are distinct. Raw Ed25519 keys
must use the raw Ed25519 import APIs. `import_der(ed25519, ...)` rejects until
real Ed25519 DER parsing exists.

`PublicKey::bytes()` and `PrivateKey::bytes()` return the stored material.
Check `is_der_encoded()` before treating those bytes as DER. Use `export_der()`
only when DER output is required.

## Memory Boundary

`SecureBuffer` zeroes owned bytes on destruction. `PrivateKey` is move-only so
private material is not accidentally copied through the public key API.

This does not promise that all compiler temporaries, OS paging, crash dumps,
allocator copies, or caller-owned buffers are erased.

## RNG Boundary

Native OS RNG uses:

- Windows: `BCryptGenRandom`
- Linux: `getrandom`
- Apple platforms: `SecRandomCopyBytes`
- BSD family systems: `arc4random_buf`

RNG failure is returned as `Result<T>` failure. There is no silent fallback to a
weaker PRNG.

## Non-Goals For 0.x

- production certification
- formal constant-time certification
- certificate chain validation
- TLS protocol implementation
- mutable global provider registry
- Ed25519ctx or Ed25519ph
- native P-384
- legacy algorithms such as DES, RC2, RC4, MD5, or SHA-1

Current algorithm status is tracked in `docs/algorithm-status.md`.
