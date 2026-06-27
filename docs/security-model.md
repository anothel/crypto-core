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
must use the raw Ed25519 import APIs. Compatibility `import_der(...)` validates
public keys as SPKI DER and private keys as PKCS#8 DER. `import_der(ed25519,
...)` rejects until real Ed25519 DER parsing exists.

`PublicKey::bytes()` and `PrivateKey::bytes()` return the stored material.
Check `is_der_encoded()` before treating those bytes as DER. Use `export_der()`
only when DER output is required.

## Public API Failure Modes

Public APIs are exception-free and return `Result<T>`. Callers must check the
result before reading the value. `ErrorCode` values are stable enough for coarse
caller branching; error messages are diagnostic text, not a compatibility
contract.

| Surface | Public API | Expected failure behavior |
|---|---|---|
| Key import | `PublicKey::import_spki_der`, `PrivateKey::import_pkcs8_der`, `PrivateKey::import_sec1_der`, `import_rsa_pkcs1_der`, raw Ed25519 import APIs | Malformed DER, wrong containers, unsupported algorithms, invalid P-256 points, and invalid Ed25519 raw key sizes return `invalid_key` or `unsupported_algorithm`. Imported bytes remain distinct from exported DER; raw Ed25519 keys are not DER. |
| DER parsing | RSA SPKI/PKCS#1/PKCS#8, P-256 SPKI/SEC1/PKCS#8, ECDSA signatures | Non-minimal lengths/integers, trailing data, wrong OIDs, unsupported versions, negative integers, and invalid public points reject deterministically with `invalid_key`. |
| Decrypt | `aead_decrypt`, `asymmetric_decrypt` | Authentication/tag/ciphertext failures return `authentication_failed` for AEAD or RSA-OAEP. Unsupported algorithms return `unsupported_algorithm`; null or wrong-usage keys return `invalid_argument` or `invalid_key`. |
| Verify | `verify` | Bad signatures normally return a successful `VerifyResult::invalid()`. Unsupported algorithms or unusable keys return `Result<VerifyResult>` failure. |
| RNG | `random_bytes` | Zero-length requests succeed with empty output. Unsupported providers return `unsupported_algorithm`; OS RNG failure returns `provider_error`. There is no fallback PRNG. |
| KDF | `pbkdf2`, `hkdf` | Unsupported algorithm/API pair returns `unsupported_algorithm`. Zero iterations or zero output size return `invalid_argument`; HKDF output larger than 255 digest blocks returns `invalid_argument`. Provider backend failures return `provider_error`. |

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

## Nonce And Tag Boundary

AES-GCM nonces are caller-supplied. Callers must use a unique nonce for each
key; the API authenticates the supplied nonce but does not generate, store, or
track nonce reuse. AES-GCM decrypt accepts 12- to 16-byte tags, so protocols
that require a fixed tag length must enforce that length before calling decrypt.

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
