# Crypto Policy

This document is the policy layer for current `crypto-core` behavior. It does
not add a runtime policy engine; public APIs and provider capability checks are
the current enforcement points.

## Policy Version

- Policy version: `2026.06`
- Status: experimental 0.x policy
- Default provider: `NativeProvider`
- Optional compatibility provider: `OpenSSLProvider`

## Allowed Algorithms

New code may use only release-supported algorithms listed here:

- SHA-256 and SHA-512
- HMAC-SHA256 and HMAC-SHA512
- PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
- HKDF-SHA256 and HKDF-SHA512
- AES-128/192/256-CBC for compatibility use
- AES-128/192/256-GCM
- RSA-PSS with SHA-256 or explicit `RsaPssParams`
- RSA-OAEP with SHA-256 or explicit `RsaOaepParams`
- ECDSA-P256-SHA256
- Ed25519 pure mode
- OS CSPRNG through `random_bytes`

## Forbidden Algorithms

These must not be added for new data or new signatures:

- MD5
- SHA-1 for signatures
- DES, 3DES, RC2, and RC4
- AES-ECB
- RSA-PKCS1-v1_5 encryption for new data
- unauthenticated encryption for new data
- `rand`, `srand`, `Math.random`, or predictable PRNGs for key, nonce, IV, or
  salt material

## Nonce, IV, And Salt

- AES-GCM requires a unique nonce for each key.
- Nonce/IV values for AES-GCM are caller-supplied today.
- Callers must bind nonce uniqueness to the key scope.
- The API authenticates supplied nonces but does not track reuse.
- Salt values are KDF inputs, not encryption nonces.

## Error And Logging Policy

- Public APIs return `Result<T>` and stable `ErrorCode` values.
- Error messages are diagnostic text, not a compatibility contract.
- Authentication failures should remain coarse externally.
- Logs and errors must not expose plaintext, keys, tokens, passwords, seeds,
  private keys, or full ciphertexts.
- Secret/tag comparisons must stay on existing constant-time helper paths.

## FIPS And PQC

0.x does not claim FIPS validation or PQC support. Future FIPS or PQC work
must be added as separate provider/profile work, not by silently changing the
default provider behavior.
