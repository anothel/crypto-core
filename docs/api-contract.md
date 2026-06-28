# API Contract

This document records caller-visible behavior that must stay aligned with tests
and provider capability reports.

## Provider Capability Contract

Provider `supports` answers describe whether callers may expect an operation to
work for an algorithm. A false `supports` result means callers must not expect
the operation to succeed.

Rules:

- capability queries are advisory, not a substitute for checking `Result<T>`.
- operation-level queries must match provider behavior for sign, verify,
  encrypt, decrypt, derive, and keygen.
- unsupported algorithms return `unsupported_algorithm`.
- malformed input returns a stable coarse `ErrorCode`; public APIs should not
  expose parser internals as an oracle.
- provider differences belong in `docs/algorithm-status.md` and tests.

## Result Handling

Public APIs return `Result<T>` or `Result<void>`. Callers must check
`has_value()` before reading a value. Examples should show this explicitly.

Use `VerifyResult::invalid()` for bad signatures that parsed correctly. Do not
treat a failed `Result<VerifyResult>` as a normal invalid signature; it means the
operation itself failed.

## Raw And Encoded Key Material

Raw bytes and encoded bytes are different API boundaries.

- raw Ed25519 public key: 32-byte encoded point.
- raw Ed25519 private seed: 32-byte seed.
- SPKI DER: encoded public-key container.
- SEC1 DER: encoded EC private-key container.
- PKCS#1 DER: encoded RSA public or private key container.
- PKCS#8 DER: encoded private-key container.

Names and docs must state whether bytes are raw, DER, seed, public key, private
key, ciphertext, tag, nonce, or salt.

## Misuse-Sensitive Operations

- AES-GCM requires a unique nonce for each key. Wrong key, nonce, AAD,
  ciphertext, or tag returns authentication failure.
- RSA-OAEP decrypt failure is intentionally coarse.
- RSA-PSS, ECDSA, and Ed25519 verify distinguish malformed operation failure
  from parsed-but-invalid signatures.
- RNG failure must return an error and must not fall back to weak randomness.

