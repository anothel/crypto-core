# Roadmap

## Direction

`crypto-core` is a native-first cryptographic engine.

- `NativeProvider` is the default backend and proof target.
- `OpenSSLProvider` is optional: compatibility backend and differential oracle.
- 0.x stays experimental until release gates below are proven.

This file tracks direction and remaining work only. Detailed imported-analysis
history belongs in commits, not in the roadmap.

## Roadmap Rules

- Evidence first: security, CI, packaging, and release claims need a
  reproducible command, test, or linked remote run.
- Keep security docs and code vocabulary aligned.
- Prefer targeted hardening slices over broad rewrites.
- Every non-trivial hardening change needs a focused regression test.

## Release Gates

Before calling an alpha/reuse-ready release:

- `LICENSE` selected by the project owner.
- Windows, Linux, and macOS native CI have a green remote run.
- OpenSSL ON/OFF CI has a green remote run where OpenSSL is supported.
- `find_package(crypto_core CONFIG REQUIRED)` works from an install tree.
- security boundary docs state threat model, provider trust, zeroization, RNG
  failure behavior, and constant-time limitations.
- supported algorithms, parameters, unsupported modes, and provider differences
  are documented.
- public API failure modes are documented for misuse-sensitive operations.
- known-answer and negative tests cover each release-supported primitive.
- malformed parser/import/decrypt inputs reject deterministically.
- release artifacts include checksum policy, SBOM plan, and vulnerability
  reporting policy.

## What To Do Next

Work in this order unless a security issue preempts it:

1. P0: close security-boundary regression gaps.
   - add NativeProvider RNG failure injection where randomness is consumed
     inside RSA signing/encryption.
   - add RSA-PSS and RSA-OAEP malformed/misuse vectors.
   - audit secret debug/log/panic exposure and key material copies.
   - keep secret/tag comparison on the constant-time helper path.
   - exit when malformed inputs reject deterministically and RNG failures never
     silently fall back.

2. P0: harden imported key structure.
   - add SPKI/PKCS#8 malformed algorithm variants.
   - exit when structurally invalid keys reject before crypto operations.

3. P1: finish Ed25519 interoperability proof.
   - add OpenSSL differential tests if local/CI OpenSSL exposes Ed25519
     support.
   - otherwise document it as unavailable in the status docs.
   - exit when Ed25519 native sign/verify has either OpenSSL differential
     coverage or an explicit, tested reason it cannot.

4. P2: continue RSA and P-256 hardening.
   - choose one reviewed boundary at a time: RSA CRT recombination or P-256
     exceptional-case formulas.
   - exit only with targeted tests and updated constant-time notes.

5. P2: prepare release integrity.
   - choose concrete SBOM and signing commands once release artifacts exist.
   - add a release checklist only when a versioned release process exists.
   - exit when release artifacts can be verified by users.

## Current Focus

### 1. Regression Hardening

Status: active
Priority: P0
Size: M

Goal: convert security-risk notes into executable tests.

Next slices:

- known-answer vectors for every release-supported primitive.
- negative vectors for tamper, wrong key, wrong nonce, unsupported tag length,
  malformed DER, unsupported version/algorithm, and invalid length.
- malformed DER/signature fixtures for RSA and ECDSA.
- RSA-PSS and RSA-OAEP negative cases.
- RNG failure injection with stable `ErrorCode`.
- property-style round-trip and tamper checks where one compact test covers the
  behavior without a new framework.

Exit criteria:

- release-supported primitives have positive and negative vector coverage.
- malformed inputs reject deterministically.
- RNG failures do not silently fall back.
- new malformed cases are added with targeted tests.

### 2. Imported-Key Validation

Status: active
Priority: P0
Size: M

Goal: reject structurally invalid key material at import time.

Next slices:

- SPKI/PKCS#8 malformed algorithm variants.

Exit criteria:

- invalid key structure rejects before sign, verify, encrypt, or decrypt.
- parser errors remain deterministic and use stable `ErrorCode`.
- each new boundary has one focused regression test.

### 3. Ed25519 Finish

Status: active
Priority: P1
Size: S

Goal: finish the remaining Ed25519 proof points without expanding the API.

Next slices:

- OpenSSL differential path if local/CI OpenSSL supports Ed25519.
- document NativeProvider keygen as unsupported/deferred unless a release gate
  needs it.

Exit criteria:

- RFC 8032 vectors pass.
- NativeProvider signs and verifies deterministic Ed25519 signatures.
- invalid signatures return `VerifyResult::invalid()`.
- OpenSSL differential support is tested or explicitly documented unavailable.

### 4. API and Implementation Hardening

Status: queued
Priority: P1
Size: M

Goal: reduce misuse without expanding the API surface unnecessarily.

Next slices:

- keep dedicated key/nonce/salt/tag/AAD types where they already exist; add a
  new type only when raw bytes are causing real misuse risk.
- block secret material from debug/log/panic paths.
- keep constant-time comparison centralized.
- make error types precise where callers must branch, and intentionally vague
  where detail would leak security state.
- isolate deprecated or unsafe surfaces behind explicit names/docs.

Exit criteria:

- no release-supported secret/tag verification path uses ordinary byte compare.
- no secret-owning public type exposes accidental copy/debug output.
- API docs show both recommended use and common misuse rejection.

### 5. Release Integrity

Status: active
Priority: P2
Size: M

Goal: make build and distribution outputs verifiable.

Next slices:

- security changelog and migration notes for breaking security changes.
- choose concrete SBOM and signing commands once release artifacts exist.
- benchmark baseline only after release-supported APIs stabilize.

Exit criteria:

- users can verify release artifacts.
- dependency security updates run through CI.
- release checklist covers tests, SBOM, checksums/signing, and changelog.

## Later

Keep these out of active work until a current focus item needs them:

- full `docs/architecture.md`, `docs/api-contract.md`,
  `docs/testing-strategy.md`, `docs/release-process.md`, and
  `docs/migration-guide.md` split. Keep content in existing docs until a split
  removes real duplication.
- shared ASN.1 DER core.
- PEM parser/encoder.
- CSR parser.
- provider-backed `KeyStore` handles.
- PKCS#11 provider.
- self-test or restricted/validated mode.
- PQC provider.
- additional RSA sizes or native RSA key generation.
- P-384, compressed EC points, raw fixed-width ECDSA signature format, ECDH.

## Not Planned For 0.x/1.x Unless Required

- mutable global provider registry.
- runtime replacement of `default_provider()`.
- certificate chain validation.
- TLS protocol implementation.
- legacy algorithms such as DES, RC2, RC4, MD5, or SHA-1.
- formal constant-time certification.
