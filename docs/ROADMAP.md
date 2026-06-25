# Roadmap

## Direction

`crypto-core` is a native-first cryptographic engine.

- `NativeProvider` is the default backend and proof target.
- `OpenSSLProvider` is optional: compatibility backend and differential oracle.
- 0.x stays experimental until release gates below are proven.

This file tracks direction and remaining work only. Detailed imported-analysis
history belongs in commits, not in the roadmap.

## Release Gates

Before calling an alpha/reuse-ready release:

- `LICENSE` selected by the project owner.
- `SECURITY.md` has a real reporting policy and supported-version scope.
- Windows, Linux, and macOS native CI have a green remote run.
- OpenSSL ON/OFF CI has a green remote run where OpenSSL is supported.
- `find_package(crypto_core CONFIG REQUIRED)` works from an install tree.
- `docs/algorithm-status.md` matches provider capability tests.
- raw key material APIs and DER/SPKI/PKCS#8 import APIs are not ambiguous.
- security boundary docs state threat model, provider trust, zeroization, RNG
  failure behavior, and constant-time limitations.

## Current Focus

### 1. Key Material Format Boundary

Status: active
Priority: P0
Size: M

Goal: stop raw key bytes and DER/ASN.1 containers from looking like the same
API.

Done baseline:

- raw Ed25519 public/private imports exist.
- `import_der(ed25519, ...)` rejects until real Ed25519 SPKI/PKCS#8 parsing
  exists.
- raw Ed25519 material does not export as DER.

Next slices:

- clarify `bytes()`/export semantics before 1.0.
- add DER-specific names where needed: `import_spki_der`,
  `import_pkcs8_der`, `import_rsa_pkcs1_der`.
- keep compatibility wrappers only until the 1.0 API decision.
- add strict malformed DER rejection tests for paths that claim DER parsing.

Exit criteria:

- raw and DER import paths are separately named and tested.
- DER-specific APIs perform real DER parsing.
- existing RSA, ECDSA, and Ed25519 tests stay green.

### 2. Security Boundary Documentation

Status: queued
Priority: P0
Size: S

Goal: make security claims explicit instead of implied.

Next slices:

- create `SECURITY.md` after owner confirms reporting channel.
- keep `docs/algorithm-status.md` aligned with provider capability tests.

Must cover:

- protected assets and non-goals for 0.x.
- secret/public data boundary.
- provider trust boundary.
- memory zeroization policy.
- RNG source and failure semantics.
- side-channel/constant-time limitations.
- conservative production-use wording.

Exit criteria:

- users can tell what is complete, experimental, verify-only, unsupported, or
  deferred.
- no production, audit, or constant-time certification is implied.

### 3. CI, Install, and Evidence

Status: active
Priority: P1
Size: M

Goal: prove the library builds, tests, and installs outside a local checkout.

Next slices:

- capture first green remote CI run for Windows/Linux/macOS native builds.
- capture first green remote CI run for OpenSSL ON/OFF matrix.
- run an install-tree consumer smoke test and record command/environment.
- link release checklist or README badge to green CI evidence.

Exit criteria:

- `find_package(crypto_core CONFIG REQUIRED)` works from install tree.
- remote CI evidence exists, not just workflow files.
- OpenSSL remains optional and disabled by default.

### 4. Regression Hardening

Status: queued
Priority: P1
Size: M

Goal: convert security-risk notes into executable tests.

Next slices:

- malformed DER/signature fixtures for RSA and ECDSA.
- RSA-PSS and RSA-OAEP negative cases.
- Ed25519 public-key decode and signature canonicality rejection cases.
- P-256 public-point rejection cases.
- RNG failure injection with stable `ErrorCode`.
- provider capability matrix regression against `docs/algorithm-status.md`.

Exit criteria:

- malformed inputs reject deterministically.
- RNG failures do not silently fall back.
- capability tests prevent docs/API drift.

### 5. Ed25519 Finish

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

## Later

Keep these out of active work until a current focus item needs them:

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
