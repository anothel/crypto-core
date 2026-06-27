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

## Active Work

Work in this order unless a security issue preempts it:

### 1. P1: API and Implementation Hardening

Goal: reduce misuse without expanding the API surface unnecessarily.

Next slices:

- keep dedicated key/nonce/salt/tag/AAD types where they already exist; add a
  new type only when raw bytes are causing real misuse risk.
- make error types precise where callers must branch, and intentionally vague
  where detail would leak security state.
- isolate deprecated or unsafe surfaces behind explicit names/docs.

Exit criteria:

- API docs show both recommended use and common misuse rejection.

### 2. P2: RSA and P-256 Hardening

Goal: reduce risk in reviewed math boundaries without broad rewrites.

Next slices:

- RSA CRT recombination boundary.
- P-256 exceptional-case formulas.

Exit criteria:

- one reviewed boundary closes with targeted tests.
- constant-time notes update when behavior or limits change.

### 3. P2: Release Integrity

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
