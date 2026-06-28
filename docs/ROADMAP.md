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

### P1: Static Analysis And Coverage

Goal: add cheap mechanical checks without blocking useful work too early.

Targets:

- manual or non-blocking `clang-tidy` job first.
- parser/negative-path coverage reporting.
- sanitizer coverage expansion only after the current matrix stays stable.

Exit criteria:

- analysis failures are visible in CI before becoming required.
- coverage reports help find missing parser and negative-path tests.

### P1: Expand Fuzzing

Goal: turn the current smoke harness into useful coverage-guided fuzzing.

Targets:

- add ECDSA DER signature parsing to the fuzz harness.
- add RSA-PSS signature and RSA-OAEP ciphertext fuzz selectors.
- run the harness manually or non-blocking in CI when Clang/libFuzzer is
  available.
- grow `tests/corpus/invalid/` from real regression inputs.

Exit criteria:

- fuzzer build command is validated on at least one supported platform.
- CI records a non-blocking fuzz run or a documented reason it is unavailable.

### P1: Alpha Release Preparation

Goal: make `v0.1.0-alpha.1` verifiable without implying production readiness.

Targets:

- release checklist issue with CI run links, install smoke, checksum, SBOM,
  signing status, and known limitations.
- release notes for security-relevant changes and provider differences.
- source archive checksum policy before binary artifacts.

Exit criteria:

- release evidence names exact commit/run and freshness status.
- release notes say artifacts are unsigned until signing exists.
- users can verify source/archive integrity from documented commands.

## Later

Keep these out of active work until a current focus item needs them:

- full `docs/architecture.md`, `docs/testing-strategy.md`,
  `docs/release-process.md`, and `docs/migration-guide.md` split. Keep
  content in existing policy, API contract, envelope, key lifecycle, security
  model, and release docs until a split removes real duplication.
- envelope serializer implementation and golden file tests.
- provider-backed key lifecycle implementation.
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
