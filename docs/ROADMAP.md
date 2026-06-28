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

### P1: Promote Analysis Gates

Goal: decide when non-blocking analysis, coverage, and fuzzing jobs are stable
enough to become required.

Targets:

- monitor `static-analysis-ubuntu-clang`, `coverage-ubuntu-clang`, and
  `fuzzing-ubuntu-clang` for toolchain noise.
- fix actionable findings before promoting jobs.
- keep local reproduction scripts from writing generated artifacts outside
  ignored build directories.
- keep growing `tests/corpus/invalid/` from real regressions.

Exit criteria:

- jobs are green on normal pull requests.
- reproduction scripts leave no tracked or untracked root artifacts.
- required status checks are updated only after the jobs are stable.

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
