# Roadmap

## Direction

`crypto-core` is a native-first cryptographic engine.

- `NativeProvider` is the default backend and proof target.
- `OpenSSLProvider` is optional: compatibility backend and differential oracle.
- 0.x stays experimental until release gates below are proven.
- Current priority is stabilizing the existing surface, not adding algorithms.

This file tracks direction and remaining work only. Detailed imported-analysis
history belongs in commits, not in the roadmap.

## Roadmap Rules

- Evidence first: security, CI, packaging, and release claims need a
  reproducible command, test, or linked remote run.
- Keep security docs and code vocabulary aligned.
- Prefer targeted hardening slices over broad rewrites.
- Every non-trivial hardening change needs a focused regression test.
- Do not raise security claims without audit, leakage evidence, or release
  evidence that supports them.

## Release Gates

Before calling an alpha/reuse-ready release:

- Windows, Linux, and macOS native CI have a green remote run.
- OpenSSL ON/OFF CI has a green remote run where OpenSSL is supported.
- static analysis, coverage, and fuzzing CI jobs have green remote runs.
- `find_package(crypto_core CONFIG REQUIRED)` works from an install tree.
- security boundary docs state threat model, provider trust, zeroization, RNG
  failure behavior, nonce/tag responsibility, and constant-time limitations.
- supported algorithms, parameters, unsupported modes, and provider differences
  are documented.
- public API failure modes are documented for misuse-sensitive operations.
- known-answer, differential, and negative tests cover each release-supported
  primitive.
- malformed parser/import/decrypt inputs reject deterministically.
- release artifacts include checksum policy, SBOM status or plan, signing
  status, release notes, and vulnerability reporting policy.
- release evidence is refreshed for the exact release candidate commit.

## Active Work

### P0: Close Alpha Release Gates

Goal: make `v0.1.0-alpha.1` experimental but reproducible.

Targets:

- add an install-tree smoke CI job for the CMake package config.
- record final release-candidate CI evidence in `docs/release-evidence.md`.
- prepare release notes with known limitations, provider differences, and
  security-relevant changes.
- generate source archive checksums or document the exact manual process.
- generate SBOM output or explicitly record SBOM absence for the alpha.
- state unsigned-artifact status if no release signing key exists.
- create the `v0.1.0-alpha.1` release checklist issue from the existing
  checklist template.

Exit criteria:

- release candidate commit has linked green CI evidence.
- install-tree consumer smoke is required CI, not only a local/manual check.
- checksum, SBOM, signing, release notes, and vulnerability reporting status
  are visible from release docs.

Current bundle:

- release artifact integrity bundle: source archive checksum commands,
  alpha SBOM absence conditions, unsigned-artifact status, and alpha checklist
  issue creation command are documented.

Next bundle:

- remote release evidence bundle: refresh exact release-candidate remote CI
  evidence, generate final source archive checksums from the release candidate,
  and create the alpha release checklist issue.

### P1: Grow Malformed Corpus And Fuzzing

Goal: keep expanding malformed parser/import/decrypt coverage from real
regressions and edge cases.

Targets:

- add `tests/corpus/invalid/` seeds for newly found malformed-input bugs.
- expand DER cases: non-minimal length, negative integer, trailing data, wrong
  OID, and malformed SPKI/PKCS#8/SEC1/RSA PKCS#1 inputs.
- expand ECDSA DER malformed signature cases.
- expand RSA-PSS salt, hash, and malformed signature cases.
- expand RSA-OAEP label, hash, and ciphertext length boundary cases.
- expand Ed25519 raw public key, seed size, and canonical encoding cases.
- expand AES-GCM nonce, tag, and ciphertext mutation cases.
- keep `tests/fuzz/fuzz_parser_boundaries.cpp` aligned with supported public
  parser/import/decrypt boundaries.
- keep `static-analysis-ubuntu-clang`, `coverage-ubuntu-clang`, and
  `fuzzing-ubuntu-clang` green as required CI jobs.

Current bundle:

- malformed parser/import/decrypt corpus bundle: representative negative seeds
  cover encoding/PEM, DER key import, ECDSA/RSA signatures, AES-GCM decrypt,
  and RSA-OAEP decrypt. Local and remote CI evidence is recorded.

Next bundle:

- release-gate closure bundle: P1 exit criteria are ready for reassessment;
  current source work has moved to the P0 install-tree/package evidence bundle.

Exit criteria:

- supported malformed parser/import/decrypt boundaries have representative
  negative corpus coverage.
- each new malformed-input regression lands with a corpus seed or focused
  negative test.
- required analysis jobs stay green on normal pull requests.

### P1: Improve Docs And Misuse-Resistant Examples

Goal: make existing APIs harder to misunderstand before expanding the API.

Targets:

- add `docs/README.md` or `docs/INDEX.md` that groups getting started,
  security boundaries, API contract, testing/release, and future design docs.
- update README CI coverage to mention static analysis, coverage, and fuzzing
  gates.
- make "no published release yet" and "0.x experimental" easy to see.
- strengthen quickstart examples for SHA-256, AES-GCM nonce generation/tag
  handling, sign/verify failure handling, and guarded `Result::value()` use.
- place AES-GCM nonce-reuse warnings near runnable examples.
- clarify that minimal PEM decode/armor support exists today, while full PEM
  parser/encoder work remains later.
- strengthen raw key export/access warnings for APIs such as
  `PrivateKey::bytes()`.
- explain provider support failure versus parsed-but-invalid verification
  results in quickstart or API docs.

Exit criteria:

- a new user can find the right security/API/release doc without reading every
  doc file.
- quickstart examples show safe nonce, tag, failure, and `Result` handling.
- current PEM support cannot be mistaken for complete PEM parser/encoder
  support.

### P2: Improve Test Diagnostics And Coverage Baselines

Goal: keep tests dependency-light while making failures easier to diagnose.

Targets:

- improve the in-tree test helper before adding an external test framework.
- include file, line, and test-case name in assertion failures.
- print expected and actual error codes where tests assert `ErrorCode`.
- preserve coverage reports as artifacts or define a minimal regression
  threshold.
- split short fuzzing smoke from manual or scheduled extended fuzzing.

Exit criteria:

- common test failures identify the failing expression and location.
- coverage output is preserved or compared against an agreed baseline.
- extended fuzzing can run without slowing normal pull requests.

### P2: Maintain Side-Channel Hardening Backlog

Goal: accumulate evidence without overstating constant-time claims.

Targets:

- keep "no formal constant-time certification" language.
- review RSA CRT recombination paths that still use variable-limb `BigInt`.
- review P-256 exceptional-case branches.
- keep constant-time notes updated when implementation paths change.
- connect RSA/P-256 audit notes to focused tests where practical.
- consider dudect, ctgrind, or equivalent leakage analysis later, without
  turning 0.x into a certification claim.

Exit criteria:

- known constant-time limits remain documented and current.
- hardening work leaves tests or review evidence behind.
- release docs do not imply audit, FIPS validation, or formal leakage proof.

## Later

Keep these out of active work until a current focus item needs them:

- AES-GCM safe helper or envelope helper implementation. First settle format
  and golden files.
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
- release workflow automation. First make the manual alpha gate correct.
- full `docs/architecture.md`, `docs/testing-strategy.md`,
  `docs/release-process.md`, and `docs/migration-guide.md` split. Keep
  content in existing policy, API contract, envelope, key lifecycle, security
  model, and release docs until a split removes real duplication.

## External Repository Tasks

These belong in GitHub settings or release operations, not in source files:

- set repository description to
  `Native-first C++20 cryptographic engine with provider-backed APIs. Experimental 0.x.`
- set topics such as `cryptography`, `cpp20`, `security`, `crypto`, `openssl`,
  `aes-gcm`, `rsa-pss`, `ed25519`, `ecdsa`, `hkdf`, and `pbkdf2`.
- create the alpha release checklist issue.
- publish release artifacts only after the release gates above are satisfied.

## Not Planned For 0.x/1.x Unless Required

- mutable global provider registry.
- runtime replacement of `default_provider()`.
- certificate chain validation.
- TLS protocol implementation.
- legacy algorithms such as DES, RC2, RC4, MD5, or SHA-1.
- formal constant-time certification.
- FIPS/validated mode claim.
- production-ready or audited security claims.
