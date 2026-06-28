# Release Notes

## Unreleased

Status:

- 0.x remains experimental.
- no production certification is claimed.
- no formal constant-time certification is claimed.
- no release artifacts are signed until a release signing key exists.

Changed:

- added governance docs for crypto policy, envelope format, key lifecycle, API
  contract, and review checklist.
- aligned README provider wording with Ed25519 OpenSSL differential coverage.
- tracked fuzzing, malformed corpus, static analysis, coverage, and alpha
  release preparation in the roadmap.
- added a fuzz boundary smoke test, invalid corpus path, and libFuzzer skeleton
  for parser/import/decrypt boundaries.
- expanded the fuzz boundary harness and corpus to cover ECDSA DER signatures,
  RSA-PSS signatures, and RSA-OAEP ciphertexts.
- added non-blocking CI jobs for clang-tidy, LLVM coverage reporting, and the
  libFuzzer seed corpus.
- added an alpha release checklist document and GitHub issue template for
  CI evidence, install smoke, checksum, SBOM, signing status, and limitations.

Known limitations:

- no stable encrypted envelope serializer yet.
- no provider-backed KMS/HSM/Secret Manager key lifecycle implementation yet.
- AES-GCM nonce uniqueness is caller responsibility in the current low-level
  API.
- coverage-guided fuzzing and coverage jobs are planned but not release gates
  yet.
