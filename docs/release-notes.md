# Release Notes

## Unreleased

Status:

- 0.x remains experimental.
- no production certification is claimed.
- no formal constant-time certification is claimed.
- unsigned artifacts require users to verify the source commit and CI evidence.
- no release artifacts are signed until a release signing key exists.
- no SBOM is published for `v0.1.0-alpha.1` unless custom binary/package
  artifacts are added.
- source archives require SHA-256 checksums generated from final release
  artifacts.

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
- added CI jobs for clang-tidy, LLVM coverage reporting, and the libFuzzer seed
  corpus.
- added an alpha release checklist document and GitHub issue template for
  CI evidence, install smoke, checksum, SBOM, signing status, and limitations.
- added local reproduction scripts for static analysis, coverage, and fuzzing
  CI jobs.
- kept coverage and fuzzing reproduction artifacts under ignored build
  directories.
- installed LLVM coverage tools in CI before running the coverage reproduction
  script.
- promoted static analysis, coverage, and fuzzing CI jobs to required workflow
  gates after stabilizing toolchain noise.
- added an install-tree smoke CI job that verifies
  `find_package(crypto_core CONFIG REQUIRED)` from an installed package.

Known limitations:

- no stable encrypted envelope serializer yet.
- no provider-backed KMS/HSM/Secret Manager key lifecycle implementation yet.
- AES-GCM nonce uniqueness is caller responsibility in the current low-level
  API.
- coverage-guided fuzzing, coverage, static-analysis, and install-tree smoke
  jobs are required CI workflow gates.
- no SBOM is published for `v0.1.0-alpha.1` when the alpha publishes only
  GitHub-generated source archives.
