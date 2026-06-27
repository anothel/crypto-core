# Release Integrity

This document defines release-artifact verification expectations before the
project publishes reusable 0.x artifacts.

## Dependency Update Policy

- Do not vendor third-party cryptographic dependencies into this repository.
- Keep OpenSSL optional and record the OpenSSL version used for release
  evidence.
- Apply dependency security updates when CI still passes on the supported
  matrix.
- For routine dependency updates, batch them behind a green native and
  OpenSSL-enabled CI run.
- For security advisories that affect a release-supported dependency, update or
  document non-impact before publishing new artifacts.

## SBOM Expectations

Each published release artifact set should include an SBOM or an explicit note
that no artifact was published.

The SBOM should record:

- project name, version, commit, and build configuration
- compiler and platform used for each binary artifact
- optional OpenSSL dependency version when OpenSSL support is enabled
- direct build-time tools needed to reproduce the artifact
- SBOM generator name and version

## Checksums

Every published archive, package, binary, and SBOM should have a SHA-256
checksum.

Checksum files should:

- use deterministic artifact filenames
- include one SHA-256 digest per artifact
- be published beside the artifacts
- be regenerated only from the final uploaded artifacts

## Signing

Release signing is required before calling artifacts reuse-ready.

Until the project owner publishes a release signing key:

- release artifacts are considered unsigned
- release notes must say artifacts are unsigned
- users must rely on source checkout plus CI evidence, not artifact signatures

After a signing key exists:

- sign the checksum file or each artifact
- publish the public verification key and fingerprint
- document the verification command in the release notes

## Release Checklist

No release checklist is maintained yet because the project has no versioned
release process. Add one only when actual release steps exist.
