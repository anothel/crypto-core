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

Publish the SBOM in SPDX JSON or CycloneDX JSON format. The release workflow may
use a different generator, but release notes must record the generator name and
version. A concrete command template for SPDX JSON is:

```sh
syft dir:. -o spdx-json=crypto-core-${version}.spdx.json
```

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

Command template:

```sh
sha256sum ${artifacts} > crypto-core-${version}.sha256
```

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

Command templates:

```sh
cosign sign-blob --key crypto-core-release.key --output-signature ${artifact}.sig ${artifact}
cosign verify-blob --key crypto-core-release.pub --signature ${artifact}.sig ${artifact}
```

## Artifact Verification

Users should verify downloaded artifacts before reuse:

```sh
sha256sum -c crypto-core-${version}.sha256
cosign verify-blob --key crypto-core-release.pub --signature ${artifact}.sig ${artifact}
```

If artifacts are unsigned, release notes must say so and users should verify the
source commit against recorded CI evidence instead of trusting artifact
signatures.

## Security Changelog And Migration Notes

Each versioned release should state:

- security fixes and behavior-changing hardening since the previous release
- breaking API or error-code changes
- provider behavior differences that affect compatibility
- new unsupported modes or removed experimental surfaces
- known unsigned-artifact or missing-SBOM exceptions

## Alpha Release Checklist Issue

For each alpha candidate, create a release checklist issue before tagging. Use
`.github/ISSUE_TEMPLATE/alpha-release-checklist.md` and keep it linked from the
release notes or release evidence.

The issue must track:

- CI run links
- install-tree consumer smoke
- checksum and SBOM status
- signing status, including when artifacts are unsigned
- known limitations and provider differences

## Release Checklist

Before publishing versioned artifacts:

- run native CI on Windows, Linux, and macOS
- run OpenSSL-enabled CI where OpenSSL is supported
- run install-tree consumer smoke
- publish SHA-256 checksums for every archive, package, binary, and SBOM
- publish SBOM in SPDX JSON or CycloneDX JSON format
- publish security changelog and migration notes
- publish signing key fingerprint and verification command when artifacts are signed
- state clearly when artifacts are unsigned
