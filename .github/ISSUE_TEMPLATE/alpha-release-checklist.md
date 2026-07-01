---
name: Alpha release checklist
about: Track evidence for an alpha release candidate
title: "Release checklist: v0.1.0-alpha.1"
labels: release
assignees: ""
---

## CI evidence

- [ ] Native Windows/Linux/macOS CI run links recorded.
- [ ] OpenSSL-enabled CI run links recorded where supported.
- [ ] Sanitizer job status recorded.
- [ ] Static analysis, coverage, and fuzzing job status recorded.
- [ ] Install-tree smoke CI job status recorded.

## Install and artifacts

- [ ] install-tree consumer smoke completed through `find_package`.
- [ ] Source archive checksum generated from final artifact.
- [ ] SBOM status recorded.
- [ ] Unsigned artifacts clearly stated, or signing key fingerprint recorded.

## Notes

- [ ] Release notes include security changes and provider differences.
- [ ] Known limitations are listed.
- [ ] `docs/release-evidence.md` refreshed for exact commit/run.

## Unsigned artifacts

Artifacts are unsigned until a release signing key exists. Users must verify the
source commit and CI evidence instead of trusting artifact signatures.
