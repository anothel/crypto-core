# Alpha Release Checklist

Use this for `v0.1.0-alpha.1` and later alpha candidates. Do not call an alpha
production-ready or production-certified.

## v0.1.0-alpha.1 Checklist

- CI run links for native Windows, Linux, and macOS jobs.
- CI run links for OpenSSL-enabled jobs where OpenSSL is supported.
- sanitizer, static-analysis, coverage, and fuzzing job status recorded.
- install-tree consumer smoke completed through `find_package`.
- source archive checksum generated from final release artifacts.
- SBOM status recorded as published or explicitly absent.
- signing status recorded; artifacts are unsigned until a release key exists.
- release notes include security changes, provider differences, and known
  limitations.
- `docs/release-evidence.md` refreshed with exact commit, run, and freshness
  status.

## Known Limitations

- 0.x remains experimental.
- no external audit is claimed.
- no formal constant-time certification is claimed.
- unsigned artifacts require users to verify source commit and CI evidence.
- coverage-guided fuzzing and analysis jobs are required CI jobs.
