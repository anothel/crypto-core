# Security Review Checklist

Use this checklist for changes that touch crypto behavior, key material,
release artifacts, provider boundaries, or security documentation.

## Required Checks

- forbidden algorithms are not introduced
- nonce, IV, and salt handling is explicit
- logs and errors do not expose plaintext, keys, tokens, passwords, seeds, or private keys
- malformed inputs have deterministic negative tests
- secret/tag comparison stays on constant-time helper paths
- public API failure modes use stable `ErrorCode` values
- release artifacts have SBOM, checksums, signing status, and vulnerability reporting notes
- OpenSSL provider differences are documented when behavior changes
- docs and tests update with any supported algorithm, parameter, or format change

## Code Review Questions

- Does this change let callers choose weaker algorithms or modes?
- Does this change pass raw key material through a wider boundary?
- Does this change create, reuse, or persist nonces?
- Does this change parse external data without negative tests?
- Does this change expose more detail through logs, errors, panics, or debug output?
- Does this change alter provider capability reports?
- Does this change require migration notes or release evidence?

## Release Review Questions

- Are native and OpenSSL-enabled CI runs green where supported?
- Does install-tree `find_package(crypto_core CONFIG REQUIRED)` still work?
- Are SBOM and checksum expectations satisfied or explicitly marked absent?
- Are unsigned artifacts clearly marked unsigned?
- Is the vulnerability reporting policy linked?
