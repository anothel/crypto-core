# Security Policy

## Supported Versions

`crypto-core` 0.x is experimental and not production-certified.

Security fixes are handled on a best-effort basis for the latest `main` branch.
No stable release support window is promised until the project owner publishes a
versioned support policy.

## Reporting a Vulnerability

Report sensitive vulnerabilities by email: anothel1@naver.com

Do not open public issues for vulnerabilities that could expose private keys,
plaintext, RNG failures, authentication bypasses, memory disclosure, or practical
signature/encryption breaks.

Include, when possible:

- affected commit or version
- platform and compiler
- provider in use (`NativeProvider` or `OpenSSLProvider`)
- minimal reproduction steps or proof of concept
- impact and any known mitigations

Reports are reviewed on a best-effort basis. Public disclosure should wait until
a fix or mitigation is available.

## Scope

In scope:

- private key, symmetric key, or plaintext disclosure
- RNG failure behavior or weak fallback
- incorrect signature verification or encryption/decryption behavior
- malformed key, DER, signature, or ciphertext inputs that bypass validation
- memory zeroization regressions in secret-owning types

Out of scope:

- production certification claims for 0.x
- formal constant-time certification
- certificate chain validation
- TLS protocol behavior
- vulnerabilities only present in unsupported legacy algorithms

Security boundaries and non-goals are documented in
`docs/security-model.md`, `docs/algorithm-status.md`, and
`docs/constant-time-notes.md`.
