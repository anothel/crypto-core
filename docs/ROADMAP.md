# Roadmap

## Direction

`crypto-core` is a native-first cryptographic engine.

`NativeProvider` is the default backend and proof target.
`OpenSSLProvider` stays optional as compatibility backend and differential
oracle. OpenSSL support is controlled by `CRYPTO_CORE_ENABLE_OPENSSL` and is
disabled by default.

This file tracks remaining work only.

## Planning Scale

- `S`: 1 focused slice, usually 1-3 files, targeted tests plus full suite
- `M`: 2-4 slices, internal design needed, multiple test targets
- `L`: 5+ slices, API or architecture boundary change

Every implementation slice must pass:

- native Debug configure/build/test
- OpenSSL-enabled Debug configure/build/test when OpenSSL surface exists
- targeted tests for new or changed behavior

## External Analysis Triage: 2026-06-22

Source: `C:/Users/anoth/Downloads/crypto-core-analysis-roadmap.md`.

Accepted now:

- Provider capability truthfulness.
  - Reason: current `supports(SignatureAlgorithm::ed25519)` can be read as
    "sign and verify", while only verify exists.
  - Action: add operation-level capability checks for sign/verify/keygen/
    encrypt/decrypt/derive. Keep legacy algorithm-level `supports()` for
    source compatibility.

Accepted and already completed:

- Ed25519 sign.
  - Reason: Ed25519 was verify-only when the analysis was imported.
  - Result: NativeProvider now supports deterministic Ed25519 sign and verify.

Accepted into roadmap:

- Raw vs DER key material boundary.
  - Reason: `import_der()` is currently a thin owned key container and does not
    prove DER parsing for every algorithm.
  - Goes under Next Queue before KeyStore handle evolution.
- Cross-platform OS RNG.
  - Reason: native engine should not be Windows-only.
  - Goes under Next Queue.
- Security documentation and algorithm status.
  - Reason: users need explicit supported/experimental/verify-only status and
    vulnerability-reporting expectations.
  - Goes under Next Queue.
- CMake install/export and CI matrix.
  - Reason: library usability and repeatable verification matter before alpha.
  - Goes under Next Queue.
- NativeProvider key generation status.
  - Reason: provider API exposes key generation, but NativeProvider support is
    currently absent and should be test-visible.
  - Goes into operation-level capability checks and algorithm status docs.
- Broader negative/vector test backlog.
  - Reason: Ed25519, RNG, DER, RSA, P-256, provider, memory, and fuzzing gaps
    are valid, but not all belong in one implementation slice.
  - Goes into each relevant roadmap section.

Deferred:

- Provider-backed KeyStore, PKCS#11, CSR, PQC.
  - Reason: already tracked, but depends on key-material and provider-capability
    cleanup.
- Formal constant-time certification.
  - Reason: not credible until RSA/P-256/Ed25519 arithmetic boundaries are
    documented and narrowed.
- Validated/restricted provider mode.
  - Reason: useful later, but premature before algorithm status and self-tests.

Rejected for now:

- Replace operation-level overloads with a fixed `ProviderCapabilities` struct.
  - Reason: a struct will churn every time an algorithm is added. Operation
    overloads keep API smaller and extensible.
- Add many separate docs at once.
  - Reason: documentation should start with `algorithm-status`, `security-model`,
    and `constant-time-notes`; more files can split out when content grows.
- Choose a license without owner decision.
  - Reason: license is project-owner policy, not an implementation detail.

Alpha gate from the analysis:

- `LICENSE` selected by owner
- `SECURITY.md` present
- Windows/Linux/macOS native CI green
- OpenSSL ON/OFF CI green
- algorithm status table present
- Ed25519 sign+verify complete
- cross-platform OS RNG present
- raw/DER key material boundary clear
- CMake install/export works

## Current Focus

### 1.3 Ed25519

Status: active
Size: `M`
Priority: P1

Goal:

- add deterministic modern signatures with simpler parameter surface than
  RSA/ECDSA.

Remaining slices:

1. `S` OpenSSL differential path, if local OpenSSL supports Ed25519
   - sign OpenSSL -> verify Native
   - sign Native -> verify OpenSSL

2. `S` Ed25519 key generation, if needed before KeyStore evolution
   - import public/private key material
   - export public/private material in the current thin key shape

Exit criteria:

- RFC 8032 vectors pass
- NativeProvider signs and verifies deterministic Ed25519 signatures
- invalid signatures return `VerifyResult::invalid()`
- API does not expose irrelevant RSA/ECDSA parameters

## Next Queue

### 1.4 Key Material Format Boundary

Status: queued
Size: `M`
Priority: P0

Goal:

- separate raw key material APIs from DER/ASN.1 key import APIs.

Remaining slices:

1. `M` DER naming migration plan
   - decide `import_spki_der`, `import_pkcs8_der`, and `import_rsa_pkcs1_der`
   - keep compatibility wrappers until 1.0 API decision

Exit criteria:

- DER-specific names map to actual DER parsing behavior
- existing RSA/ECDSA tests stay green

### 1.5 Cross-Platform OS RNG

Status: active
Size: `S`
Priority: P1

Goal:

- prove native OS RNG on Windows, Linux, and macOS in CI.

Remaining slices:

1. `S` platform CI smoke tests
   - run native RNG tests on Windows
   - run native RNG tests on Linux
   - run native RNG tests on macOS
   - GitHub Actions workflow added; first remote green run pending

Exit criteria:

- native RNG tests run in Windows/Linux/macOS CI

### 1.6 Security and Status Documentation

Status: queued
Size: `S`
Priority: P1

Goal:

- make project security boundary and algorithm status explicit.

Remaining slices:

1. `S` `SECURITY.md`
   - vulnerability reporting policy
   - supported versions
   - do-not-file-public-sensitive-issue note

2. `S` `docs/algorithm-status.md`
   - native sign/verify/encrypt/decrypt/keygen status
   - OpenSSL oracle status
   - experimental/verify-only/planned/deferred labels

3. `S` `docs/security-model.md` and `docs/constant-time-notes.md`
   - protected assets
   - non-goals for 0.x
   - known timing-risk register

Exit criteria:

- user can tell which algorithms are complete, verify-only, or deferred
- known side-channel boundaries are documented, not implied

### 1.7 Build, Package, and CI

Status: active
Size: `M`
Priority: P1

Goal:

- make the library installable and continuously verified.

Remaining slices:

1. `M` CMake install/export
   - `install(TARGETS)`
   - `install(EXPORT)`
   - package config and version config
   - install-tree smoke test

2. `M` GitHub Actions native CI
   - Windows/MSVC
   - Ubuntu/GCC
   - Ubuntu/Clang
   - macOS/Clang
   - workflow added; first remote green run pending

3. `M` OpenSSL and sanitizer CI
   - OpenSSL ON/OFF
   - ASan/UBSan on Linux Clang Debug
   - workflow added; first remote green run pending

Exit criteria:

- `find_package(crypto_core CONFIG REQUIRED)` works from install tree
- native CI covers Windows/Linux/macOS
- OpenSSL oracle path is tested in CI

### 1.8 RSA Deferred Hardening

Status: deferred
Size: `M`
Priority: P2

Goal:

- continue RSA timing-risk reduction beyond the P0 NativeProvider private
  exponent path.

Remaining slices:

1. `M` CRT recombination fixed-width path
   - replace variable-limb CRT recombination with fixed-width arithmetic
   - preserve existing provider behavior
   - minimum tests: RSA primitive, provider, reference vectors

2. `M` RSA blinding setup hardening
   - assess public-exponent blinding and inverse setup
   - move private-sensitive pieces away from variable-limb arithmetic where
     practical

3. `L` additional RSA support
   - RSA-3072/RSA-4096 fixed-width support
   - native RSA key generation
   - PKCS#11-backed RSA keys

Deferred:

- formal constant-time certification

### 1.9 P-256 Deferred Hardening

Status: deferred
Size: `M`
Priority: P2

Goal:

- continue P-256 timing-risk reduction beyond the current fixed-limb backend.

Remaining slices:

1. `M` complete point formulas
   - replace exceptional-case point add/double paths where practical
   - preserve existing ECDSA sign/verify behavior
   - minimum tests: group-law edge cases, RFC 6979 vectors, provider vectors

2. `M` constant-time audit
   - review scalar, field, point, and DER-adjacent boundaries
   - document public-input branches vs private-input branches

Deferred:

- P-384
- compressed point support
- raw fixed-width signature public format
- ECDH, unless key agreement becomes a project goal

### 1.10 KeyStore Evolution

Status: queued  
Size: `L`  
Priority: P2

Goal:

- evolve from in-memory key bytes to key references that can later support
  provider-backed and hardware-backed keys.

Remaining slices:

1. `M` provider-backed key handle model
   - opaque key id/reference type
   - exportable vs non-exportable policy
   - provider ownership boundary

2. `M` sign/decrypt by key id
   - provider API path for handle-backed operations
   - in-memory and provider-backed key paths share high-level calls

3. `S` PKCS#11-compatible key reference shape
   - align data model with slot/token/object handle needs
   - no real PKCS#11 loading yet

Exit criteria:

- high-level APIs can use opaque key handles
- private key export restrictions are representable
- current in-memory `KeyStore` behavior stays green

### 1.11 Self-Test and Validated Mode

Status: optional  
Size: `M`  
Priority: P3

Goal:

- add validation-oriented behavior only when deployment needs it.

Remaining slices:

1. `S` self-test registry design
2. `S` deterministic known-answer self-tests by algorithm family
3. `M` restricted mode capability policy

Exit criteria:

- self-tests are deterministic
- restricted mode cannot silently enable unsupported algorithms
- normal provider injection remains simple

## Phase 3: Encoding and Certificate Requests

### 2.0 ASN.1 DER Core

Status: queued  
Size: `M`  
Priority: P1 after Phase 2 hardening

Remaining slices:

1. `S` DER TLV reader
   - definite length only
   - reject indefinite lengths
   - reject trailing data

2. `S` primitive helpers
   - INTEGER
   - BIT STRING
   - OCTET STRING
   - OID
   - SEQUENCE nested reader

3. `S` migrate RSA/ECDSA parser fragments where practical

Exit criteria:

- malformed DER rejects deterministically
- RSA/ECDSA key parsers can share DER helpers
- parser tests cover at least 20 malformed cases

### 2.1 PEM

Status: queued  
Size: `S`  
Priority: P2

Remaining slices:

1. label validation policy
2. multiple-block behavior decision
3. header handling decision
4. deterministic line wrapping on encode

Exit criteria:

- malformed armor rejects deterministically
- label mismatch behavior is tested
- PEM output is deterministic

### 2.2 CSR Parser

Status: queued  
Size: `M`  
Priority: P2

Remaining slices:

1. CertificationRequestInfo parser
2. subject extraction
3. public key extraction
4. signature algorithm extraction
5. CSR signature verification through provider API
6. malformed CSR fixture suite

Exit criteria:

- valid CSR fixtures parse
- malformed CSR fixtures reject without exceptions
- extracted public keys flow into provider verify APIs

## Phase 4: External Providers and PQC

### 3.0 PKCS#11 Provider

Status: later  
Size: `L`  
Priority: P3

Remaining slices:

1. module loading
2. slot/token enumeration
3. session lifecycle
4. login policy
5. key lookup
6. token-backed sign/verify
7. software-token or mocked-boundary tests

Exit criteria:

- token private keys can sign without export
- session and token errors map into `ErrorCode`
- provider-backed key handles integrate with `KeyStore`

### 3.1 PQC Provider

Status: later  
Size: `L`  
Priority: P3

Remaining slices:

1. PQC signature extension point
2. KEM API decision
3. reference implementation integration decision
4. test vector ownership/license review
5. provider capability model for large keys/signatures/ciphertexts

Exit criteria:

- PQC signatures do not force accidental RSA/ECDSA/Ed25519 API changes
- KEM support has an explicit API if added
- vectors or upstream provider tests cover added algorithms

## Not Planned For 0.x/1.x Unless Required

- mutable global provider registry
- runtime replacement of `default_provider()`
- certificate chain validation
- TLS protocol implementation
- legacy algorithms such as DES, RC2, RC4, MD5, or SHA1
