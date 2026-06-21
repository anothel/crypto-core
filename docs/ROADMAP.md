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

## Current Focus

### 1.2 ECDSA P-256 Hardening

Status: active
Size: `M`
Priority: P0

Goal:

- finish native P-256 hardening now that RSA private-operation P0 is closed.

Remaining slices:

1. `M` point addition/doubling audit
   - identify remaining exceptional-case branches
   - route secret-dependent choices through selectors where practical
   - document remaining timing boundary

Exit criteria:

- native ECDSA sign/verify vectors pass
- OpenSSL interop stays green
- DER signature behavior remains documented and tested
- remaining timing-risk boundary is explicit

Deferred:

- P-384
- compressed point support
- raw fixed-width signature public format
- ECDH, unless key agreement becomes a project goal

## Next Queue

### 1.3 RSA Deferred Hardening

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

### 1.4 Ed25519

Status: queued  
Size: `M`  
Priority: P1

Goal:

- add deterministic modern signatures with simpler parameter surface than
  RSA/ECDSA.

Remaining slices:

1. `S` API fit check
   - key algorithm enum
   - signature algorithm enum
   - no hash/prehash knobs unless deliberately added

2. `M` NativeProvider Ed25519 sign/verify
   - import public/private key material
   - sign and verify through provider API
   - minimum tests: RFC 8032 vectors, invalid signature vectors

3. `S` OpenSSL differential path, if local OpenSSL supports Ed25519
   - sign OpenSSL -> verify Native
   - sign Native -> verify OpenSSL

Exit criteria:

- RFC 8032 vectors pass
- invalid signatures return `VerifyResult::invalid()`
- API does not expose irrelevant RSA/ECDSA parameters

### 1.5 KeyStore Evolution

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

### 1.6 Self-Test and Validated Mode

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
