# Fuzzing

Fuzzing is a required CI smoke gate. This document tracks the current harness
and corpus contract so parser/import/decrypt boundaries have one place to grow.

## Current Harness

- `tests/fuzz/fuzz_parser_boundaries.cpp`

Covered boundaries:

- Base64 decode.
- Base64url decode.
- PEM decode.
- RSA SPKI and PKCS#1 public-key import.
- RSA PKCS#8 private-key import.
- P-256 SEC1 private-key import.
- AES-GCM decrypt with mutated tag and ciphertext.
- ECDSA DER signature verify.
- RSA-PSS signature verify.
- RSA-OAEP decrypt.

## Corpus

Invalid seed files live in `tests/corpus/invalid/`.

Current corpus:

- `base64_bad_padding.txt`
- `base64_invalid_character.txt`
- `base64url_bad_padding.txt`
- `base64url_standard_alphabet.txt`
- `pem_invalid_payload.pem`
- `pem_mismatched_label.pem`
- `der_declared_length_too_long.der`
- `der_short_length.der`
- `der_truncated_sequence.der`
- `der_wrong_tag.der`
- `aead_short_tag.bin`
- `aead_tampered_ciphertext.bin`
- `ecdsa_der_truncated_signature.der`
- `rsa_pss_short_signature.bin`
- `rsa_oaep_short_ciphertext.bin`

## Local Smoke

`crypto_core.fuzz_boundary_smoke` runs the seed corpus through public APIs and
requires deterministic rejection. It is not coverage-guided fuzzing.

The CMake test build also compiles `tests/fuzz/fuzz_parser_boundaries.cpp` as an
object target, which catches API drift without requiring libFuzzer locally.

## CI Hook

`fuzzing-ubuntu-clang` builds the harness with libFuzzer and runs the invalid
seed corpus. The job is required.

## Manual Fuzzer Build

Use Clang/libFuzzer when available:

```sh
bash scripts/ci/fuzzing.sh
```

Keep OpenSSL-specific builds separate; this harness targets native/public
boundaries first.

On MSVC-only local environments, use the CMake object target and smoke test as
the available fallback until Clang/libFuzzer is installed.
