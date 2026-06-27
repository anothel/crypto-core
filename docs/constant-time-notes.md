# Constant-Time Notes

## Status

Constant-time helper primitives exist, but `crypto-core` does not claim
algorithm-level constant-time certification.

Treat 0.x as experimental. Do not infer audit status from helper names or fixed
operation-count internals.

## What Exists

- `secure_zero_memory` for explicit byte clearing.
- constant-time byte equality/select helpers.
- fixed-width RSA Montgomery work on the NativeProvider private exponent path.
- fixed-limb P-256 backend pieces, including branch-free base-point table
  selection.
- RSA-PSS and RSA-OAEP checks that avoid early public padding exits in key
  paths where the code already tracks validity masks.
- Native AES-GCM tag verification, RSA-PSS expected-hash verification, and
  RSA-OAEP label-hash verification route through `constant_time_equal`.

## Known Limits

- BigInt-backed helpers still exist in some internal paths.
- RSA CRT recombination hardening is not complete.
- P-256 point formulas still have exceptional-case branches.
- DER/PEM/ASN.1 parsing is public-input parsing and is not constant-time.
- OpenSSL timing behavior depends on the linked OpenSSL build.
- No formal leakage testing, audit, or certification has been completed.

## Review Rule

Do not document an algorithm as constant-time unless all secret-dependent
branches, memory indexes, arithmetic widths, and error paths for that algorithm
have been reviewed and tested for that claim.

Until then, use narrower wording:

- "uses fixed-width helper in this path"
- "avoids early exit for this padding check"
- "constant-time certification is not claimed"
