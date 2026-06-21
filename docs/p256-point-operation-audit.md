# P-256 Point Operation Audit

## Status

Native ECDSA P-256 uses the fixed-limb P-256 backend for sign and verify.
Current hardening delivered:

- fixed-size P-256 field/scalar storage
- fixed-base window selector without secret table indexing
- branch-free generic scalar-bit ladder selection
- RFC 6979 fixed scalar reduction
- external-style valid and invalid ECDSA vectors

## Accepted Public Branches

The following branches are on public input or validation state and are accepted
for the current 0.x native engine:

- public point import and on-curve validation
- public `p256_fixed_point_add()` identity, doubling, and inverse cases
- DER/key/signature parser rejection behavior

These paths validate external data. They are not treated as private-scalar
control flow.

## Remaining Timing Boundary

Fixed P-256 scalar multiplication no longer branches directly on the scalar bit.
It still uses point formulas with exceptional-case handling:

- Jacobian doubling returns infinity for infinity or `y == 0`
- Jacobian mixed addition handles infinity, same-point, and inverse-point cases
- affine conversion returns early for infinity

In ECDSA verify, scalars and public points are not private signing secrets.
In ECDSA sign, the fixed-base path is used for nonce multiplication; its table
selection is masked, but the point formula layer has not been converted to a
complete, formally constant-time formula set.

## Decision

This closes the active P-256 hardening slice for the current roadmap because the
remaining boundary is explicit and tested at behavior level. A future hardening
slice may replace point formulas with complete formulas and run a full
constant-time audit.
