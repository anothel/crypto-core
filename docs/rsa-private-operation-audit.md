# RSA Private-Operation Audit

## Scope

This note covers NativeProvider RSA private operations after the fixed-width RSA Montgomery work.

## Fixed-Width Paths

- RSA-PSS signing uses `rsa_private_crt_blinded_operation`.
- RSA-OAEP decrypt uses `rsa_private_crt_blinded_operation`.
- Internal unblinded CRT primitive uses fixed-width exponentiation for both CRT prime branches.
- CRT prime exponentiation uses `RsaFixedBigInt::montgomery_mod_exp_secret`.
- Fixed-width Montgomery core covers modular import, Montgomery multiply, Montgomery conversion, and fixed exponent ladder.

## Remaining Variable-Limb Boundaries

- Public RSA operations still use variable-limb `BigInt`; inputs and exponents are public.
- Non-CRT private fallback still uses variable-limb `BigInt`; NativeProvider private operations use CRT material, but this fallback remains an internal boundary.
- CRT recombination still uses variable-limb `BigInt`; it combines private branch results and has behavior coverage for identity, wraparound, and maximal representatives, but constant-time hardening is not claimed.
- RSA blinding setup still uses variable-limb operations for public-exponent blinding and modular inverse setup.
- DER parsing and key material storage remain byte-buffer based.

## Verification

- Native Debug full suite must pass.
- OpenSSL-enabled Debug full suite must pass when local OpenSSL is available.
- RSA primitive, provider, and reference vector targets must pass.

## Decision

RSA hardening can leave active P0. NativeProvider RSA-PSS signing and RSA-OAEP decrypt now route CRT private exponentiation through fixed-width Montgomery arithmetic. Remaining timing work is tracked as deferred hardening rather than blocking ECDSA P-256 work.

The CRT recombination roadmap slice is closed at behavior-test level only. A
future constant-time audit may still replace variable-limb recombination.
