# Contributing

`crypto-core` is experimental security-sensitive software. Keep changes small,
tested, and documented.

## Build And Test

Run the relevant native build and tests before reporting a change as complete:

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Run the OpenSSL-enabled build when provider behavior, differential tests, or
OpenSSL docs change.

## Security-Sensitive Changes

For changes touching crypto behavior, key material, parsing, RNG, nonces,
errors, logging, providers, or release artifacts:

- add or update negative tests.
- update known-answer or differential tests when behavior changes.
- update `docs/algorithm-status.md` for supported algorithm/provider changes.
- update `docs/security-model.md` for threat-model or misuse changes.
- update `docs/constant-time-notes.md` when secret-dependent control flow or
  comparison behavior changes.
- update `docs/release-notes.md` for security-relevant behavior changes.
- keep public errors coarse enough to avoid oracle behavior.

## Documentation

Docs and tests must move together for supported algorithms, parameters, formats,
provider capability reports, and release claims.

