# Crypto Envelope Format

`crypto-core` currently exposes primitive/provider APIs. A stable application
envelope format is not implemented yet. This document defines the format
contract future envelope helpers must follow.

## Versioned Envelope

New encryption must emit only the latest envelope version. Decryption may keep
read-only support for older versions when migration requires it.

Canonical JSON field names:

```json
{
  "v": 1,
  "suite": "AES-256-GCM",
  "kid": "local:example-key:2026-06",
  "nonce": "base64url",
  "aad": "base64url-or-context-id",
  "ct": "base64url",
  "tag": "base64url"
}
```

## Required Fields

- `v`: integer envelope version
- `suite`: algorithm suite selected by policy
- `kid`: key identifier or resolver handle
- `nonce`: nonce or IV encoded separately from ciphertext
- `aad`: associated data or context identifier
- `ct`: ciphertext
- `tag`: authentication tag for AEAD modes

## Compatibility Rules

- Unknown versions must reject deterministically.
- Unknown suites must reject deterministically.
- Deprecated versions are read-only.
- Base64url encoding must be explicit; do not mix padded base64, hex, and
  base64url in one format.
- Golden file tests are required before shipping an envelope implementation.

## Non-Goals

- No JSON parser is added by this document.
- No KMS, HSM, or Secret Manager integration is added by this document.
- No backwards compatibility is promised for formats not documented here.
