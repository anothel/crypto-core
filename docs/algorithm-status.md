# Algorithm Status

Status labels:

- `experimental`: implemented and tested, but not production-certified
- `verify-only`: verification works, signing is not implemented
- `planned`: tracked but not implemented
- `deferred`: intentionally later
- `unsupported`: not planned for 0.x/1.x unless required

## NativeProvider

| Area | Algorithm | Native operation status | Notes |
|---|---|---|---|
| Hash | SHA-256 | experimental | one-shot and streaming context |
| Hash | SHA-512 | experimental | one-shot and streaming context |
| MAC | HMAC-SHA256 | experimental | streaming context |
| MAC | HMAC-SHA512 | experimental | streaming context |
| KDF | PBKDF2-HMAC-SHA256 | experimental | native |
| KDF | PBKDF2-HMAC-SHA512 | experimental | native |
| KDF | HKDF-SHA256 | experimental | native |
| KDF | HKDF-SHA512 | experimental | native |
| Cipher | AES-CBC | experimental | AES-128/192/256 |
| AEAD | AES-GCM | experimental | AES-128/192/256 |
| RNG | OS RNG | experimental | Windows `BCryptGenRandom`, Linux `getrandom`, Apple `SecRandomCopyBytes`, BSD `arc4random_buf`; cross-platform CI queued |
| Signature | RSA-PSS | sign + verify experimental | RSA-2048 current native focus |
| Signature | ECDSA P-256 | sign + verify experimental | fixed-limb backend; hardening notes tracked |
| Signature | Ed25519 | sign + verify experimental | raw 32-byte public keys and private seeds |
| Encryption | RSA-OAEP | encrypt + decrypt experimental | RSA-2048 current native focus |
| Key import | Ed25519 raw public key | experimental | `PublicKey::import_raw_ed25519` validates 32-byte raw keys |
| Key import | Ed25519 raw private seed | experimental | `PrivateKey::import_raw_ed25519_seed` validates 32-byte seeds |
| Key import | DER/SPKI/PKCS#8 | planned | current `import_der` is compatibility wrapper, not full parser |
| Keygen | RSA/ECDSA/Ed25519 | planned | operation-level capability reports false for NativeProvider |
| Key agreement | ECDH | planned/deferred | no active 0.x goal |

## OpenSSLProvider

| Area | Algorithm | OpenSSL operation status | Notes |
|---|---|---|---|
| Hash | SHA-256/SHA-512 | experimental | optional provider |
| MAC | HMAC-SHA256/HMAC-SHA512 | experimental | optional provider |
| KDF | PBKDF2/HKDF SHA-2 variants | experimental | optional provider |
| Signature | RSA-PSS | sign + verify experimental | differential oracle |
| Signature | ECDSA P-256 | sign + verify experimental | differential oracle |
| Signature | Ed25519 | planned | differential path queued |
| Encryption | RSA-OAEP | encrypt + decrypt experimental | optional provider |
| Keygen | RSA/ECDSA P-256 | experimental | optional provider |

## Explicit Non-Goals For Now

- DES, RC2, RC4, MD5, SHA-1
- TLS protocol implementation
- certificate chain validation
- mutable global provider registry
- formal constant-time certification
