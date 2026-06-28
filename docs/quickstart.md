# Quickstart

These examples show caller patterns, not production certification.

## Consumer CMake

```cmake
find_package(crypto_core CONFIG REQUIRED)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE crypto_core::crypto_core)
```

## SHA-256

```cpp
#include "crypto_core/crypto_core.hpp"

#include <array>
#include <cstdint>

std::array<std::uint8_t, 3> input{1, 2, 3};
auto digest = crypto_core::hash(crypto_core::HashAlgorithm::sha256, input);
if (!digest.has_value()) {
    return 1;
}
```

## AES-GCM

Use AES-GCM only with a nonce that is unique for the key. Never reuse an AES-GCM nonce with the same key.

Current low-level APIs require the caller to supply and persist the nonce and
tag. A future high-level helper may generate nonces through the provider RNG.

```cpp
auto &provider = crypto_core::default_provider();
// Call the AEAD API with a fresh nonce, AAD, plaintext, and key.
// Check Result<T> before using ciphertext or plaintext.
```

## Sign And Verify

RSA-PSS, ECDSA P-256, and Ed25519 return operation failures through `Result<T>`.
A parsed but bad signature is a successful verify operation with an invalid
verify result.

```cpp
auto verified = crypto_core::verify(provider, {algorithm, &public_key, signature}, message);
if (!verified.has_value()) {
    return 1;
}
if (!verified.value().is_valid()) {
    return 2;
}
```

## OpenSSLProvider

When built with OpenSSL support, `OpenSSLProvider` is optional. Use it for
compatibility checks and differential tests, not as a hidden global replacement.
See `docs/algorithm-status.md` for the exact provider matrix.
