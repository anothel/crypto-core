#pragma once

#include "crypto_core/aead.hpp"

namespace crypto_core::internal
{

[[nodiscard]] Result<AeadEncryptResult> aes_gcm_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
[[nodiscard]] Result<ByteBuffer> aes_gcm_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;

} // namespace crypto_core::internal
