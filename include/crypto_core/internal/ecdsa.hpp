#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<ByteBuffer> sign_ecdsa_p256_sha256_digest(std::span<const std::uint8_t> private_key_der, std::span<const std::uint8_t> digest);
[[nodiscard]] Result<bool> verify_ecdsa_p256_sha256_digest(std::span<const std::uint8_t> public_key_der, std::span<const std::uint8_t> signature_der, std::span<const std::uint8_t> digest);

} // namespace crypto_core::internal
