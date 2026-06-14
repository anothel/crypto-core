#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/internal/rsa_der.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<ByteBuffer> rsa_public_operation(const RsaPublicKeyMaterial &key, std::span<const std::uint8_t> input);

[[nodiscard]] Result<ByteBuffer> rsa_private_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input);

} // namespace crypto_core::internal
