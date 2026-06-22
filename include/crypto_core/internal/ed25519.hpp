#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<bool> verify_ed25519(std::span<const std::uint8_t> public_key, std::span<const std::uint8_t> signature, std::span<const std::uint8_t> message);
[[nodiscard]] Result<ByteBuffer> sign_ed25519_seed(std::span<const std::uint8_t> seed, std::span<const std::uint8_t> message);

} // namespace crypto_core::internal
