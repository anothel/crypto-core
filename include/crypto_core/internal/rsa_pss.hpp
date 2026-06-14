#pragma once

#include "crypto_core/asymmetric.hpp"
#include "crypto_core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<bool> emsa_pss_verify(std::span<const std::uint8_t> encoded_message, std::size_t encoded_bits, std::span<const std::uint8_t> message_hash, const RsaPssParams &params);

} // namespace crypto_core::internal
