#pragma once

#include "crypto_core/asymmetric.hpp"
#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<ByteBuffer> eme_oaep_encode(std::size_t encoded_size, std::span<const std::uint8_t> message, std::span<const std::uint8_t> seed, const RsaOaepParams &params);

[[nodiscard]] Result<ByteBuffer> eme_oaep_decode(std::span<const std::uint8_t> encoded_message, const RsaOaepParams &params);

} // namespace crypto_core::internal
