#pragma once

#include "crypto_core/kdf.hpp"
#include "crypto_core/provider.hpp"

namespace crypto_core::internal
{

[[nodiscard]] Result<ByteBuffer> native_pbkdf2(
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> password,
    std::span<const std::uint8_t> salt,
    std::uint32_t iterations,
    std::size_t output_size) noexcept;

[[nodiscard]] Result<ByteBuffer> native_hkdf(
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> input_key_material,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::size_t output_size) noexcept;

} // namespace crypto_core::internal
