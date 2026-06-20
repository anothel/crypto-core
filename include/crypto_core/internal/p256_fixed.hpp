#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/internal/p256.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

[[nodiscard]] Result<P256Point> p256_fixed_point_from_coordinates(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y);
[[nodiscard]] Result<bool> p256_fixed_is_on_curve(const P256Point &point);
[[nodiscard]] Result<P256Point> p256_fixed_point_add(const P256Point &lhs, const P256Point &rhs);
[[nodiscard]] Result<P256Point> p256_fixed_scalar_multiply(std::span<const std::uint8_t> scalar, const P256Point &point);
[[nodiscard]] Result<P256Point> p256_fixed_base_point_multiply(std::span<const std::uint8_t> scalar);
[[nodiscard]] Result<ByteBuffer> p256_fixed_scalar_inverse(std::span<const std::uint8_t> scalar);
[[nodiscard]] Result<ByteBuffer> p256_fixed_scalar_add_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs);
[[nodiscard]] Result<ByteBuffer> p256_fixed_scalar_multiply_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs);
[[nodiscard]] Result<ByteBuffer> p256_fixed_scalar_reduce_fixed_32(std::span<const std::uint8_t> scalar);
[[nodiscard]] Result<ByteBuffer> p256_fixed_x_mod_order(const P256Point &point);
[[nodiscard]] Result<bool> p256_fixed_scalar_is_valid_nonzero(std::span<const std::uint8_t> scalar);

} // namespace crypto_core::internal
