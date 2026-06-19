#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

struct P256Point final
{
	ByteBuffer x;
	ByteBuffer y;
	bool infinity{false};
};

[[nodiscard]] P256Point p256_point_at_infinity() noexcept;
[[nodiscard]] Result<P256Point> p256_point_from_coordinates(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y);
[[nodiscard]] Result<P256Point> p256_base_point();
[[nodiscard]] Result<bool> p256_is_on_curve(const P256Point &point);
[[nodiscard]] Result<P256Point> p256_point_add(const P256Point &lhs, const P256Point &rhs);
[[nodiscard]] Result<P256Point> p256_scalar_multiply(std::span<const std::uint8_t> scalar, const P256Point &point);
[[nodiscard]] Result<P256Point> p256_base_point_multiply(std::span<const std::uint8_t> scalar);
[[nodiscard]] Result<ByteBuffer> p256_scalar_inverse(std::span<const std::uint8_t> scalar);
[[nodiscard]] Result<ByteBuffer> p256_scalar_multiply_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs);
[[nodiscard]] Result<ByteBuffer> p256_x_mod_order(const P256Point &point);
[[nodiscard]] std::span<const std::uint8_t> p256_group_order() noexcept;

} // namespace crypto_core::internal
