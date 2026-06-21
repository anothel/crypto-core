#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core::internal
{

class RsaFixedBigInt final
{
public:
	static constexpr std::size_t kMaxLimbs = 64;

	[[nodiscard]] static Result<RsaFixedBigInt> zero(std::size_t width);
	[[nodiscard]] static Result<RsaFixedBigInt> from_be_bytes(std::span<const std::uint8_t> bytes, std::size_t width);

	[[nodiscard]] ByteBuffer to_be_bytes() const;
	[[nodiscard]] bool is_zero() const noexcept;
	[[nodiscard]] std::size_t width() const noexcept;

	[[nodiscard]] static Result<std::uint8_t> equal_mask(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs);
	[[nodiscard]] static Result<std::uint8_t> less_than_mask(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs);
	[[nodiscard]] static Result<RsaFixedBigInt> select(std::uint8_t mask, const RsaFixedBigInt &if_set, const RsaFixedBigInt &if_clear);
	[[nodiscard]] static Result<RsaFixedBigInt> add(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs);
	[[nodiscard]] static Result<RsaFixedBigInt> subtract(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs);

private:
	explicit RsaFixedBigInt(std::size_t width) noexcept;

	[[nodiscard]] static bool valid_width(std::size_t width) noexcept;
	[[nodiscard]] static Result<void> require_matching_widths(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs);

	std::array<std::uint32_t, kMaxLimbs> limbs_{};
	std::size_t width_{};
};

} // namespace crypto_core::internal
