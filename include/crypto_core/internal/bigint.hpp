#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace crypto_core::internal
{

class BigInt final
{
public:
	[[nodiscard]] static Result<BigInt> from_be_bytes(std::span<const std::uint8_t> bytes);

	[[nodiscard]] static Result<BigInt> mod_multiply(const BigInt &lhs, const BigInt &rhs, const BigInt &modulus);
	[[nodiscard]] static Result<BigInt> mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus);

	[[nodiscard]] ByteBuffer to_be_bytes() const;
	[[nodiscard]] bool is_zero() const noexcept;
	[[nodiscard]] int compare(const BigInt &other) const noexcept;

private:
	explicit BigInt(std::vector<std::uint32_t> limbs) noexcept;

	[[nodiscard]] static BigInt zero();
	[[nodiscard]] static BigInt one();

	void normalize() noexcept;
	[[nodiscard]] bool bit(std::size_t index) const noexcept;
	[[nodiscard]] std::size_t bit_length() const noexcept;
	[[nodiscard]] static int compare_limbs(std::span<const std::uint32_t> lhs, std::span<const std::uint32_t> rhs) noexcept;
	[[nodiscard]] static BigInt add(const BigInt &lhs, const BigInt &rhs);
	[[nodiscard]] static BigInt subtract(const BigInt &lhs, const BigInt &rhs);
	[[nodiscard]] static BigInt multiply(const BigInt &lhs, const BigInt &rhs);
	[[nodiscard]] static BigInt shift_left_bits(const BigInt &value, std::size_t bits);
	[[nodiscard]] static BigInt mod(const BigInt &value, const BigInt &modulus);

	std::vector<std::uint32_t> limbs_;
};

} // namespace crypto_core::internal
