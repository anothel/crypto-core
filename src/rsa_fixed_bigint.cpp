#include "crypto_core/internal/rsa_fixed_bigint.hpp"

#include "crypto_core/error.hpp"

#include <array>
#include <cstddef>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto_core::internal
{
namespace
{

[[nodiscard]] Error fixed_error(std::string_view message) noexcept
{
	return make_error(ErrorCode::invalid_argument, "rsa_fixed_bigint", message);
}

[[nodiscard]] std::uint32_t word_mask_from_byte(std::uint8_t mask) noexcept
{
	return std::uint32_t{0} - static_cast<std::uint32_t>((mask >> 7U) & 1U);
}

[[nodiscard]] std::uint32_t word_less_than_mask(std::uint32_t lhs, std::uint32_t rhs) noexcept
{
	return std::uint32_t{0} - static_cast<std::uint32_t>(lhs < rhs);
}

[[nodiscard]] std::uint8_t byte_mask_from_word(std::uint32_t mask) noexcept
{
	return static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>((mask >> 31U) & 1U));
}

[[nodiscard]] std::uint32_t word_non_zero_mask(std::uint32_t value) noexcept
{
	const auto non_zero = value | (std::uint32_t{0} - value);
	return std::uint32_t{0} - ((non_zero >> 31U) & 1U);
}

template <std::size_t Size>
void add_carry(std::array<std::uint32_t, Size> &limbs, std::size_t index, std::uint64_t carry) noexcept
{
	while (carry != 0 && index < Size)
	{
		const auto sum = static_cast<std::uint64_t>(limbs[index]) + carry;
		limbs[index] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
		++index;
	}
}

} // namespace

RsaFixedBigInt::RsaFixedBigInt(std::size_t width) noexcept
    : width_(width)
{
}

Result<RsaFixedBigInt> RsaFixedBigInt::zero(std::size_t width)
{
	if (!valid_width(width))
	{
		return Result<RsaFixedBigInt>::failure(fixed_error("RSA fixed integer width is invalid"));
	}

	return Result<RsaFixedBigInt>::success(RsaFixedBigInt(width));
}

Result<RsaFixedBigInt> RsaFixedBigInt::from_be_bytes(std::span<const std::uint8_t> bytes, std::size_t width)
{
	if (!valid_width(width))
	{
		return Result<RsaFixedBigInt>::failure(fixed_error("RSA fixed integer width is invalid"));
	}

	const auto byte_width = width * 4U;
	while (bytes.size() > byte_width && !bytes.empty() && bytes.front() == 0)
	{
		bytes = bytes.subspan(1);
	}
	if (bytes.size() > byte_width)
	{
		return Result<RsaFixedBigInt>::failure(fixed_error("RSA fixed integer input exceeds width"));
	}

	RsaFixedBigInt output(width);
	std::size_t byte_index = bytes.size();
	for (std::size_t limb_index = 0; limb_index < width; ++limb_index)
	{
		std::uint32_t limb = 0;
		for (std::size_t i = 0; i < 4 && byte_index > 0; ++i)
		{
			--byte_index;
			limb |= static_cast<std::uint32_t>(bytes[byte_index]) << (i * 8U);
		}
		output.limbs_[limb_index] = limb;
	}

	return Result<RsaFixedBigInt>::success(output);
}

Result<RsaFixedBigInt> RsaFixedBigInt::from_be_bytes_mod(std::span<const std::uint8_t> bytes, const RsaFixedBigInt &modulus)
{
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<RsaFixedBigInt>::failure(valid_modulus.error());
	}

	RsaFixedBigInt output(modulus.width_);
	for (const auto byte : bytes)
	{
		for (std::size_t bit = 8U; bit > 0; --bit)
		{
			output = double_mod(output, modulus);
			const auto incremented = add_one_mod(output, modulus);
			const auto mask = static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>((byte >> (bit - 1U)) & 1U));
			auto selected = select(mask, incremented, output);
			if (!selected)
			{
				return Result<RsaFixedBigInt>::failure(selected.error());
			}
			output = std::move(selected.value());
		}
	}

	return Result<RsaFixedBigInt>::success(output);
}

ByteBuffer RsaFixedBigInt::to_be_bytes() const
{
	std::vector<std::uint8_t> bytes(width_ * 4U);
	for (std::size_t limb_index = 0; limb_index < width_; ++limb_index)
	{
		const auto limb = limbs_[limb_index];
		const auto offset = (width_ - limb_index - 1U) * 4U;
		bytes[offset] = static_cast<std::uint8_t>((limb >> 24U) & 0xFFU);
		bytes[offset + 1U] = static_cast<std::uint8_t>((limb >> 16U) & 0xFFU);
		bytes[offset + 2U] = static_cast<std::uint8_t>((limb >> 8U) & 0xFFU);
		bytes[offset + 3U] = static_cast<std::uint8_t>(limb & 0xFFU);
	}

	return ByteBuffer(std::move(bytes));
}

bool RsaFixedBigInt::is_zero() const noexcept
{
	std::uint32_t diff = 0;
	for (std::size_t i = 0; i < width_; ++i)
	{
		diff |= limbs_[i];
	}

	return diff == 0;
}

std::size_t RsaFixedBigInt::width() const noexcept
{
	return width_;
}

Result<std::uint8_t> RsaFixedBigInt::equal_mask(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs)
{
	auto widths = require_matching_widths(lhs, rhs);
	if (!widths)
	{
		return Result<std::uint8_t>::failure(widths.error());
	}

	std::uint32_t diff = 0;
	for (std::size_t i = 0; i < lhs.width_; ++i)
	{
		diff |= lhs.limbs_[i] ^ rhs.limbs_[i];
	}
	const auto non_zero = diff | (std::uint32_t{0} - diff);
	const auto is_zero = ((non_zero >> 31U) ^ 1U) & 1U;
	return Result<std::uint8_t>::success(static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>(is_zero)));
}

Result<std::uint8_t> RsaFixedBigInt::less_than_mask(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs)
{
	auto widths = require_matching_widths(lhs, rhs);
	if (!widths)
	{
		return Result<std::uint8_t>::failure(widths.error());
	}

	std::uint32_t less = 0;
	std::uint32_t greater = 0;
	for (std::size_t i = lhs.width_; i > 0; --i)
	{
		const auto left = lhs.limbs_[i - 1U];
		const auto right = rhs.limbs_[i - 1U];
		const auto undecided = ~(less | greater);
		less |= undecided & word_less_than_mask(left, right);
		greater |= undecided & word_less_than_mask(right, left);
	}

	return Result<std::uint8_t>::success(byte_mask_from_word(less));
}

Result<RsaFixedBigInt> RsaFixedBigInt::select(std::uint8_t mask, const RsaFixedBigInt &if_set, const RsaFixedBigInt &if_clear)
{
	auto widths = require_matching_widths(if_set, if_clear);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}

	const auto word_mask = word_mask_from_byte(mask);
	RsaFixedBigInt output(if_set.width_);
	for (std::size_t i = 0; i < if_set.width_; ++i)
	{
		output.limbs_[i] = (if_set.limbs_[i] & word_mask) | (if_clear.limbs_[i] & ~word_mask);
	}

	return Result<RsaFixedBigInt>::success(output);
}

Result<RsaFixedBigInt> RsaFixedBigInt::add(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs)
{
	auto widths = require_matching_widths(lhs, rhs);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}

	RsaFixedBigInt output(lhs.width_);
	std::uint64_t carry = 0;
	for (std::size_t i = 0; i < lhs.width_; ++i)
	{
		const auto sum = static_cast<std::uint64_t>(lhs.limbs_[i]) + rhs.limbs_[i] + carry;
		output.limbs_[i] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
	}

	return Result<RsaFixedBigInt>::success(output);
}

Result<RsaFixedBigInt> RsaFixedBigInt::subtract(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs)
{
	auto widths = require_matching_widths(lhs, rhs);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}

	RsaFixedBigInt output(lhs.width_);
	std::uint64_t borrow = 0;
	for (std::size_t i = 0; i < lhs.width_; ++i)
	{
		const auto left = static_cast<std::uint64_t>(lhs.limbs_[i]);
		const auto right = static_cast<std::uint64_t>(rhs.limbs_[i]) + borrow;
		output.limbs_[i] = static_cast<std::uint32_t>(left - right);
		borrow = static_cast<std::uint64_t>(left < right);
	}

	return Result<RsaFixedBigInt>::success(output);
}

Result<std::uint32_t> RsaFixedBigInt::montgomery_n0_inverse(const RsaFixedBigInt &modulus)
{
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<std::uint32_t>::failure(valid_modulus.error());
	}

	std::uint32_t inverse = 1;
	for (int i = 0; i < 5; ++i)
	{
		inverse *= 2U - (modulus.limbs_[0] * inverse);
	}

	return Result<std::uint32_t>::success(std::uint32_t{0} - inverse);
}

Result<RsaFixedBigInt> RsaFixedBigInt::montgomery_r_squared(const RsaFixedBigInt &modulus)
{
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<RsaFixedBigInt>::failure(valid_modulus.error());
	}

	RsaFixedBigInt result(modulus.width_);
	result.limbs_[0] = 1;
	auto reduced = require_reduced_value(result, modulus);
	if (!reduced)
	{
		return Result<RsaFixedBigInt>::failure(reduced.error());
	}

	const auto bit_width = modulus.width_ * 32U;
	for (std::size_t i = 0; i < bit_width * 2U; ++i)
	{
		result = double_mod(result, modulus);
	}

	return Result<RsaFixedBigInt>::success(result);
}

Result<RsaFixedBigInt> RsaFixedBigInt::montgomery_multiply(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs, const RsaFixedBigInt &modulus)
{
	auto widths = require_matching_widths(lhs, rhs);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}
	widths = require_matching_widths(lhs, modulus);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<RsaFixedBigInt>::failure(valid_modulus.error());
	}
	auto lhs_reduced = require_reduced_value(lhs, modulus);
	if (!lhs_reduced)
	{
		return Result<RsaFixedBigInt>::failure(lhs_reduced.error());
	}
	auto rhs_reduced = require_reduced_value(rhs, modulus);
	if (!rhs_reduced)
	{
		return Result<RsaFixedBigInt>::failure(rhs_reduced.error());
	}
	auto inverse = montgomery_n0_inverse(modulus);
	if (!inverse)
	{
		return Result<RsaFixedBigInt>::failure(inverse.error());
	}

	std::array<std::uint32_t, (2U * kMaxLimbs) + 2U> accumulator{};
	const auto width = modulus.width_;
	for (std::size_t i = 0; i < width; ++i)
	{
		std::uint64_t carry = 0;
		for (std::size_t j = 0; j < width; ++j)
		{
			const auto index = i + j;
			const auto product =
			    static_cast<std::uint64_t>(lhs.limbs_[i]) * rhs.limbs_[j] + accumulator[index] + carry;
			accumulator[index] = static_cast<std::uint32_t>(product);
			carry = product >> 32U;
		}
		add_carry(accumulator, i + width, carry);
	}

	for (std::size_t i = 0; i < width; ++i)
	{
		const auto factor = static_cast<std::uint32_t>(accumulator[i] * inverse.value());
		std::uint64_t carry = 0;
		for (std::size_t j = 0; j < width; ++j)
		{
			const auto index = i + j;
			const auto product =
			    static_cast<std::uint64_t>(factor) * modulus.limbs_[j] + accumulator[index] + carry;
			accumulator[index] = static_cast<std::uint32_t>(product);
			carry = product >> 32U;
		}
		add_carry(accumulator, i + width, carry);
	}

	RsaFixedBigInt reduced(width);
	for (std::size_t i = 0; i < width; ++i)
	{
		reduced.limbs_[i] = accumulator[width + i];
	}
	const auto high_limb = accumulator[2U * width] | accumulator[(2U * width) + 1U];
	return Result<RsaFixedBigInt>::success(subtract_modulus_if_needed(reduced, modulus, high_limb));
}

Result<RsaFixedBigInt> RsaFixedBigInt::to_montgomery(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus)
{
	auto widths = require_matching_widths(value, modulus);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<RsaFixedBigInt>::failure(valid_modulus.error());
	}
	auto reduced = require_reduced_value(value, modulus);
	if (!reduced)
	{
		return Result<RsaFixedBigInt>::failure(reduced.error());
	}

	auto output = value;
	const auto bit_width = value.width_ * 32U;
	for (std::size_t i = 0; i < bit_width; ++i)
	{
		output = double_mod(output, modulus);
	}

	return Result<RsaFixedBigInt>::success(output);
}

Result<RsaFixedBigInt> RsaFixedBigInt::from_montgomery(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus)
{
	auto widths = require_matching_widths(value, modulus);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}

	RsaFixedBigInt one(value.width_);
	one.limbs_[0] = 1;
	return montgomery_multiply(value, one, modulus);
}

Result<RsaFixedBigInt> RsaFixedBigInt::montgomery_mod_exp_secret(const RsaFixedBigInt &base, std::span<const std::uint8_t> exponent, const RsaFixedBigInt &modulus, std::size_t exponent_bits)
{
	auto widths = require_matching_widths(base, modulus);
	if (!widths)
	{
		return Result<RsaFixedBigInt>::failure(widths.error());
	}
	auto valid_modulus = require_montgomery_modulus(modulus);
	if (!valid_modulus)
	{
		return Result<RsaFixedBigInt>::failure(valid_modulus.error());
	}
	auto reduced = require_reduced_value(base, modulus);
	if (!reduced)
	{
		return Result<RsaFixedBigInt>::failure(reduced.error());
	}

	RsaFixedBigInt one(base.width_);
	one.limbs_[0] = 1;
	auto r0 = to_montgomery(one, modulus);
	auto r1 = to_montgomery(base, modulus);
	if (!r0)
	{
		return Result<RsaFixedBigInt>::failure(r0.error());
	}
	if (!r1)
	{
		return Result<RsaFixedBigInt>::failure(r1.error());
	}

	for (std::size_t i = exponent_bits; i > 0; --i)
	{
		auto product = montgomery_multiply(r0.value(), r1.value(), modulus);
		auto r0_squared = montgomery_multiply(r0.value(), r0.value(), modulus);
		auto r1_squared = montgomery_multiply(r1.value(), r1.value(), modulus);
		if (!product)
		{
			return Result<RsaFixedBigInt>::failure(product.error());
		}
		if (!r0_squared)
		{
			return Result<RsaFixedBigInt>::failure(r0_squared.error());
		}
		if (!r1_squared)
		{
			return Result<RsaFixedBigInt>::failure(r1_squared.error());
		}

		const auto mask = static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>(exponent_bit(exponent, i - 1U)));
		auto selected_r0 = select(mask, product.value(), r0_squared.value());
		auto selected_r1 = select(mask, r1_squared.value(), product.value());
		if (!selected_r0)
		{
			return Result<RsaFixedBigInt>::failure(selected_r0.error());
		}
		if (!selected_r1)
		{
			return Result<RsaFixedBigInt>::failure(selected_r1.error());
		}
		r0 = std::move(selected_r0);
		r1 = std::move(selected_r1);
	}

	return from_montgomery(r0.value(), modulus);
}

bool RsaFixedBigInt::valid_width(std::size_t width) noexcept
{
	return width > 0 && width <= kMaxLimbs;
}

Result<void> RsaFixedBigInt::require_matching_widths(const RsaFixedBigInt &lhs, const RsaFixedBigInt &rhs)
{
	if (lhs.width_ != rhs.width_)
	{
		return Result<void>::failure(fixed_error("RSA fixed integer widths do not match"));
	}

	return Result<void>::success();
}

Result<void> RsaFixedBigInt::require_montgomery_modulus(const RsaFixedBigInt &modulus)
{
	if (modulus.is_zero() || (modulus.limbs_[0] & 1U) == 0U)
	{
		return Result<void>::failure(fixed_error("RSA fixed Montgomery modulus must be non-zero and odd"));
	}
	std::uint32_t remaining = 0;
	for (std::size_t i = 1; i < modulus.width_; ++i)
	{
		remaining |= modulus.limbs_[i];
	}
	if (modulus.limbs_[0] == 1U && remaining == 0U)
	{
		return Result<void>::failure(fixed_error("RSA fixed Montgomery modulus must be greater than one"));
	}

	return Result<void>::success();
}

Result<void> RsaFixedBigInt::require_reduced_value(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus)
{
	auto widths = require_matching_widths(value, modulus);
	if (!widths)
	{
		return widths;
	}

	auto less = less_than_mask(value, modulus);
	if (!less)
	{
		return Result<void>::failure(less.error());
	}
	if (less.value() != 0xFFU)
	{
		return Result<void>::failure(fixed_error("RSA fixed Montgomery value must be reduced modulo modulus"));
	}

	return Result<void>::success();
}

bool RsaFixedBigInt::exponent_bit(std::span<const std::uint8_t> exponent, std::size_t bit_index) noexcept
{
	const auto byte_from_end = bit_index / 8U;
	if (byte_from_end >= exponent.size())
	{
		return false;
	}
	const auto byte = exponent[exponent.size() - byte_from_end - 1U];
	return ((byte >> (bit_index % 8U)) & 1U) != 0U;
}

RsaFixedBigInt RsaFixedBigInt::add_one_mod(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus)
{
	RsaFixedBigInt output(value.width_);
	std::uint64_t carry = 1;
	for (std::size_t i = 0; i < value.width_; ++i)
	{
		const auto sum = static_cast<std::uint64_t>(value.limbs_[i]) + carry;
		output.limbs_[i] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
	}

	return subtract_modulus_if_needed(output, modulus, static_cast<std::uint32_t>(carry));
}

RsaFixedBigInt RsaFixedBigInt::double_mod(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus)
{
	RsaFixedBigInt doubled(value.width_);
	std::uint64_t carry = 0;
	for (std::size_t i = 0; i < value.width_; ++i)
	{
		const auto sum = (static_cast<std::uint64_t>(value.limbs_[i]) << 1U) + carry;
		doubled.limbs_[i] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
	}

	return subtract_modulus_if_needed(doubled, modulus, static_cast<std::uint32_t>(carry));
}

RsaFixedBigInt RsaFixedBigInt::subtract_modulus_if_needed(const RsaFixedBigInt &value, const RsaFixedBigInt &modulus, std::uint32_t high_limb)
{
	auto difference = subtract(value, modulus);
	auto less = less_than_mask(value, modulus);
	const auto high_mask = byte_mask_from_word(word_non_zero_mask(high_limb));
	const auto subtract_mask = static_cast<std::uint8_t>(high_mask | static_cast<std::uint8_t>(~less.value()));
	auto selected = select(subtract_mask, difference.value(), value);
	return std::move(selected.value());
}

} // namespace crypto_core::internal
