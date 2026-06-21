#include "crypto_core/internal/rsa_fixed_bigint.hpp"

#include "crypto_core/error.hpp"

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

} // namespace crypto_core::internal
