#include "crypto_core/internal/bigint.hpp"

#include "crypto_core/error.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace crypto_core::internal
{

BigInt::BigInt(std::vector<std::uint32_t> limbs) noexcept
    : limbs_(std::move(limbs))
{
	normalize();
}

Result<BigInt> BigInt::from_be_bytes(std::span<const std::uint8_t> bytes)
{
	while (!bytes.empty() && bytes.front() == 0)
	{
		bytes = bytes.subspan(1);
	}
	if (bytes.empty())
	{
		return Result<BigInt>::success(zero());
	}

	std::vector<std::uint32_t> limbs((bytes.size() + 3U) / 4U);
	std::size_t byte_index = bytes.size();
	for (std::size_t limb_index = 0; limb_index < limbs.size(); ++limb_index)
	{
		std::uint32_t limb = 0;
		for (std::size_t i = 0; i < 4 && byte_index > 0; ++i)
		{
			--byte_index;
			limb |= static_cast<std::uint32_t>(bytes[byte_index]) << (i * 8U);
		}
		limbs[limb_index] = limb;
	}

	return Result<BigInt>::success(BigInt(std::move(limbs)));
}

Result<BigInt> BigInt::mod_multiply(const BigInt &lhs, const BigInt &rhs, const BigInt &modulus)
{
	if (modulus.is_zero())
	{
		return Result<BigInt>::failure(make_error(ErrorCode::invalid_argument, "bigint", "modulus must be non-zero"));
	}

	return Result<BigInt>::success(mod(multiply(mod(lhs, modulus), mod(rhs, modulus)), modulus));
}

Result<BigInt> BigInt::mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus)
{
	if (modulus.is_zero())
	{
		return Result<BigInt>::failure(make_error(ErrorCode::invalid_argument, "bigint", "modulus must be non-zero"));
	}

	auto result = mod(one(), modulus);
	auto power = mod(base, modulus);
	const auto bits = exponent.bit_length();
	for (std::size_t i = 0; i < bits; ++i)
	{
		if (exponent.bit(i))
		{
			result = mod(multiply(result, power), modulus);
		}
		power = mod(multiply(power, power), modulus);
	}

	return Result<BigInt>::success(std::move(result));
}

ByteBuffer BigInt::to_be_bytes() const
{
	if (is_zero())
	{
		return ByteBuffer(std::vector<std::uint8_t>{0});
	}

	std::vector<std::uint8_t> bytes;
	bytes.reserve(limbs_.size() * 4U);
	for (std::size_t reverse_index = limbs_.size(); reverse_index > 0; --reverse_index)
	{
		const auto limb = limbs_[reverse_index - 1U];
		for (int shift = 24; shift >= 0; shift -= 8)
		{
			const auto byte = static_cast<std::uint8_t>((limb >> static_cast<std::uint32_t>(shift)) & 0xFFU);
			if (!bytes.empty() || byte != 0)
			{
				bytes.push_back(byte);
			}
		}
	}

	return ByteBuffer(std::move(bytes));
}

bool BigInt::is_zero() const noexcept
{
	return limbs_.empty();
}

int BigInt::compare(const BigInt &other) const noexcept
{
	return compare_limbs(limbs_, other.limbs_);
}

BigInt BigInt::zero()
{
	return BigInt(std::vector<std::uint32_t>{});
}

BigInt BigInt::one()
{
	return BigInt(std::vector<std::uint32_t>{1});
}

void BigInt::normalize() noexcept
{
	while (!limbs_.empty() && limbs_.back() == 0)
	{
		limbs_.pop_back();
	}
}

bool BigInt::bit(std::size_t index) const noexcept
{
	const auto limb_index = index / 32U;
	const auto bit_index = index % 32U;
	if (limb_index >= limbs_.size())
	{
		return false;
	}

	return ((limbs_[limb_index] >> bit_index) & 1U) != 0U;
}

std::size_t BigInt::bit_length() const noexcept
{
	if (limbs_.empty())
	{
		return 0;
	}

	const auto high = limbs_.back();
	std::size_t bits = (limbs_.size() - 1U) * 32U;
	for (int bit_index = 31; bit_index >= 0; --bit_index)
	{
		if (((high >> static_cast<std::uint32_t>(bit_index)) & 1U) != 0U)
		{
			return bits + static_cast<std::size_t>(bit_index) + 1U;
		}
	}

	return bits;
}

int BigInt::compare_limbs(std::span<const std::uint32_t> lhs, std::span<const std::uint32_t> rhs) noexcept
{
	while (!lhs.empty() && lhs.back() == 0)
	{
		lhs = lhs.first(lhs.size() - 1U);
	}
	while (!rhs.empty() && rhs.back() == 0)
	{
		rhs = rhs.first(rhs.size() - 1U);
	}
	if (lhs.size() < rhs.size())
	{
		return -1;
	}
	if (lhs.size() > rhs.size())
	{
		return 1;
	}
	for (std::size_t i = lhs.size(); i > 0; --i)
	{
		if (lhs[i - 1U] < rhs[i - 1U])
		{
			return -1;
		}
		if (lhs[i - 1U] > rhs[i - 1U])
		{
			return 1;
		}
	}

	return 0;
}

BigInt BigInt::add(const BigInt &lhs, const BigInt &rhs)
{
	std::vector<std::uint32_t> output(std::max(lhs.limbs_.size(), rhs.limbs_.size()) + 1U);
	std::uint64_t carry = 0;
	for (std::size_t i = 0; i < output.size(); ++i)
	{
		const auto left = i < lhs.limbs_.size() ? lhs.limbs_[i] : 0U;
		const auto right = i < rhs.limbs_.size() ? rhs.limbs_[i] : 0U;
		const auto sum = static_cast<std::uint64_t>(left) + right + carry;
		output[i] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
	}

	return BigInt(std::move(output));
}

BigInt BigInt::subtract(const BigInt &lhs, const BigInt &rhs)
{
	std::vector<std::uint32_t> output(lhs.limbs_.size());
	std::uint64_t borrow = 0;
	for (std::size_t i = 0; i < lhs.limbs_.size(); ++i)
	{
		const auto left = static_cast<std::uint64_t>(lhs.limbs_[i]);
		const auto right = static_cast<std::uint64_t>(i < rhs.limbs_.size() ? rhs.limbs_[i] : 0U) + borrow;
		if (left >= right)
		{
			output[i] = static_cast<std::uint32_t>(left - right);
			borrow = 0;
		}
		else
		{
			output[i] = static_cast<std::uint32_t>((std::uint64_t{1} << 32U) + left - right);
			borrow = 1;
		}
	}

	return BigInt(std::move(output));
}

BigInt BigInt::multiply(const BigInt &lhs, const BigInt &rhs)
{
	if (lhs.is_zero() || rhs.is_zero())
	{
		return zero();
	}

	std::vector<std::uint32_t> output(lhs.limbs_.size() + rhs.limbs_.size() + 1U);
	for (std::size_t i = 0; i < lhs.limbs_.size(); ++i)
	{
		std::uint64_t carry = 0;
		for (std::size_t j = 0; j < rhs.limbs_.size(); ++j)
		{
			const auto index = i + j;
			const auto product = static_cast<std::uint64_t>(lhs.limbs_[i]) * rhs.limbs_[j] + output[index] + carry;
			output[index] = static_cast<std::uint32_t>(product);
			carry = product >> 32U;
		}

		std::size_t index = i + rhs.limbs_.size();
		while (carry != 0)
		{
			const auto sum = static_cast<std::uint64_t>(output[index]) + carry;
			output[index] = static_cast<std::uint32_t>(sum);
			carry = sum >> 32U;
			++index;
		}
	}

	return BigInt(std::move(output));
}

BigInt BigInt::shift_left_bits(const BigInt &value, std::size_t bits)
{
	if (value.is_zero())
	{
		return zero();
	}

	const auto limb_shift = bits / 32U;
	const auto bit_shift = bits % 32U;
	std::vector<std::uint32_t> output(value.limbs_.size() + limb_shift + 1U);
	std::uint64_t carry = 0;
	for (std::size_t i = 0; i < value.limbs_.size(); ++i)
	{
		const auto shifted = (static_cast<std::uint64_t>(value.limbs_[i]) << bit_shift) | carry;
		output[i + limb_shift] = static_cast<std::uint32_t>(shifted);
		carry = shifted >> 32U;
	}
	output[value.limbs_.size() + limb_shift] = static_cast<std::uint32_t>(carry);

	return BigInt(std::move(output));
}

BigInt BigInt::mod(const BigInt &value, const BigInt &modulus)
{
	auto remainder = value;
	if (modulus.is_zero() || remainder.compare(modulus) < 0)
	{
		return remainder;
	}

	const auto modulus_bits = modulus.bit_length();
	while (remainder.compare(modulus) >= 0)
	{
		auto shift = remainder.bit_length() - modulus_bits;
		auto shifted = shift_left_bits(modulus, shift);
		if (shifted.compare(remainder) > 0)
		{
			--shift;
			shifted = shift_left_bits(modulus, shift);
		}
		remainder = subtract(remainder, shifted);
	}

	return remainder;
}

} // namespace crypto_core::internal
