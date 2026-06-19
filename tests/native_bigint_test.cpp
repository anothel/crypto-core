#include "crypto_core/internal/bigint.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

void require_bytes(std::span<const std::uint8_t> actual, std::span<const std::uint8_t> expected)
{
	require(actual.size() == expected.size());
	for (std::size_t i = 0; i < actual.size(); ++i)
	{
		require(actual[i] == expected[i]);
	}
}

crypto_core::internal::BigInt bigint(std::span<const std::uint8_t> bytes)
{
	auto value = crypto_core::internal::BigInt::from_be_bytes(bytes);
	require(value.has_value());
	return std::move(value.value());
}

void test_bigint_normalizes_big_endian_bytes()
{
	const std::array<std::uint8_t, 4> input{0x00, 0x00, 0x01, 0x23};
	auto value = crypto_core::internal::BigInt::from_be_bytes(input);
	require(value.has_value());
	require(!value.value().is_zero());
	require_bytes(value.value().to_be_bytes().bytes(), std::array<std::uint8_t, 2>{0x01, 0x23});

	const std::array<std::uint8_t, 2> zero_input{0x00, 0x00};
	auto zero = crypto_core::internal::BigInt::from_be_bytes(zero_input);
	require(zero.has_value());
	require(zero.value().is_zero());
	require_bytes(zero.value().to_be_bytes().bytes(), std::array<std::uint8_t, 1>{0x00});
}

void test_bigint_compare_ignores_leading_zeroes()
{
	const std::array<std::uint8_t, 2> one_with_zero{0x00, 0x01};
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 1> two{0x02};
	require(bigint(one_with_zero).compare(bigint(one)) == 0);
	require(bigint(one).compare(bigint(two)) < 0);
	require(bigint(two).compare(bigint(one)) > 0);
}

void test_mod_multiply_small_values()
{
	const std::array<std::uint8_t, 2> lhs{0x30, 0x39};
	const std::array<std::uint8_t, 2> rhs{0x1A, 0x85};
	const std::array<std::uint8_t, 3> modulus{0x01, 0x86, 0xA0};

	auto result = crypto_core::internal::BigInt::mod_multiply(bigint(lhs), bigint(rhs), bigint(modulus));
	require(result.has_value());
	require_bytes(result.value().to_be_bytes().bytes(), std::array<std::uint8_t, 2>{0x27, 0xDD});
}

void test_mod_add_and_subtract_wrap_values()
{
	const std::array<std::uint8_t, 1> lhs_add{0xFE};
	const std::array<std::uint8_t, 1> rhs_add{0x03};
	const std::array<std::uint8_t, 1> modulus_add{0xFF};
	auto add = crypto_core::internal::BigInt::mod_add(bigint(lhs_add), bigint(rhs_add), bigint(modulus_add));
	require(add.has_value());
	require_bytes(add.value().to_be_bytes().bytes(), std::array<std::uint8_t, 1>{0x02});

	const std::array<std::uint8_t, 1> lhs_sub{0x02};
	const std::array<std::uint8_t, 1> rhs_sub{0x05};
	const std::array<std::uint8_t, 1> modulus_sub{0x0B};
	auto subtract = crypto_core::internal::BigInt::mod_subtract(bigint(lhs_sub), bigint(rhs_sub), bigint(modulus_sub));
	require(subtract.has_value());
	require_bytes(subtract.value().to_be_bytes().bytes(), std::array<std::uint8_t, 1>{0x08});
}

void test_mod_multiply_handles_values_larger_than_uint64()
{
	const std::array<std::uint8_t, 9> almost_modulus{
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
	const std::array<std::uint8_t, 9> modulus{
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	auto result = crypto_core::internal::BigInt::mod_multiply(bigint(almost_modulus), bigint(almost_modulus), bigint(modulus));
	require(result.has_value());
	require_bytes(result.value().to_be_bytes().bytes(), std::array<std::uint8_t, 1>{0x01});
}

void test_mod_exp_small_values()
{
	const std::array<std::uint8_t, 1> base{0x04};
	const std::array<std::uint8_t, 1> exponent{0x0D};
	const std::array<std::uint8_t, 2> modulus{0x01, 0xF1};

	auto result = crypto_core::internal::BigInt::mod_exp(bigint(base), bigint(exponent), bigint(modulus));
	require(result.has_value());
	require_bytes(result.value().to_be_bytes().bytes(), std::array<std::uint8_t, 2>{0x01, 0xBD});
}

void test_mod_exp_handles_values_larger_than_uint64()
{
	const std::array<std::uint8_t, 9> base{
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
	const std::array<std::uint8_t, 1> exponent{0x03};
	const std::array<std::uint8_t, 9> modulus{
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	auto result = crypto_core::internal::BigInt::mod_exp(bigint(base), bigint(exponent), bigint(modulus));
	require(result.has_value());
	require_bytes(result.value().to_be_bytes().bytes(), base);
}

void test_mod_exp_secret_matches_public_mod_exp()
{
	const std::array<std::uint8_t, 2> base{0x12, 0x34};
	const std::array<std::uint8_t, 2> exponent{0x01, 0x01};
	const std::array<std::uint8_t, 2> modulus{0x13, 0x57};

	auto public_result = crypto_core::internal::BigInt::mod_exp(bigint(base), bigint(exponent), bigint(modulus));
	auto secret_result = crypto_core::internal::BigInt::mod_exp_secret(bigint(base), bigint(exponent), bigint(modulus), exponent.size() * 8U);
	require(public_result.has_value());
	require(secret_result.has_value());
	require_bytes(secret_result.value().to_be_bytes().bytes(), public_result.value().to_be_bytes().bytes());
}

void test_mod_operations_reject_zero_modulus()
{
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 1> zero{0x00};

	auto multiply = crypto_core::internal::BigInt::mod_multiply(bigint(one), bigint(one), bigint(zero));
	require(!multiply.has_value());
	require(multiply.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto add = crypto_core::internal::BigInt::mod_add(bigint(one), bigint(one), bigint(zero));
	require(!add.has_value());
	require(add.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto subtract = crypto_core::internal::BigInt::mod_subtract(bigint(one), bigint(one), bigint(zero));
	require(!subtract.has_value());
	require(subtract.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto exponent = crypto_core::internal::BigInt::mod_exp(bigint(one), bigint(one), bigint(zero));
	require(!exponent.has_value());
	require(exponent.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto secret_exponent = crypto_core::internal::BigInt::mod_exp_secret(bigint(one), bigint(one), bigint(zero), one.size() * 8U);
	require(!secret_exponent.has_value());
	require(secret_exponent.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_bigint_normalizes_big_endian_bytes();
	test_bigint_compare_ignores_leading_zeroes();
	test_mod_multiply_small_values();
	test_mod_add_and_subtract_wrap_values();
	test_mod_multiply_handles_values_larger_than_uint64();
	test_mod_exp_small_values();
	test_mod_exp_handles_values_larger_than_uint64();
	test_mod_exp_secret_matches_public_mod_exp();
	test_mod_operations_reject_zero_modulus();
	return 0;
}
