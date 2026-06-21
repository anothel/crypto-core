#include "crypto_core/internal/rsa_fixed_bigint.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <utility>

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

void require_tail_bytes(std::span<const std::uint8_t> actual, std::span<const std::uint8_t> expected_tail)
{
	require(actual.size() >= expected_tail.size());
	const auto prefix_size = actual.size() - expected_tail.size();
	for (std::size_t i = 0; i < prefix_size; ++i)
	{
		require(actual[i] == 0U);
	}
	for (std::size_t i = 0; i < expected_tail.size(); ++i)
	{
		require(actual[prefix_size + i] == expected_tail[i]);
	}
}

crypto_core::internal::RsaFixedBigInt fixed(std::span<const std::uint8_t> bytes, std::size_t width)
{
	auto value = crypto_core::internal::RsaFixedBigInt::from_be_bytes(bytes, width);
	require(value.has_value());
	return std::move(value.value());
}

void test_import_export_zero_extends_to_width()
{
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 8> expected{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	auto value = crypto_core::internal::RsaFixedBigInt::from_be_bytes(one, 2);
	require(value.has_value());
	require(value.value().width() == 2);
	require(!value.value().is_zero());
	require_bytes(value.value().to_be_bytes().bytes(), expected);
}

void test_import_rejects_non_zero_oversized_input()
{
	const std::array<std::uint8_t, 5> too_large{0x01, 0x00, 0x00, 0x00, 0x00};
	auto value = crypto_core::internal::RsaFixedBigInt::from_be_bytes(too_large, 1);
	require(!value.has_value());
	require(value.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_import_accepts_leading_zero_oversized_input()
{
	const std::array<std::uint8_t, 5> with_leading_zero{0x00, 0x12, 0x34, 0x56, 0x78};
	const std::array<std::uint8_t, 4> expected{0x12, 0x34, 0x56, 0x78};
	auto value = crypto_core::internal::RsaFixedBigInt::from_be_bytes(with_leading_zero, 1);
	require(value.has_value());
	require_bytes(value.value().to_be_bytes().bytes(), expected);
}

void test_zero_rejects_invalid_width()
{
	auto zero_width = crypto_core::internal::RsaFixedBigInt::zero(0);
	require(!zero_width.has_value());
	require(zero_width.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto too_wide = crypto_core::internal::RsaFixedBigInt::zero(crypto_core::internal::RsaFixedBigInt::kMaxLimbs + 1U);
	require(!too_wide.has_value());
	require(too_wide.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_equal_mask()
{
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 1> two{0x02};
	auto same = crypto_core::internal::RsaFixedBigInt::equal_mask(fixed(one, 2), fixed(one, 2));
	auto different = crypto_core::internal::RsaFixedBigInt::equal_mask(fixed(one, 2), fixed(two, 2));
	require(same.has_value());
	require(different.has_value());
	require(same.value() == 0xFFU);
	require(different.value() == 0x00U);
}

void test_less_than_mask()
{
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 1> two{0x02};
	const std::array<std::uint8_t, 5> high{0x01, 0x00, 0x00, 0x00, 0x00};
	const std::array<std::uint8_t, 5> lower_high{0x00, 0xFF, 0xFF, 0xFF, 0xFF};

	auto one_less_two = crypto_core::internal::RsaFixedBigInt::less_than_mask(fixed(one, 2), fixed(two, 2));
	auto two_less_one = crypto_core::internal::RsaFixedBigInt::less_than_mask(fixed(two, 2), fixed(one, 2));
	auto equal_less = crypto_core::internal::RsaFixedBigInt::less_than_mask(fixed(one, 2), fixed(one, 2));
	auto high_order = crypto_core::internal::RsaFixedBigInt::less_than_mask(fixed(lower_high, 2), fixed(high, 2));

	require(one_less_two.has_value());
	require(two_less_one.has_value());
	require(equal_less.has_value());
	require(high_order.has_value());
	require(one_less_two.value() == 0xFFU);
	require(two_less_one.value() == 0x00U);
	require(equal_less.value() == 0x00U);
	require(high_order.value() == 0xFFU);
}

void test_select_chooses_by_mask()
{
	const std::array<std::uint8_t, 2> left{0x12, 0x34};
	const std::array<std::uint8_t, 2> right{0xAB, 0xCD};
	const std::array<std::uint8_t, 8> expected_left{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
	const std::array<std::uint8_t, 8> expected_right{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD};

	auto selected_left = crypto_core::internal::RsaFixedBigInt::select(0xFFU, fixed(left, 2), fixed(right, 2));
	auto selected_right = crypto_core::internal::RsaFixedBigInt::select(0x00U, fixed(left, 2), fixed(right, 2));
	require(selected_left.has_value());
	require(selected_right.has_value());
	require_bytes(selected_left.value().to_be_bytes().bytes(), expected_left);
	require_bytes(selected_right.value().to_be_bytes().bytes(), expected_right);
}

void test_add_wraps_to_width()
{
	const std::array<std::uint8_t, 4> low_max{0xFF, 0xFF, 0xFF, 0xFF};
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 8> expected_carry{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
	auto carry = crypto_core::internal::RsaFixedBigInt::add(fixed(low_max, 2), fixed(one, 2));
	require(carry.has_value());
	require_bytes(carry.value().to_be_bytes().bytes(), expected_carry);

	const std::array<std::uint8_t, 8> full_max{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	const std::array<std::uint8_t, 8> expected_wrap{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	auto wrap = crypto_core::internal::RsaFixedBigInt::add(fixed(full_max, 2), fixed(one, 2));
	require(wrap.has_value());
	require_bytes(wrap.value().to_be_bytes().bytes(), expected_wrap);
}

void test_subtract_wraps_to_width()
{
	const std::array<std::uint8_t, 1> three{0x03};
	const std::array<std::uint8_t, 1> one{0x01};
	const std::array<std::uint8_t, 8> expected_two{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	auto two = crypto_core::internal::RsaFixedBigInt::subtract(fixed(three, 2), fixed(one, 2));
	require(two.has_value());
	require_bytes(two.value().to_be_bytes().bytes(), expected_two);

	const std::array<std::uint8_t, 1> zero{0x00};
	const std::array<std::uint8_t, 8> expected_wrap{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	auto wrap = crypto_core::internal::RsaFixedBigInt::subtract(fixed(zero, 2), fixed(one, 2));
	require(wrap.has_value());
	require_bytes(wrap.value().to_be_bytes().bytes(), expected_wrap);
}

void test_binary_operations_reject_width_mismatch()
{
	const std::array<std::uint8_t, 1> one{0x01};
	auto add = crypto_core::internal::RsaFixedBigInt::add(fixed(one, 1), fixed(one, 2));
	auto subtract = crypto_core::internal::RsaFixedBigInt::subtract(fixed(one, 1), fixed(one, 2));
	auto equal = crypto_core::internal::RsaFixedBigInt::equal_mask(fixed(one, 1), fixed(one, 2));
	auto less = crypto_core::internal::RsaFixedBigInt::less_than_mask(fixed(one, 1), fixed(one, 2));
	auto select = crypto_core::internal::RsaFixedBigInt::select(0xFFU, fixed(one, 1), fixed(one, 2));

	require(!add.has_value());
	require(!subtract.has_value());
	require(!equal.has_value());
	require(!less.has_value());
	require(!select.has_value());
	require(add.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(subtract.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(equal.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(less.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(select.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_montgomery_n0_inverse_matches_known_value()
{
	const std::array<std::uint8_t, 1> modulus{0x03};

	auto inverse = crypto_core::internal::RsaFixedBigInt::montgomery_n0_inverse(fixed(modulus, 1));
	require(inverse.has_value());
	require(inverse.value() == 0x55555555U);
}

void test_montgomery_multiply_raw_matches_expected()
{
	const std::array<std::uint8_t, 1> lhs{0x05};
	const std::array<std::uint8_t, 1> rhs{0x07};
	const std::array<std::uint8_t, 1> modulus{0x13};
	const std::array<std::uint8_t, 4> expected{0x00, 0x00, 0x00, 0x09};

	auto product =
	    crypto_core::internal::RsaFixedBigInt::montgomery_multiply(fixed(lhs, 1), fixed(rhs, 1), fixed(modulus, 1));
	require(product.has_value());
	require_bytes(product.value().to_be_bytes().bytes(), expected);
}

void test_montgomery_r_squared_matches_expected()
{
	const std::array<std::uint8_t, 1> modulus{0x13};
	const std::array<std::uint8_t, 4> expected{0x00, 0x00, 0x00, 0x11};

	auto r_squared = crypto_core::internal::RsaFixedBigInt::montgomery_r_squared(fixed(modulus, 1));
	require(r_squared.has_value());
	require_bytes(r_squared.value().to_be_bytes().bytes(), expected);
}

void test_montgomery_round_trip()
{
	const std::array<std::uint8_t, 1> value_bytes{0x05};
	const std::array<std::uint8_t, 1> modulus_bytes{0x13};
	const std::array<std::uint8_t, 4> expected_montgomery{0x00, 0x00, 0x00, 0x0B};
	const std::array<std::uint8_t, 4> expected_normal{0x00, 0x00, 0x00, 0x05};

	auto value = fixed(value_bytes, 1);
	auto modulus = fixed(modulus_bytes, 1);
	auto montgomery = crypto_core::internal::RsaFixedBigInt::to_montgomery(value, modulus);
	require(montgomery.has_value());
	require_bytes(montgomery.value().to_be_bytes().bytes(), expected_montgomery);

	auto normal = crypto_core::internal::RsaFixedBigInt::from_montgomery(montgomery.value(), modulus);
	require(normal.has_value());
	require_bytes(normal.value().to_be_bytes().bytes(), expected_normal);
}

void test_montgomery_domain_multiply_round_trip()
{
	const std::array<std::uint8_t, 1> lhs_bytes{0x05};
	const std::array<std::uint8_t, 1> rhs_bytes{0x07};
	const std::array<std::uint8_t, 1> modulus_bytes{0x13};
	const std::array<std::uint8_t, 4> expected{0x00, 0x00, 0x00, 0x10};

	auto modulus = fixed(modulus_bytes, 1);
	auto montgomery_lhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(fixed(lhs_bytes, 1), modulus);
	auto montgomery_rhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(fixed(rhs_bytes, 1), modulus);
	require(montgomery_lhs.has_value());
	require(montgomery_rhs.has_value());

	auto montgomery_product = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(montgomery_lhs.value(),
	    montgomery_rhs.value(),
	    modulus);
	require(montgomery_product.has_value());

	auto normal_product = crypto_core::internal::RsaFixedBigInt::from_montgomery(montgomery_product.value(), modulus);
	require(normal_product.has_value());
	require_bytes(normal_product.value().to_be_bytes().bytes(), expected);
}

void test_from_be_bytes_mod_reduces_wide_input()
{
	const std::array<std::uint8_t, 2> input{0x0A, 0xE6};
	const std::array<std::uint8_t, 1> modulus_bytes{0x3D};
	const std::array<std::uint8_t, 4> expected{0x00, 0x00, 0x00, 0x2D};

	auto reduced = crypto_core::internal::RsaFixedBigInt::from_be_bytes_mod(input, fixed(modulus_bytes, 1));
	require(reduced.has_value());
	require_bytes(reduced.value().to_be_bytes().bytes(), expected);
}

void test_montgomery_mod_exp_secret_matches_crt_branch_value()
{
	const std::array<std::uint8_t, 2> input{0x0A, 0xE6};
	const std::array<std::uint8_t, 1> exponent{0x35};
	const std::array<std::uint8_t, 1> modulus_bytes{0x3D};
	const std::array<std::uint8_t, 4> expected{0x00, 0x00, 0x00, 0x04};

	auto modulus = fixed(modulus_bytes, 1);
	auto base = crypto_core::internal::RsaFixedBigInt::from_be_bytes_mod(input, modulus);
	require(base.has_value());

	auto output = crypto_core::internal::RsaFixedBigInt::montgomery_mod_exp_secret(base.value(), exponent, modulus, 8U);
	require(output.has_value());
	require_bytes(output.value().to_be_bytes().bytes(), expected);
}

void test_montgomery_rejects_invalid_modulus_and_width()
{
	const std::array<std::uint8_t, 1> value_bytes{0x05};
	const std::array<std::uint8_t, 1> one_modulus_bytes{0x01};
	const std::array<std::uint8_t, 1> even_modulus_bytes{0x12};
	const std::array<std::uint8_t, 1> odd_modulus_bytes{0x13};

	auto value = fixed(value_bytes, 1);
	auto one_modulus = fixed(one_modulus_bytes, 1);
	auto even_modulus = fixed(even_modulus_bytes, 1);
	auto zero_modulus = crypto_core::internal::RsaFixedBigInt::zero(1);
	auto wide_modulus = fixed(odd_modulus_bytes, 2);
	require(zero_modulus.has_value());

	auto one_inverse = crypto_core::internal::RsaFixedBigInt::montgomery_n0_inverse(one_modulus);
	auto even_inverse = crypto_core::internal::RsaFixedBigInt::montgomery_n0_inverse(even_modulus);
	auto zero_inverse = crypto_core::internal::RsaFixedBigInt::montgomery_n0_inverse(zero_modulus.value());
	auto even_product = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(value, value, even_modulus);
	auto width_mismatch = crypto_core::internal::RsaFixedBigInt::to_montgomery(value, wide_modulus);

	require(!one_inverse.has_value());
	require(!even_inverse.has_value());
	require(!zero_inverse.has_value());
	require(!even_product.has_value());
	require(!width_mismatch.has_value());
	require(one_inverse.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(even_inverse.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(zero_inverse.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(even_product.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(width_mismatch.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_montgomery_rejects_non_reduced_values()
{
	const std::array<std::uint8_t, 1> value_bytes{0x13};
	const std::array<std::uint8_t, 1> reduced_bytes{0x05};
	const std::array<std::uint8_t, 1> modulus_bytes{0x13};

	auto value = fixed(value_bytes, 1);
	auto reduced = fixed(reduced_bytes, 1);
	auto modulus = fixed(modulus_bytes, 1);

	auto convert = crypto_core::internal::RsaFixedBigInt::to_montgomery(value, modulus);
	auto multiply_lhs = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(value, reduced, modulus);
	auto multiply_rhs = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(reduced, value, modulus);

	require(!convert.has_value());
	require(!multiply_lhs.has_value());
	require(!multiply_rhs.has_value());
	require(convert.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(multiply_lhs.error().code() == crypto_core::ErrorCode::invalid_argument);
	require(multiply_rhs.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_montgomery_handles_max_width_smoke()
{
	constexpr std::size_t width = crypto_core::internal::RsaFixedBigInt::kMaxLimbs;
	const std::array<std::uint8_t, 1> lhs_bytes{0x7B};
	const std::array<std::uint8_t, 2> rhs_bytes{0x01, 0xC8};
	const std::array<std::uint8_t, 3> modulus_bytes{0x01, 0x00, 0x01};
	const std::array<std::uint8_t, 2> expected_tail{0xDB, 0x18};

	auto modulus = fixed(modulus_bytes, width);
	auto montgomery_lhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(fixed(lhs_bytes, width), modulus);
	auto montgomery_rhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(fixed(rhs_bytes, width), modulus);
	require(montgomery_lhs.has_value());
	require(montgomery_rhs.has_value());

	auto montgomery_product = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(montgomery_lhs.value(),
	    montgomery_rhs.value(),
	    modulus);
	require(montgomery_product.has_value());

	auto normal_product = crypto_core::internal::RsaFixedBigInt::from_montgomery(montgomery_product.value(), modulus);
	require(normal_product.has_value());
	require_tail_bytes(normal_product.value().to_be_bytes().bytes(), expected_tail);
}

void test_montgomery_handles_full_width_carry_heavy_smoke()
{
	constexpr std::size_t width = crypto_core::internal::RsaFixedBigInt::kMaxLimbs;
	std::array<std::uint8_t, width * 4U> modulus_bytes{};
	std::array<std::uint8_t, width * 4U> lhs_bytes{};
	std::array<std::uint8_t, width * 4U> rhs_bytes{};
	modulus_bytes.fill(0xFFU);
	lhs_bytes.fill(0xAAU);
	rhs_bytes.fill(0x55U);
	modulus_bytes.back() = 0xFDU;

	auto modulus = fixed(modulus_bytes, width);
	auto lhs = fixed(lhs_bytes, width);
	auto rhs = fixed(rhs_bytes, width);

	auto reference_lhs = crypto_core::internal::BigInt::from_be_bytes(lhs_bytes);
	auto reference_rhs = crypto_core::internal::BigInt::from_be_bytes(rhs_bytes);
	auto reference_modulus = crypto_core::internal::BigInt::from_be_bytes(modulus_bytes);
	require(reference_lhs.has_value());
	require(reference_rhs.has_value());
	require(reference_modulus.has_value());
	auto reference_product = crypto_core::internal::BigInt::mod_multiply(reference_lhs.value(),
	    reference_rhs.value(),
	    reference_modulus.value());
	require(reference_product.has_value());

	auto montgomery_lhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(lhs, modulus);
	auto montgomery_rhs = crypto_core::internal::RsaFixedBigInt::to_montgomery(rhs, modulus);
	require(montgomery_lhs.has_value());
	require(montgomery_rhs.has_value());

	auto montgomery_product = crypto_core::internal::RsaFixedBigInt::montgomery_multiply(montgomery_lhs.value(),
	    montgomery_rhs.value(),
	    modulus);
	require(montgomery_product.has_value());

	auto normal_product = crypto_core::internal::RsaFixedBigInt::from_montgomery(montgomery_product.value(), modulus);
	require(normal_product.has_value());
	require_tail_bytes(normal_product.value().to_be_bytes().bytes(), reference_product.value().to_be_bytes().bytes());
}

} // namespace

int main()
{
	test_import_export_zero_extends_to_width();
	test_import_rejects_non_zero_oversized_input();
	test_import_accepts_leading_zero_oversized_input();
	test_zero_rejects_invalid_width();
	test_equal_mask();
	test_less_than_mask();
	test_select_chooses_by_mask();
	test_add_wraps_to_width();
	test_subtract_wraps_to_width();
	test_binary_operations_reject_width_mismatch();
	test_montgomery_n0_inverse_matches_known_value();
	test_montgomery_multiply_raw_matches_expected();
	test_montgomery_r_squared_matches_expected();
	test_montgomery_round_trip();
	test_montgomery_domain_multiply_round_trip();
	test_from_be_bytes_mod_reduces_wide_input();
	test_montgomery_mod_exp_secret_matches_crt_branch_value();
	test_montgomery_rejects_invalid_modulus_and_width();
	test_montgomery_rejects_non_reduced_values();
	test_montgomery_handles_max_width_smoke();
	test_montgomery_handles_full_width_carry_heavy_smoke();
	return 0;
}
