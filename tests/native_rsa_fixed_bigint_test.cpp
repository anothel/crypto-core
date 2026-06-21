#include "crypto_core/internal/rsa_fixed_bigint.hpp"

#include "crypto_core/error.hpp"

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
	return 0;
}
