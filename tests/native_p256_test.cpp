#include "crypto_core/internal/p256.hpp"
#include "crypto_core/internal/p256_fixed.hpp"

#include "test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

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

std::vector<std::uint8_t> bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

void require_point(const crypto_core::internal::P256Point &point, std::span<const std::uint8_t> x, std::span<const std::uint8_t> y)
{
	require(!point.infinity);
	require_bytes(point.x.bytes(), x);
	require_bytes(point.y.bytes(), y);
}

crypto_core::internal::P256Point unchecked_point(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y)
{
	return crypto_core::internal::P256Point{crypto_core::ByteBuffer::copy_from(x), crypto_core::ByteBuffer::copy_from(y), false};
}

void require_invalid_key(auto result)
{
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_base_point_is_on_curve()
{
	auto point = crypto_core::internal::p256_base_point();
	require(point.has_value());

	auto on_curve = crypto_core::internal::p256_is_on_curve(point.value());
	require(on_curve.has_value());
	require(on_curve.value());
}

void test_point_double_matches_known_two_g()
{
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());

	auto doubled = crypto_core::internal::p256_point_add(base.value(), base.value());
	require(doubled.has_value());
	require_point(
	    doubled.value(),
	    bytes("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978"),
	    bytes("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"));
}

void test_point_add_matches_point_double_for_base_point()
{
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());

	auto added = crypto_core::internal::p256_point_add(base.value(), base.value());
	auto doubled = crypto_core::internal::p256_scalar_multiply(std::array<std::uint8_t, 1>{0x02}, base.value());
	require(added.has_value());
	require(doubled.has_value());
	require_point(doubled.value(), added.value().x.bytes(), added.value().y.bytes());
}

void test_scalar_multiply_by_two_matches_known_two_g()
{
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());

	auto doubled = crypto_core::internal::p256_scalar_multiply(std::array<std::uint8_t, 1>{0x02}, base.value());
	require(doubled.has_value());
	require_point(
	    doubled.value(),
	    bytes("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978"),
	    bytes("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"));
}

void test_scalar_multiply_by_group_order_returns_infinity()
{
	auto result = crypto_core::internal::p256_base_point_multiply(crypto_core::internal::p256_group_order());
	require(result.has_value());
	require(result.value().infinity);
}

void test_scalar_multiply_by_group_order_plus_one_returns_base_point()
{
	auto scalar = std::vector<std::uint8_t>(
	    crypto_core::internal::p256_group_order().begin(),
	    crypto_core::internal::p256_group_order().end());
	for (std::size_t i = scalar.size(); i > 0; --i)
	{
		++scalar[i - 1U];
		if (scalar[i - 1U] != 0)
		{
			break;
		}
	}

	auto base = crypto_core::internal::p256_base_point();
	auto result = crypto_core::internal::p256_base_point_multiply(scalar);
	require(base.has_value());
	require(result.has_value());
	require_point(result.value(), base.value().x.bytes(), base.value().y.bytes());
}

void test_scalar_inverse_satisfies_multiply_to_one()
{
	const std::array<std::uint8_t, 1> three{0x03};
	auto inverse = crypto_core::internal::p256_scalar_inverse(three);
	require(inverse.has_value());

	auto product = crypto_core::internal::p256_scalar_multiply_mod(three, inverse.value().bytes());
	require(product.has_value());
	require_bytes(product.value().bytes(), std::array<std::uint8_t, 1>{0x01});
}

void test_scalar_inverse_rejects_zero()
{
	const std::array<std::uint8_t, 1> zero{0x00};
	auto inverse = crypto_core::internal::p256_scalar_inverse(zero);
	require(!inverse.has_value());
	require(inverse.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_rejects_point_not_on_curve()
{
	auto x = bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
	auto y = bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F6");

	auto point = crypto_core::internal::p256_point_from_coordinates(x, y);
	require_invalid_key(point);
}

void test_point_add_rejects_off_curve_lhs()
{
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());
	auto off_curve = unchecked_point(
	    bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
	    bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F6"));

	require_invalid_key(crypto_core::internal::p256_point_add(off_curve, base.value()));
}

void test_point_add_rejects_off_curve_rhs()
{
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());
	auto off_curve = unchecked_point(
	    bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
	    bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F6"));

	require_invalid_key(crypto_core::internal::p256_point_add(base.value(), off_curve));
}

void test_x_mod_order_rejects_off_curve_point()
{
	auto off_curve = unchecked_point(
	    bytes("0000000000000000000000000000000000000000000000000000000000000001"),
	    bytes("0000000000000000000000000000000000000000000000000000000000000001"));

	require_invalid_key(crypto_core::internal::p256_x_mod_order(off_curve));
}

void test_fixed_base_point_multiply_matches_reference()
{
	auto scalar = bytes("11223344556677889900AABBCCDDEEFF0102030405060708090A0B0C0D0E0F10");

	auto reference = crypto_core::internal::p256_base_point_multiply(scalar);
	auto fixed = crypto_core::internal::p256_fixed_base_point_multiply(scalar);
	require(reference.has_value());
	require(fixed.has_value());
	require_point(fixed.value(), reference.value().x.bytes(), reference.value().y.bytes());
}

void test_fixed_scalar_multiply_matches_reference()
{
	auto scalar = bytes("0102030405060708090A0B0C0D0E0F1011223344556677889900AABBCCDDEEFF");
	auto base = crypto_core::internal::p256_base_point();
	require(base.has_value());

	auto reference = crypto_core::internal::p256_scalar_multiply(scalar, base.value());
	auto fixed = crypto_core::internal::p256_fixed_scalar_multiply(scalar, base.value());
	require(reference.has_value());
	require(fixed.has_value());
	require_point(fixed.value(), reference.value().x.bytes(), reference.value().y.bytes());
}

void test_fixed_scalar_multiply_arbitrary_point_matches_reference()
{
	auto scalar = bytes("2A75F9367C8AF1E2D3C4B5A697887766554433221100FFEEDDCCBBAA00998877");
	auto point = crypto_core::internal::p256_point_from_coordinates(
	    bytes("507A822E9DA764244CCE994EF0BB4ADEE4FD71B66585C56954BBAFC7BBD2FAA4"),
	    bytes("5424E4C9C7A95082E8AE73482CE33DAAB6C27530E728B3B8473A38D99704E480"));
	require(point.has_value());

	auto reference = crypto_core::internal::p256_scalar_multiply(scalar, point.value());
	auto fixed = crypto_core::internal::p256_fixed_scalar_multiply(scalar, point.value());
	require(reference.has_value());
	require(fixed.has_value());
	require_point(fixed.value(), reference.value().x.bytes(), reference.value().y.bytes());
}

void test_fixed_scalar_inverse_satisfies_multiply_to_one()
{
	const std::array<std::uint8_t, 1> seven{0x07};
	auto inverse = crypto_core::internal::p256_fixed_scalar_inverse(seven);
	require(inverse.has_value());

	auto product = crypto_core::internal::p256_fixed_scalar_multiply_mod(seven, inverse.value().bytes());
	require(product.has_value());
	require_bytes(product.value().bytes(), std::array<std::uint8_t, 1>{0x01});
}

void test_fixed_scalar_helpers_match_reference_for_ecdsa_values()
{
	auto digest = bytes("2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4D3");
	auto r = bytes("5CE55BADA0C9A41C4C702AD67FB0AD0F2439673EC85A794DD0E2C8D002A1A685");
	auto s = bytes("54C14EA056B9D38183599E3C1B3C669F044507E543FF797FBCD25A06B72E7F95");

	auto reference_inverse = crypto_core::internal::p256_scalar_inverse(s);
	auto fixed_inverse = crypto_core::internal::p256_fixed_scalar_inverse(s);
	require(reference_inverse.has_value());
	require(fixed_inverse.has_value());
	require_bytes(fixed_inverse.value().bytes(), reference_inverse.value().bytes());

	auto reference_u1 = crypto_core::internal::p256_scalar_multiply_mod(digest, reference_inverse.value().bytes());
	auto fixed_u1 = crypto_core::internal::p256_fixed_scalar_multiply_mod(digest, fixed_inverse.value().bytes());
	require(reference_u1.has_value());
	require(fixed_u1.has_value());
	require_bytes(fixed_u1.value().bytes(), reference_u1.value().bytes());

	auto reference_u2 = crypto_core::internal::p256_scalar_multiply_mod(r, reference_inverse.value().bytes());
	auto fixed_u2 = crypto_core::internal::p256_fixed_scalar_multiply_mod(r, fixed_inverse.value().bytes());
	require(reference_u2.has_value());
	require(fixed_u2.has_value());
	require_bytes(fixed_u2.value().bytes(), reference_u2.value().bytes());
}

void test_fixed_scalar_add_mod_matches_reference_for_ecdsa_values()
{
	auto digest = bytes("2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4D3");
	auto rd = bytes("32867704082A2019E5C357816D85382C34F0790063B6A045025486B974B69944");
	auto expected = bytes("56DF1A32F1B0741ECD003EEA3BD087C57AAA28B87CF6EC29DD932B1819308E17");

	auto fixed = crypto_core::internal::p256_fixed_scalar_add_mod(digest, rd);
	require(fixed.has_value());
	require_bytes(fixed.value().bytes(), expected);
}

void test_fixed_scalar_reduce_fixed_32_matches_rfc6979_octets()
{
	auto digest = bytes("2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4D3");
	auto order = bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
	auto order_plus_one = bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552");
	auto leading_zero_order_plus_one = bytes("00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552");

	auto reduced_digest = crypto_core::internal::p256_fixed_scalar_reduce_fixed_32(digest);
	require(reduced_digest.has_value());
	require_bytes(reduced_digest.value().bytes(), digest);

	auto reduced_order = crypto_core::internal::p256_fixed_scalar_reduce_fixed_32(order);
	require(reduced_order.has_value());
	require_bytes(reduced_order.value().bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000000"));

	auto reduced_order_plus_one = crypto_core::internal::p256_fixed_scalar_reduce_fixed_32(order_plus_one);
	require(reduced_order_plus_one.has_value());
	require_bytes(reduced_order_plus_one.value().bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000001"));

	auto reduced_leading_zero = crypto_core::internal::p256_fixed_scalar_reduce_fixed_32(leading_zero_order_plus_one);
	require(reduced_leading_zero.has_value());
	require_bytes(reduced_leading_zero.value().bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000001"));
}

void test_fixed_x_mod_order_matches_reference()
{
	auto scalar = bytes("3141592653589793238462643383279502884197169399375105820974944592");
	auto point = crypto_core::internal::p256_base_point_multiply(scalar);
	require(point.has_value());

	auto reference = crypto_core::internal::p256_x_mod_order(point.value());
	auto fixed = crypto_core::internal::p256_fixed_x_mod_order(point.value());
	require(reference.has_value());
	require(fixed.has_value());
	require_bytes(fixed.value().bytes(), reference.value().bytes());
}

void test_fixed_ecdsa_recombination_matches_reference()
{
	auto q = crypto_core::internal::p256_point_from_coordinates(
	    bytes("507A822E9DA764244CCE994EF0BB4ADEE4FD71B66585C56954BBAFC7BBD2FAA4"),
	    bytes("5424E4C9C7A95082E8AE73482CE33DAAB6C27530E728B3B8473A38D99704E480"));
	auto digest = bytes("2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4D3");
	auto r = bytes("5CE55BADA0C9A41C4C702AD67FB0AD0F2439673EC85A794DD0E2C8D002A1A685");
	auto s = bytes("54C14EA056B9D38183599E3C1B3C669F044507E543FF797FBCD25A06B72E7F95");
	require(q.has_value());

	auto w = crypto_core::internal::p256_fixed_scalar_inverse(s);
	require(w.has_value());
	auto u1 = crypto_core::internal::p256_fixed_scalar_multiply_mod(digest, w.value().bytes());
	auto u2 = crypto_core::internal::p256_fixed_scalar_multiply_mod(r, w.value().bytes());
	require(u1.has_value());
	require(u2.has_value());

	auto reference_u1_g = crypto_core::internal::p256_base_point_multiply(u1.value().bytes());
	auto reference_u2_q = crypto_core::internal::p256_scalar_multiply(u2.value().bytes(), q.value());
	auto fixed_u1_g = crypto_core::internal::p256_fixed_base_point_multiply(u1.value().bytes());
	auto fixed_u2_q = crypto_core::internal::p256_fixed_scalar_multiply(u2.value().bytes(), q.value());
	require(reference_u1_g.has_value());
	require(reference_u2_q.has_value());
	require(fixed_u1_g.has_value());
	require(fixed_u2_q.has_value());
	auto reference_sum = crypto_core::internal::p256_point_add(reference_u1_g.value(), reference_u2_q.value());
	auto fixed_sum = crypto_core::internal::p256_fixed_point_add(fixed_u1_g.value(), fixed_u2_q.value());
	require(reference_sum.has_value());
	require(fixed_sum.has_value());
	require_point(fixed_sum.value(), reference_sum.value().x.bytes(), reference_sum.value().y.bytes());

	auto fixed_x = crypto_core::internal::p256_fixed_x_mod_order(fixed_sum.value());
	require(fixed_x.has_value());
	require_bytes(fixed_x.value().bytes(), r);
}

} // namespace

int main()
{
	test_base_point_is_on_curve();
	test_point_double_matches_known_two_g();
	test_point_add_matches_point_double_for_base_point();
	test_scalar_multiply_by_two_matches_known_two_g();
	test_scalar_multiply_by_group_order_returns_infinity();
	test_scalar_multiply_by_group_order_plus_one_returns_base_point();
	test_scalar_inverse_satisfies_multiply_to_one();
	test_scalar_inverse_rejects_zero();
	test_rejects_point_not_on_curve();
	test_point_add_rejects_off_curve_lhs();
	test_point_add_rejects_off_curve_rhs();
	test_x_mod_order_rejects_off_curve_point();
	test_fixed_base_point_multiply_matches_reference();
	test_fixed_scalar_multiply_matches_reference();
	test_fixed_scalar_multiply_arbitrary_point_matches_reference();
	test_fixed_scalar_inverse_satisfies_multiply_to_one();
	test_fixed_scalar_helpers_match_reference_for_ecdsa_values();
	test_fixed_scalar_add_mod_matches_reference_for_ecdsa_values();
	test_fixed_scalar_reduce_fixed_32_matches_rfc6979_octets();
	test_fixed_x_mod_order_matches_reference();
	test_fixed_ecdsa_recombination_matches_reference();
	return 0;
}
