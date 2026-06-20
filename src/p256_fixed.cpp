#include "crypto_core/internal/p256_fixed.hpp"

#include "crypto_core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto_core::internal
{
namespace
{

constexpr std::size_t coordinate_size = 32;
constexpr std::size_t limb_count = 8;
constexpr std::size_t wide_limb_count = 16;

struct U256 final
{
	std::array<std::uint32_t, limb_count> limbs{};
};

struct U512 final
{
	std::array<std::uint32_t, wide_limb_count> limbs{};
};

struct AffinePoint final
{
	U256 x;
	U256 y;
	bool infinity{false};
};

struct JacobianPoint final
{
	U256 x;
	U256 y;
	U256 z;
	bool infinity{false};
};

constexpr U256 p_value{{0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU}};
constexpr U256 a_value{{0xFFFFFFFCU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU}};
constexpr U256 b_value{{0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U,
    0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U}};
constexpr U256 gx_value{{0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U,
    0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U}};
constexpr U256 gy_value{{0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U,
    0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U}};
constexpr U256 n_value{{0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU}};
constexpr U256 p_minus_two_value{{0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU}};
constexpr U256 n_minus_two_value{{0xFC63254FU, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU}};

[[nodiscard]] Error fixed_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "p256_fixed", message);
}

[[nodiscard]] U256 zero() noexcept
{
	return U256{};
}

[[nodiscard]] U256 one() noexcept
{
	U256 value{};
	value.limbs[0] = 1;
	return value;
}

[[nodiscard]] U256 word(std::uint32_t value) noexcept
{
	U256 output{};
	output.limbs[0] = value;
	return output;
}

[[nodiscard]] bool is_zero(const U256 &value) noexcept
{
	for (const auto limb : value.limbs)
	{
		if (limb != 0)
		{
			return false;
		}
	}
	return true;
}

[[nodiscard]] int compare(const U256 &lhs, const U256 &rhs) noexcept
{
	for (std::size_t i = limb_count; i > 0; --i)
	{
		const auto left = lhs.limbs[i - 1U];
		const auto right = rhs.limbs[i - 1U];
		if (left < right)
		{
			return -1;
		}
		if (left > right)
		{
			return 1;
		}
	}
	return 0;
}

[[nodiscard]] U256 subtract_wrapped(const U256 &lhs, const U256 &rhs) noexcept
{
	U256 output{};
	std::uint64_t borrow = 0;
	for (std::size_t i = 0; i < limb_count; ++i)
	{
		const auto left = static_cast<std::uint64_t>(lhs.limbs[i]);
		const auto right = static_cast<std::uint64_t>(rhs.limbs[i]) + borrow;
		if (left >= right)
		{
			output.limbs[i] = static_cast<std::uint32_t>(left - right);
			borrow = 0;
		}
		else
		{
			output.limbs[i] = static_cast<std::uint32_t>((std::uint64_t{1} << 32U) + left - right);
			borrow = 1;
		}
	}
	return output;
}

[[nodiscard]] U256 subtract_checked(const U256 &lhs, const U256 &rhs) noexcept
{
	return subtract_wrapped(lhs, rhs);
}

[[nodiscard]] U512 multiply_wide(const U256 &lhs, const U256 &rhs) noexcept
{
	U512 output{};
	for (std::size_t i = 0; i < limb_count; ++i)
	{
		std::uint64_t carry = 0;
		for (std::size_t j = 0; j < limb_count; ++j)
		{
			const auto index = i + j;
			const auto product = static_cast<std::uint64_t>(lhs.limbs[i]) * rhs.limbs[j] + output.limbs[index] + carry;
			output.limbs[index] = static_cast<std::uint32_t>(product);
			carry = product >> 32U;
		}

		auto index = i + limb_count;
		while (carry != 0 && index < wide_limb_count)
		{
			const auto sum = static_cast<std::uint64_t>(output.limbs[index]) + carry;
			output.limbs[index] = static_cast<std::uint32_t>(sum);
			carry = sum >> 32U;
			++index;
		}
	}
	return output;
}

[[nodiscard]] bool bit_at(const U512 &value, std::size_t bit) noexcept
{
	const auto limb = bit / 32U;
	const auto offset = bit % 32U;
	return ((value.limbs[limb] >> offset) & 1U) != 0U;
}

[[nodiscard]] bool bit_at(const U256 &value, std::size_t bit) noexcept
{
	const auto limb = bit / 32U;
	const auto offset = bit % 32U;
	return ((value.limbs[limb] >> offset) & 1U) != 0U;
}

[[nodiscard]] bool shift_left_one_add(U256 &value, bool bit) noexcept
{
	std::uint32_t carry = bit ? 1U : 0U;
	for (std::size_t i = 0; i < limb_count; ++i)
	{
		const auto next = value.limbs[i] >> 31U;
		value.limbs[i] = static_cast<std::uint32_t>((value.limbs[i] << 1U) | carry);
		carry = next;
	}
	return carry != 0;
}

[[nodiscard]] U256 reduce_wide(const U512 &value, const U256 &modulus) noexcept
{
	U256 remainder{};
	for (std::size_t i = wide_limb_count * 32U; i > 0; --i)
	{
		const auto carry = shift_left_one_add(remainder, bit_at(value, i - 1U));
		if (carry)
		{
			remainder = subtract_wrapped(remainder, modulus);
		}
		else if (compare(remainder, modulus) >= 0)
		{
			remainder = subtract_checked(remainder, modulus);
		}
	}
	return remainder;
}

[[nodiscard]] U256 reduce_256(const U256 &value, const U256 &modulus) noexcept
{
	U512 wide{};
	std::copy(value.limbs.begin(), value.limbs.end(), wide.limbs.begin());
	return reduce_wide(wide, modulus);
}

[[nodiscard]] U256 mod_add(const U256 &lhs, const U256 &rhs, const U256 &modulus) noexcept
{
	U512 wide{};
	std::uint64_t carry = 0;
	for (std::size_t i = 0; i < limb_count; ++i)
	{
		const auto sum = static_cast<std::uint64_t>(lhs.limbs[i]) + rhs.limbs[i] + carry;
		wide.limbs[i] = static_cast<std::uint32_t>(sum);
		carry = sum >> 32U;
	}
	wide.limbs[limb_count] = static_cast<std::uint32_t>(carry);
	return reduce_wide(wide, modulus);
}

[[nodiscard]] U256 mod_subtract(const U256 &lhs, const U256 &rhs, const U256 &modulus) noexcept
{
	if (compare(lhs, rhs) >= 0)
	{
		return subtract_checked(lhs, rhs);
	}

	const auto delta = subtract_checked(rhs, lhs);
	return subtract_checked(modulus, delta);
}

[[nodiscard]] U256 mod_multiply(const U256 &lhs, const U256 &rhs, const U256 &modulus) noexcept
{
	return reduce_wide(multiply_wide(lhs, rhs), modulus);
}

[[nodiscard]] U256 mod_exp(U256 base, const U256 &exponent, const U256 &modulus) noexcept
{
	auto result = reduce_256(one(), modulus);
	base = reduce_256(base, modulus);
	for (std::size_t i = limb_count * 32U; i > 0; --i)
	{
		result = mod_multiply(result, result, modulus);
		if (bit_at(exponent, i - 1U))
		{
			result = mod_multiply(result, base, modulus);
		}
	}
	return result;
}

[[nodiscard]] U256 field_add(const U256 &lhs, const U256 &rhs) noexcept
{
	return mod_add(lhs, rhs, p_value);
}

[[nodiscard]] U256 field_subtract(const U256 &lhs, const U256 &rhs) noexcept
{
	return mod_subtract(lhs, rhs, p_value);
}

[[nodiscard]] U256 field_multiply(const U256 &lhs, const U256 &rhs) noexcept
{
	return mod_multiply(lhs, rhs, p_value);
}

[[nodiscard]] U256 field_inverse(const U256 &value) noexcept
{
	return mod_exp(value, p_minus_two_value, p_value);
}

[[nodiscard]] U256 scalar_reduce(const U256 &value) noexcept
{
	return reduce_256(value, n_value);
}

[[nodiscard]] Result<U256> u256_from_be(std::span<const std::uint8_t> bytes)
{
	while (!bytes.empty() && bytes.front() == 0)
	{
		bytes = bytes.subspan(1);
	}
	if (bytes.size() > coordinate_size)
	{
		return Result<U256>::failure(fixed_error(ErrorCode::invalid_argument, "integer exceeds 256 bits"));
	}

	U256 output{};
	std::size_t byte_index = bytes.size();
	for (std::size_t limb_index = 0; limb_index < limb_count; ++limb_index)
	{
		std::uint32_t limb = 0;
		for (std::size_t i = 0; i < 4 && byte_index > 0; ++i)
		{
			--byte_index;
			limb |= static_cast<std::uint32_t>(bytes[byte_index]) << (i * 8U);
		}
		output.limbs[limb_index] = limb;
	}
	return Result<U256>::success(output);
}

[[nodiscard]] Result<U256> coordinate_from_be(std::span<const std::uint8_t> bytes)
{
	if (bytes.size() != coordinate_size)
	{
		return Result<U256>::failure(fixed_error(ErrorCode::invalid_argument, "P-256 coordinates must be 32 bytes"));
	}
	auto value = u256_from_be(bytes);
	if (!value)
	{
		return Result<U256>::failure(value.error());
	}
	if (compare(value.value(), p_value) >= 0)
	{
		return Result<U256>::failure(fixed_error(ErrorCode::invalid_key, "P-256 coordinate exceeds field"));
	}
	return value;
}

[[nodiscard]] Result<U256> scalar_from_be_reduced(std::span<const std::uint8_t> bytes)
{
	auto value = u256_from_be(bytes);
	if (!value)
	{
		return Result<U256>::failure(value.error());
	}
	return Result<U256>::success(scalar_reduce(value.value()));
}

[[nodiscard]] ByteBuffer to_be_bytes_minimal(const U256 &value)
{
	if (is_zero(value))
	{
		return ByteBuffer(std::vector<std::uint8_t>{0});
	}

	std::vector<std::uint8_t> bytes;
	bytes.reserve(coordinate_size);
	for (std::size_t i = limb_count; i > 0; --i)
	{
		const auto limb = value.limbs[i - 1U];
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

[[nodiscard]] ByteBuffer to_be_bytes_fixed(const U256 &value)
{
	std::vector<std::uint8_t> bytes(coordinate_size);
	for (std::size_t i = 0; i < limb_count; ++i)
	{
		const auto limb = value.limbs[i];
		const auto offset = coordinate_size - ((i + 1U) * 4U);
		bytes[offset] = static_cast<std::uint8_t>((limb >> 24U) & 0xFFU);
		bytes[offset + 1U] = static_cast<std::uint8_t>((limb >> 16U) & 0xFFU);
		bytes[offset + 2U] = static_cast<std::uint8_t>((limb >> 8U) & 0xFFU);
		bytes[offset + 3U] = static_cast<std::uint8_t>(limb & 0xFFU);
	}
	return ByteBuffer(std::move(bytes));
}

[[nodiscard]] Result<P256Point> make_point(const U256 &x, const U256 &y)
{
	return Result<P256Point>::success(P256Point{to_be_bytes_fixed(x), to_be_bytes_fixed(y), false});
}

[[nodiscard]] Result<AffinePoint> load_affine(const P256Point &point)
{
	if (point.infinity)
	{
		return Result<AffinePoint>::success(AffinePoint{zero(), zero(), true});
	}
	auto x = coordinate_from_be(point.x.bytes());
	if (!x)
	{
		return Result<AffinePoint>::failure(x.error());
	}
	auto y = coordinate_from_be(point.y.bytes());
	if (!y)
	{
		return Result<AffinePoint>::failure(y.error());
	}
	return Result<AffinePoint>::success(AffinePoint{x.value(), y.value(), false});
}

[[nodiscard]] bool is_on_curve_affine(const AffinePoint &point) noexcept
{
	if (point.infinity)
	{
		return false;
	}

	const auto y_squared = field_multiply(point.y, point.y);
	const auto x_squared = field_multiply(point.x, point.x);
	const auto x_cubed = field_multiply(x_squared, point.x);
	const auto ax = field_multiply(a_value, point.x);
	const auto rhs = field_add(field_add(x_cubed, ax), b_value);
	return compare(y_squared, rhs) == 0;
}

[[nodiscard]] Result<AffinePoint> require_affine_on_curve(const P256Point &point)
{
	auto affine = load_affine(point);
	if (!affine)
	{
		return Result<AffinePoint>::failure(affine.error());
	}
	if (affine.value().infinity || !is_on_curve_affine(affine.value()))
	{
		return Result<AffinePoint>::failure(fixed_error(ErrorCode::invalid_key, "P-256 point is not on the curve"));
	}
	return affine;
}

[[nodiscard]] Result<P256Point> point_double_affine(const AffinePoint &point)
{
	if (point.infinity || is_zero(point.y))
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}

	const auto x_squared = field_multiply(point.x, point.x);
	const auto numerator = field_add(field_multiply(word(3), x_squared), a_value);
	const auto denominator = field_multiply(word(2), point.y);
	const auto slope = field_multiply(numerator, field_inverse(denominator));
	const auto x3 = field_subtract(field_multiply(slope, slope), field_multiply(word(2), point.x));
	const auto y3 = field_subtract(field_multiply(slope, field_subtract(point.x, x3)), point.y);
	return make_point(x3, y3);
}

[[nodiscard]] Result<JacobianPoint> jacobian_infinity()
{
	return Result<JacobianPoint>::success(JacobianPoint{zero(), zero(), zero(), true});
}

[[nodiscard]] JacobianPoint affine_to_jacobian(const AffinePoint &point) noexcept
{
	if (point.infinity)
	{
		return JacobianPoint{zero(), zero(), zero(), true};
	}
	return JacobianPoint{point.x, point.y, one(), false};
}

[[nodiscard]] Result<JacobianPoint> jacobian_double(const JacobianPoint &point)
{
	if (point.infinity || is_zero(point.y))
	{
		return jacobian_infinity();
	}

	const auto xx = field_multiply(point.x, point.x);
	const auto yy = field_multiply(point.y, point.y);
	const auto yyyy = field_multiply(yy, yy);
	const auto zz = field_multiply(point.z, point.z);
	const auto x_plus_yy = field_add(point.x, yy);
	const auto s_half = field_subtract(field_subtract(field_multiply(x_plus_yy, x_plus_yy), xx), yyyy);
	const auto s = field_multiply(word(2), s_half);
	const auto a_zz_squared = field_multiply(a_value, field_multiply(zz, zz));
	const auto m = field_add(field_multiply(word(3), xx), a_zz_squared);
	const auto x3 = field_subtract(field_multiply(m, m), field_multiply(word(2), s));
	const auto y3 = field_subtract(field_multiply(m, field_subtract(s, x3)), field_multiply(word(8), yyyy));
	const auto y_plus_z = field_add(point.y, point.z);
	const auto z3 = field_subtract(field_subtract(field_multiply(y_plus_z, y_plus_z), yy), zz);
	if (is_zero(z3))
	{
		return jacobian_infinity();
	}
	return Result<JacobianPoint>::success(JacobianPoint{x3, y3, z3, false});
}

[[nodiscard]] Result<JacobianPoint> jacobian_add_affine(const JacobianPoint &lhs, const AffinePoint &rhs)
{
	if (rhs.infinity)
	{
		return Result<JacobianPoint>::success(lhs);
	}
	if (lhs.infinity)
	{
		return Result<JacobianPoint>::success(affine_to_jacobian(rhs));
	}

	const auto z1z1 = field_multiply(lhs.z, lhs.z);
	const auto u2 = field_multiply(rhs.x, z1z1);
	const auto s2 = field_multiply(rhs.y, field_multiply(lhs.z, z1z1));
	const auto h = field_subtract(u2, lhs.x);
	const auto s2_minus_y1 = field_subtract(s2, lhs.y);
	if (is_zero(h))
	{
		if (is_zero(s2_minus_y1))
		{
			return jacobian_double(lhs);
		}
		return jacobian_infinity();
	}

	const auto hh = field_multiply(h, h);
	const auto i = field_multiply(word(4), hh);
	const auto j = field_multiply(h, i);
	const auto r = field_multiply(word(2), s2_minus_y1);
	const auto v = field_multiply(lhs.x, i);
	const auto x3 = field_subtract(field_subtract(field_multiply(r, r), j), field_multiply(word(2), v));
	const auto y3 = field_subtract(field_multiply(r, field_subtract(v, x3)), field_multiply(word(2), field_multiply(lhs.y, j)));
	const auto z1_plus_h = field_add(lhs.z, h);
	const auto z3 = field_subtract(field_subtract(field_multiply(z1_plus_h, z1_plus_h), z1z1), hh);
	if (is_zero(z3))
	{
		return jacobian_infinity();
	}
	return Result<JacobianPoint>::success(JacobianPoint{x3, y3, z3, false});
}

[[nodiscard]] Result<P256Point> jacobian_to_affine(const JacobianPoint &point)
{
	if (point.infinity)
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}

	const auto z_inverse = field_inverse(point.z);
	const auto z_inverse_squared = field_multiply(z_inverse, z_inverse);
	const auto z_inverse_cubed = field_multiply(z_inverse_squared, z_inverse);
	return make_point(field_multiply(point.x, z_inverse_squared), field_multiply(point.y, z_inverse_cubed));
}

} // namespace

Result<P256Point> p256_fixed_point_from_coordinates(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y)
{
	auto point = P256Point{ByteBuffer::copy_from(x), ByteBuffer::copy_from(y), false};
	auto affine = require_affine_on_curve(point);
	if (!affine)
	{
		return Result<P256Point>::failure(affine.error());
	}
	return Result<P256Point>::success(std::move(point));
}

Result<bool> p256_fixed_is_on_curve(const P256Point &point)
{
	auto affine = load_affine(point);
	if (!affine)
	{
		return Result<bool>::failure(affine.error());
	}
	return Result<bool>::success(is_on_curve_affine(affine.value()));
}

Result<P256Point> p256_fixed_point_add(const P256Point &lhs, const P256Point &rhs)
{
	if (lhs.infinity)
	{
		if (rhs.infinity)
		{
			return Result<P256Point>::success(p256_point_at_infinity());
		}
		return p256_fixed_point_from_coordinates(rhs.x.bytes(), rhs.y.bytes());
	}
	if (rhs.infinity)
	{
		return p256_fixed_point_from_coordinates(lhs.x.bytes(), lhs.y.bytes());
	}

	auto left = require_affine_on_curve(lhs);
	if (!left)
	{
		return Result<P256Point>::failure(left.error());
	}
	auto right = require_affine_on_curve(rhs);
	if (!right)
	{
		return Result<P256Point>::failure(right.error());
	}

	if (compare(left.value().x, right.value().x) == 0)
	{
		if (is_zero(field_add(left.value().y, right.value().y)))
		{
			return Result<P256Point>::success(p256_point_at_infinity());
		}
		return point_double_affine(left.value());
	}

	const auto numerator = field_subtract(right.value().y, left.value().y);
	const auto denominator = field_subtract(right.value().x, left.value().x);
	const auto slope = field_multiply(numerator, field_inverse(denominator));
	const auto x3 = field_subtract(field_subtract(field_multiply(slope, slope), left.value().x), right.value().x);
	const auto y3 = field_subtract(field_multiply(slope, field_subtract(left.value().x, x3)), left.value().y);
	return make_point(x3, y3);
}

Result<P256Point> p256_fixed_scalar_multiply(std::span<const std::uint8_t> scalar, const P256Point &point)
{
	if (point.infinity)
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}
	auto addend = require_affine_on_curve(point);
	if (!addend)
	{
		return Result<P256Point>::failure(addend.error());
	}

	auto result = jacobian_infinity();
	if (!result)
	{
		return Result<P256Point>::failure(result.error());
	}
	for (const auto byte : scalar)
	{
		for (int bit = 7; bit >= 0; --bit)
		{
			auto doubled = jacobian_double(result.value());
			if (!doubled)
			{
				return Result<P256Point>::failure(doubled.error());
			}
			result = std::move(doubled);

			if (((byte >> static_cast<std::uint8_t>(bit)) & 0x01U) != 0U)
			{
				auto added = jacobian_add_affine(result.value(), addend.value());
				if (!added)
				{
					return Result<P256Point>::failure(added.error());
				}
				result = std::move(added);
			}
		}
	}
	return jacobian_to_affine(result.value());
}

Result<P256Point> p256_fixed_base_point_multiply(std::span<const std::uint8_t> scalar)
{
	auto base = make_point(gx_value, gy_value);
	if (!base)
	{
		return Result<P256Point>::failure(base.error());
	}
	return p256_fixed_scalar_multiply(scalar, base.value());
}

Result<ByteBuffer> p256_fixed_scalar_inverse(std::span<const std::uint8_t> scalar)
{
	auto reduced = scalar_from_be_reduced(scalar);
	if (!reduced)
	{
		return Result<ByteBuffer>::failure(reduced.error());
	}
	if (is_zero(reduced.value()))
	{
		return Result<ByteBuffer>::failure(fixed_error(ErrorCode::invalid_argument, "scalar has no inverse"));
	}
	return Result<ByteBuffer>::success(to_be_bytes_minimal(mod_exp(reduced.value(), n_minus_two_value, n_value)));
}

Result<ByteBuffer> p256_fixed_scalar_add_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs)
{
	auto left = scalar_from_be_reduced(lhs);
	if (!left)
	{
		return Result<ByteBuffer>::failure(left.error());
	}
	auto right = scalar_from_be_reduced(rhs);
	if (!right)
	{
		return Result<ByteBuffer>::failure(right.error());
	}
	return Result<ByteBuffer>::success(to_be_bytes_minimal(mod_add(left.value(), right.value(), n_value)));
}

Result<ByteBuffer> p256_fixed_scalar_multiply_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs)
{
	auto left = scalar_from_be_reduced(lhs);
	if (!left)
	{
		return Result<ByteBuffer>::failure(left.error());
	}
	auto right = scalar_from_be_reduced(rhs);
	if (!right)
	{
		return Result<ByteBuffer>::failure(right.error());
	}
	return Result<ByteBuffer>::success(to_be_bytes_minimal(mod_multiply(left.value(), right.value(), n_value)));
}

Result<ByteBuffer> p256_fixed_x_mod_order(const P256Point &point)
{
	auto affine = require_affine_on_curve(point);
	if (!affine)
	{
		return Result<ByteBuffer>::failure(affine.error());
	}
	return Result<ByteBuffer>::success(to_be_bytes_minimal(scalar_reduce(affine.value().x)));
}

Result<bool> p256_fixed_scalar_is_valid_nonzero(std::span<const std::uint8_t> scalar)
{
	while (!scalar.empty() && scalar.front() == 0)
	{
		scalar = scalar.subspan(1);
	}
	if (scalar.size() > coordinate_size)
	{
		return Result<bool>::success(false);
	}
	auto value = u256_from_be(scalar);
	if (!value)
	{
		return Result<bool>::failure(value.error());
	}
	return Result<bool>::success(!is_zero(value.value()) && compare(value.value(), n_value) < 0);
}

} // namespace crypto_core::internal
