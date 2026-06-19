#include "crypto_core/internal/p256.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"

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

constexpr std::array<std::uint8_t, coordinate_size> p_bytes{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr std::array<std::uint8_t, coordinate_size> a_bytes{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
constexpr std::array<std::uint8_t, coordinate_size> b_bytes{
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
constexpr std::array<std::uint8_t, coordinate_size> gx_bytes{
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
constexpr std::array<std::uint8_t, coordinate_size> gy_bytes{
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
constexpr std::array<std::uint8_t, coordinate_size> n_bytes{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
constexpr std::array<std::uint8_t, coordinate_size> p_minus_two_bytes{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD};
constexpr std::array<std::uint8_t, coordinate_size> n_minus_two_bytes{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F};

[[nodiscard]] Error p256_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "p256", message);
}

[[nodiscard]] Result<BigInt> bigint(std::span<const std::uint8_t> bytes)
{
	return BigInt::from_be_bytes(bytes);
}

[[nodiscard]] Result<BigInt> zero_bigint()
{
	const std::array<std::uint8_t, 1> zero{0x00};
	return bigint(zero);
}

[[nodiscard]] Result<BigInt> one_bigint()
{
	const std::array<std::uint8_t, 1> one{0x01};
	return bigint(one);
}

[[nodiscard]] Result<BigInt> two_bigint()
{
	const std::array<std::uint8_t, 1> two{0x02};
	return bigint(two);
}

[[nodiscard]] Result<BigInt> three_bigint()
{
	const std::array<std::uint8_t, 1> three{0x03};
	return bigint(three);
}

[[nodiscard]] Result<BigInt> four_bigint()
{
	const std::array<std::uint8_t, 1> four{0x04};
	return bigint(four);
}

[[nodiscard]] Result<BigInt> eight_bigint()
{
	const std::array<std::uint8_t, 1> eight{0x08};
	return bigint(eight);
}

[[nodiscard]] Result<BigInt> field_modulus()
{
	return bigint(p_bytes);
}

[[nodiscard]] Result<BigInt> scalar_modulus()
{
	return bigint(n_bytes);
}

[[nodiscard]] Result<BigInt> curve_a()
{
	return bigint(a_bytes);
}

[[nodiscard]] Result<BigInt> curve_b()
{
	return bigint(b_bytes);
}

[[nodiscard]] Result<BigInt> field_inverse_exponent()
{
	return bigint(p_minus_two_bytes);
}

[[nodiscard]] Result<BigInt> scalar_inverse_exponent()
{
	return bigint(n_minus_two_bytes);
}

[[nodiscard]] Result<BigInt> reduce_mod(const BigInt &value, const BigInt &modulus)
{
	auto zero = zero_bigint();
	if (!zero)
	{
		return Result<BigInt>::failure(zero.error());
	}

	return BigInt::mod_add(value, zero.value(), modulus);
}

[[nodiscard]] Result<BigInt> field_add(const BigInt &lhs, const BigInt &rhs)
{
	auto modulus = field_modulus();
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}

	return BigInt::mod_add(lhs, rhs, modulus.value());
}

[[nodiscard]] Result<BigInt> field_subtract(const BigInt &lhs, const BigInt &rhs)
{
	auto modulus = field_modulus();
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}

	return BigInt::mod_subtract(lhs, rhs, modulus.value());
}

[[nodiscard]] Result<BigInt> field_multiply(const BigInt &lhs, const BigInt &rhs)
{
	auto modulus = field_modulus();
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}

	return BigInt::mod_multiply(lhs, rhs, modulus.value());
}

[[nodiscard]] Result<BigInt> field_inverse(const BigInt &value)
{
	auto modulus = field_modulus();
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}
	auto exponent = field_inverse_exponent();
	if (!exponent)
	{
		return Result<BigInt>::failure(exponent.error());
	}

	return BigInt::mod_exp(value, exponent.value(), modulus.value());
}

[[nodiscard]] Result<BigInt> scalar_reduce(std::span<const std::uint8_t> value)
{
	auto input = bigint(value);
	if (!input)
	{
		return Result<BigInt>::failure(input.error());
	}
	auto modulus = scalar_modulus();
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}

	return reduce_mod(input.value(), modulus.value());
}

[[nodiscard]] Result<ByteBuffer> fixed_32_bytes(const BigInt &value)
{
	auto minimal = value.to_be_bytes();
	if (minimal.size() > coordinate_size)
	{
		return Result<ByteBuffer>::failure(p256_error(ErrorCode::internal_error, "field element is too large"));
	}

	std::vector<std::uint8_t> output(coordinate_size);
	std::copy(minimal.bytes().begin(), minimal.bytes().end(), output.begin() + (coordinate_size - minimal.size()));
	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

[[nodiscard]] Result<P256Point> make_affine_point(const BigInt &x, const BigInt &y)
{
	auto x_bytes = fixed_32_bytes(x);
	if (!x_bytes)
	{
		return Result<P256Point>::failure(x_bytes.error());
	}
	auto y_bytes = fixed_32_bytes(y);
	if (!y_bytes)
	{
		return Result<P256Point>::failure(y_bytes.error());
	}

	return Result<P256Point>::success(P256Point{std::move(x_bytes.value()), std::move(y_bytes.value()), false});
}

struct AffinePoint final
{
	BigInt x;
	BigInt y;
};

struct JacobianPoint final
{
	BigInt x;
	BigInt y;
	BigInt z;
	bool infinity;
};

[[nodiscard]] Result<AffinePoint> load_affine_point(const P256Point &point)
{
	if (point.infinity)
	{
		return Result<AffinePoint>::failure(p256_error(ErrorCode::invalid_argument, "point is at infinity"));
	}
	if (point.x.size() != coordinate_size || point.y.size() != coordinate_size)
	{
		return Result<AffinePoint>::failure(p256_error(ErrorCode::invalid_key, "invalid P-256 coordinate length"));
	}

	auto modulus = field_modulus();
	if (!modulus)
	{
		return Result<AffinePoint>::failure(modulus.error());
	}
	auto x = bigint(point.x.bytes());
	if (!x)
	{
		return Result<AffinePoint>::failure(x.error());
	}
	auto y = bigint(point.y.bytes());
	if (!y)
	{
		return Result<AffinePoint>::failure(y.error());
	}
	if (x.value().compare(modulus.value()) >= 0 || y.value().compare(modulus.value()) >= 0)
	{
		return Result<AffinePoint>::failure(p256_error(ErrorCode::invalid_key, "P-256 coordinate exceeds field"));
	}

	return Result<AffinePoint>::success(AffinePoint{std::move(x.value()), std::move(y.value())});
}

[[nodiscard]] Result<bool> is_on_curve_affine(const AffinePoint &point)
{
	auto y_squared = field_multiply(point.y, point.y);
	if (!y_squared)
	{
		return Result<bool>::failure(y_squared.error());
	}

	auto x_squared = field_multiply(point.x, point.x);
	if (!x_squared)
	{
		return Result<bool>::failure(x_squared.error());
	}
	auto x_cubed = field_multiply(x_squared.value(), point.x);
	if (!x_cubed)
	{
		return Result<bool>::failure(x_cubed.error());
	}
	auto a = curve_a();
	if (!a)
	{
		return Result<bool>::failure(a.error());
	}
	auto ax = field_multiply(a.value(), point.x);
	if (!ax)
	{
		return Result<bool>::failure(ax.error());
	}
	auto b = curve_b();
	if (!b)
	{
		return Result<bool>::failure(b.error());
	}
	auto rhs_without_b = field_add(x_cubed.value(), ax.value());
	if (!rhs_without_b)
	{
		return Result<bool>::failure(rhs_without_b.error());
	}
	auto rhs = field_add(rhs_without_b.value(), b.value());
	if (!rhs)
	{
		return Result<bool>::failure(rhs.error());
	}

	return Result<bool>::success(y_squared.value().compare(rhs.value()) == 0);
}

[[nodiscard]] Result<void> require_on_curve_affine(const AffinePoint &point)
{
	auto on_curve = is_on_curve_affine(point);
	if (!on_curve)
	{
		return Result<void>::failure(on_curve.error());
	}
	if (!on_curve.value())
	{
		return Result<void>::failure(p256_error(ErrorCode::invalid_key, "P-256 point is not on the curve"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<P256Point> point_double(const AffinePoint &point)
{
	if (point.y.is_zero())
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}

	auto three = three_bigint();
	if (!three)
	{
		return Result<P256Point>::failure(three.error());
	}
	auto two = two_bigint();
	if (!two)
	{
		return Result<P256Point>::failure(two.error());
	}
	auto x_squared = field_multiply(point.x, point.x);
	if (!x_squared)
	{
		return Result<P256Point>::failure(x_squared.error());
	}
	auto three_x_squared = field_multiply(three.value(), x_squared.value());
	if (!three_x_squared)
	{
		return Result<P256Point>::failure(three_x_squared.error());
	}
	auto a = curve_a();
	if (!a)
	{
		return Result<P256Point>::failure(a.error());
	}
	auto numerator = field_add(three_x_squared.value(), a.value());
	if (!numerator)
	{
		return Result<P256Point>::failure(numerator.error());
	}
	auto denominator = field_multiply(two.value(), point.y);
	if (!denominator)
	{
		return Result<P256Point>::failure(denominator.error());
	}
	auto denominator_inverse = field_inverse(denominator.value());
	if (!denominator_inverse)
	{
		return Result<P256Point>::failure(denominator_inverse.error());
	}
	auto slope = field_multiply(numerator.value(), denominator_inverse.value());
	if (!slope)
	{
		return Result<P256Point>::failure(slope.error());
	}
	auto slope_squared = field_multiply(slope.value(), slope.value());
	if (!slope_squared)
	{
		return Result<P256Point>::failure(slope_squared.error());
	}
	auto two_x = field_multiply(two.value(), point.x);
	if (!two_x)
	{
		return Result<P256Point>::failure(two_x.error());
	}
	auto x3 = field_subtract(slope_squared.value(), two_x.value());
	if (!x3)
	{
		return Result<P256Point>::failure(x3.error());
	}
	auto x_minus_x3 = field_subtract(point.x, x3.value());
	if (!x_minus_x3)
	{
		return Result<P256Point>::failure(x_minus_x3.error());
	}
	auto slope_times_delta = field_multiply(slope.value(), x_minus_x3.value());
	if (!slope_times_delta)
	{
		return Result<P256Point>::failure(slope_times_delta.error());
	}
	auto y3 = field_subtract(slope_times_delta.value(), point.y);
	if (!y3)
	{
		return Result<P256Point>::failure(y3.error());
	}

	return make_affine_point(x3.value(), y3.value());
}

[[nodiscard]] Result<JacobianPoint> jacobian_infinity()
{
	auto zero = zero_bigint();
	if (!zero)
	{
		return Result<JacobianPoint>::failure(zero.error());
	}

	return Result<JacobianPoint>::success(JacobianPoint{zero.value(), zero.value(), zero.value(), true});
}

[[nodiscard]] Result<JacobianPoint> affine_to_jacobian(const AffinePoint &point)
{
	auto one = one_bigint();
	if (!one)
	{
		return Result<JacobianPoint>::failure(one.error());
	}

	return Result<JacobianPoint>::success(JacobianPoint{point.x, point.y, std::move(one.value()), false});
}

[[nodiscard]] Result<JacobianPoint> jacobian_double(const JacobianPoint &point)
{
	if (point.infinity || point.y.is_zero())
	{
		return jacobian_infinity();
	}

	auto two = two_bigint();
	if (!two)
	{
		return Result<JacobianPoint>::failure(two.error());
	}
	auto three = three_bigint();
	if (!three)
	{
		return Result<JacobianPoint>::failure(three.error());
	}
	auto eight = eight_bigint();
	if (!eight)
	{
		return Result<JacobianPoint>::failure(eight.error());
	}

	auto xx = field_multiply(point.x, point.x);
	if (!xx)
	{
		return Result<JacobianPoint>::failure(xx.error());
	}
	auto yy = field_multiply(point.y, point.y);
	if (!yy)
	{
		return Result<JacobianPoint>::failure(yy.error());
	}
	auto yyyy = field_multiply(yy.value(), yy.value());
	if (!yyyy)
	{
		return Result<JacobianPoint>::failure(yyyy.error());
	}
	auto zz = field_multiply(point.z, point.z);
	if (!zz)
	{
		return Result<JacobianPoint>::failure(zz.error());
	}
	auto x_plus_yy = field_add(point.x, yy.value());
	if (!x_plus_yy)
	{
		return Result<JacobianPoint>::failure(x_plus_yy.error());
	}
	auto x_plus_yy_squared = field_multiply(x_plus_yy.value(), x_plus_yy.value());
	if (!x_plus_yy_squared)
	{
		return Result<JacobianPoint>::failure(x_plus_yy_squared.error());
	}
	auto s_without_yyyy = field_subtract(x_plus_yy_squared.value(), xx.value());
	if (!s_without_yyyy)
	{
		return Result<JacobianPoint>::failure(s_without_yyyy.error());
	}
	auto s_half = field_subtract(s_without_yyyy.value(), yyyy.value());
	if (!s_half)
	{
		return Result<JacobianPoint>::failure(s_half.error());
	}
	auto s = field_multiply(two.value(), s_half.value());
	if (!s)
	{
		return Result<JacobianPoint>::failure(s.error());
	}
	auto zz_squared = field_multiply(zz.value(), zz.value());
	if (!zz_squared)
	{
		return Result<JacobianPoint>::failure(zz_squared.error());
	}
	auto a = curve_a();
	if (!a)
	{
		return Result<JacobianPoint>::failure(a.error());
	}
	auto a_zz_squared = field_multiply(a.value(), zz_squared.value());
	if (!a_zz_squared)
	{
		return Result<JacobianPoint>::failure(a_zz_squared.error());
	}
	auto three_xx = field_multiply(three.value(), xx.value());
	if (!three_xx)
	{
		return Result<JacobianPoint>::failure(three_xx.error());
	}
	auto m = field_add(three_xx.value(), a_zz_squared.value());
	if (!m)
	{
		return Result<JacobianPoint>::failure(m.error());
	}
	auto m_squared = field_multiply(m.value(), m.value());
	if (!m_squared)
	{
		return Result<JacobianPoint>::failure(m_squared.error());
	}
	auto two_s = field_multiply(two.value(), s.value());
	if (!two_s)
	{
		return Result<JacobianPoint>::failure(two_s.error());
	}
	auto x3 = field_subtract(m_squared.value(), two_s.value());
	if (!x3)
	{
		return Result<JacobianPoint>::failure(x3.error());
	}
	auto s_minus_x3 = field_subtract(s.value(), x3.value());
	if (!s_minus_x3)
	{
		return Result<JacobianPoint>::failure(s_minus_x3.error());
	}
	auto m_times_delta = field_multiply(m.value(), s_minus_x3.value());
	if (!m_times_delta)
	{
		return Result<JacobianPoint>::failure(m_times_delta.error());
	}
	auto eight_yyyy = field_multiply(eight.value(), yyyy.value());
	if (!eight_yyyy)
	{
		return Result<JacobianPoint>::failure(eight_yyyy.error());
	}
	auto y3 = field_subtract(m_times_delta.value(), eight_yyyy.value());
	if (!y3)
	{
		return Result<JacobianPoint>::failure(y3.error());
	}
	auto y_plus_z = field_add(point.y, point.z);
	if (!y_plus_z)
	{
		return Result<JacobianPoint>::failure(y_plus_z.error());
	}
	auto y_plus_z_squared = field_multiply(y_plus_z.value(), y_plus_z.value());
	if (!y_plus_z_squared)
	{
		return Result<JacobianPoint>::failure(y_plus_z_squared.error());
	}
	auto z_without_yy = field_subtract(y_plus_z_squared.value(), yy.value());
	if (!z_without_yy)
	{
		return Result<JacobianPoint>::failure(z_without_yy.error());
	}
	auto z3 = field_subtract(z_without_yy.value(), zz.value());
	if (!z3)
	{
		return Result<JacobianPoint>::failure(z3.error());
	}
	if (z3.value().is_zero())
	{
		return jacobian_infinity();
	}

	return Result<JacobianPoint>::success(JacobianPoint{std::move(x3.value()), std::move(y3.value()), std::move(z3.value()), false});
}

[[nodiscard]] Result<JacobianPoint> jacobian_add_affine(const JacobianPoint &lhs, const AffinePoint &rhs)
{
	if (lhs.infinity)
	{
		return affine_to_jacobian(rhs);
	}

	auto two = two_bigint();
	if (!two)
	{
		return Result<JacobianPoint>::failure(two.error());
	}
	auto four = four_bigint();
	if (!four)
	{
		return Result<JacobianPoint>::failure(four.error());
	}

	auto z1z1 = field_multiply(lhs.z, lhs.z);
	if (!z1z1)
	{
		return Result<JacobianPoint>::failure(z1z1.error());
	}
	auto u2 = field_multiply(rhs.x, z1z1.value());
	if (!u2)
	{
		return Result<JacobianPoint>::failure(u2.error());
	}
	auto z1_times_z1z1 = field_multiply(lhs.z, z1z1.value());
	if (!z1_times_z1z1)
	{
		return Result<JacobianPoint>::failure(z1_times_z1z1.error());
	}
	auto s2 = field_multiply(rhs.y, z1_times_z1z1.value());
	if (!s2)
	{
		return Result<JacobianPoint>::failure(s2.error());
	}
	auto h = field_subtract(u2.value(), lhs.x);
	if (!h)
	{
		return Result<JacobianPoint>::failure(h.error());
	}
	auto s2_minus_y1 = field_subtract(s2.value(), lhs.y);
	if (!s2_minus_y1)
	{
		return Result<JacobianPoint>::failure(s2_minus_y1.error());
	}
	if (h.value().is_zero())
	{
		if (s2_minus_y1.value().is_zero())
		{
			return jacobian_double(lhs);
		}
		return jacobian_infinity();
	}

	auto hh = field_multiply(h.value(), h.value());
	if (!hh)
	{
		return Result<JacobianPoint>::failure(hh.error());
	}
	auto i = field_multiply(four.value(), hh.value());
	if (!i)
	{
		return Result<JacobianPoint>::failure(i.error());
	}
	auto j = field_multiply(h.value(), i.value());
	if (!j)
	{
		return Result<JacobianPoint>::failure(j.error());
	}
	auto r = field_multiply(two.value(), s2_minus_y1.value());
	if (!r)
	{
		return Result<JacobianPoint>::failure(r.error());
	}
	auto v = field_multiply(lhs.x, i.value());
	if (!v)
	{
		return Result<JacobianPoint>::failure(v.error());
	}
	auto r_squared = field_multiply(r.value(), r.value());
	if (!r_squared)
	{
		return Result<JacobianPoint>::failure(r_squared.error());
	}
	auto r_squared_minus_j = field_subtract(r_squared.value(), j.value());
	if (!r_squared_minus_j)
	{
		return Result<JacobianPoint>::failure(r_squared_minus_j.error());
	}
	auto two_v = field_multiply(two.value(), v.value());
	if (!two_v)
	{
		return Result<JacobianPoint>::failure(two_v.error());
	}
	auto x3 = field_subtract(r_squared_minus_j.value(), two_v.value());
	if (!x3)
	{
		return Result<JacobianPoint>::failure(x3.error());
	}
	auto v_minus_x3 = field_subtract(v.value(), x3.value());
	if (!v_minus_x3)
	{
		return Result<JacobianPoint>::failure(v_minus_x3.error());
	}
	auto r_times_delta = field_multiply(r.value(), v_minus_x3.value());
	if (!r_times_delta)
	{
		return Result<JacobianPoint>::failure(r_times_delta.error());
	}
	auto y1_j = field_multiply(lhs.y, j.value());
	if (!y1_j)
	{
		return Result<JacobianPoint>::failure(y1_j.error());
	}
	auto two_y1_j = field_multiply(two.value(), y1_j.value());
	if (!two_y1_j)
	{
		return Result<JacobianPoint>::failure(two_y1_j.error());
	}
	auto y3 = field_subtract(r_times_delta.value(), two_y1_j.value());
	if (!y3)
	{
		return Result<JacobianPoint>::failure(y3.error());
	}
	auto z1_plus_h = field_add(lhs.z, h.value());
	if (!z1_plus_h)
	{
		return Result<JacobianPoint>::failure(z1_plus_h.error());
	}
	auto z1_plus_h_squared = field_multiply(z1_plus_h.value(), z1_plus_h.value());
	if (!z1_plus_h_squared)
	{
		return Result<JacobianPoint>::failure(z1_plus_h_squared.error());
	}
	auto z_without_z1z1 = field_subtract(z1_plus_h_squared.value(), z1z1.value());
	if (!z_without_z1z1)
	{
		return Result<JacobianPoint>::failure(z_without_z1z1.error());
	}
	auto z3 = field_subtract(z_without_z1z1.value(), hh.value());
	if (!z3)
	{
		return Result<JacobianPoint>::failure(z3.error());
	}
	if (z3.value().is_zero())
	{
		return jacobian_infinity();
	}

	return Result<JacobianPoint>::success(JacobianPoint{std::move(x3.value()), std::move(y3.value()), std::move(z3.value()), false});
}

[[nodiscard]] Result<P256Point> jacobian_to_affine(const JacobianPoint &point)
{
	if (point.infinity)
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}

	auto z_inverse = field_inverse(point.z);
	if (!z_inverse)
	{
		return Result<P256Point>::failure(z_inverse.error());
	}
	auto z_inverse_squared = field_multiply(z_inverse.value(), z_inverse.value());
	if (!z_inverse_squared)
	{
		return Result<P256Point>::failure(z_inverse_squared.error());
	}
	auto z_inverse_cubed = field_multiply(z_inverse_squared.value(), z_inverse.value());
	if (!z_inverse_cubed)
	{
		return Result<P256Point>::failure(z_inverse_cubed.error());
	}
	auto x = field_multiply(point.x, z_inverse_squared.value());
	if (!x)
	{
		return Result<P256Point>::failure(x.error());
	}
	auto y = field_multiply(point.y, z_inverse_cubed.value());
	if (!y)
	{
		return Result<P256Point>::failure(y.error());
	}

	return make_affine_point(x.value(), y.value());
}

} // namespace

P256Point p256_point_at_infinity() noexcept
{
	return P256Point{ByteBuffer{}, ByteBuffer{}, true};
}

Result<P256Point> p256_point_from_coordinates(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y)
{
	if (x.size() != coordinate_size || y.size() != coordinate_size)
	{
		return Result<P256Point>::failure(p256_error(ErrorCode::invalid_argument, "P-256 coordinates must be 32 bytes"));
	}

	auto point = P256Point{ByteBuffer::copy_from(x), ByteBuffer::copy_from(y), false};
	auto on_curve = p256_is_on_curve(point);
	if (!on_curve)
	{
		return Result<P256Point>::failure(on_curve.error());
	}
	if (!on_curve.value())
	{
		return Result<P256Point>::failure(p256_error(ErrorCode::invalid_key, "P-256 point is not on the curve"));
	}

	return Result<P256Point>::success(std::move(point));
}

Result<P256Point> p256_base_point()
{
	return p256_point_from_coordinates(gx_bytes, gy_bytes);
}

Result<bool> p256_is_on_curve(const P256Point &point)
{
	if (point.infinity)
	{
		return Result<bool>::success(false);
	}

	auto affine = load_affine_point(point);
	if (!affine)
	{
		return Result<bool>::failure(affine.error());
	}

	return is_on_curve_affine(affine.value());
}

Result<P256Point> p256_point_add(const P256Point &lhs, const P256Point &rhs)
{
	if (lhs.infinity)
	{
		if (rhs.infinity)
		{
			return Result<P256Point>::success(p256_point_at_infinity());
		}
		return p256_point_from_coordinates(rhs.x.bytes(), rhs.y.bytes());
	}
	if (rhs.infinity)
	{
		return p256_point_from_coordinates(lhs.x.bytes(), lhs.y.bytes());
	}

	auto left = load_affine_point(lhs);
	if (!left)
	{
		return Result<P256Point>::failure(left.error());
	}
	auto right = load_affine_point(rhs);
	if (!right)
	{
		return Result<P256Point>::failure(right.error());
	}
	auto left_on_curve = require_on_curve_affine(left.value());
	if (!left_on_curve)
	{
		return Result<P256Point>::failure(left_on_curve.error());
	}
	auto right_on_curve = require_on_curve_affine(right.value());
	if (!right_on_curve)
	{
		return Result<P256Point>::failure(right_on_curve.error());
	}

	if (left.value().x.compare(right.value().x) == 0)
	{
		auto y_sum = field_add(left.value().y, right.value().y);
		if (!y_sum)
		{
			return Result<P256Point>::failure(y_sum.error());
		}
		if (y_sum.value().is_zero())
		{
			return Result<P256Point>::success(p256_point_at_infinity());
		}

		return point_double(left.value());
	}

	auto numerator = field_subtract(right.value().y, left.value().y);
	if (!numerator)
	{
		return Result<P256Point>::failure(numerator.error());
	}
	auto denominator = field_subtract(right.value().x, left.value().x);
	if (!denominator)
	{
		return Result<P256Point>::failure(denominator.error());
	}
	auto denominator_inverse = field_inverse(denominator.value());
	if (!denominator_inverse)
	{
		return Result<P256Point>::failure(denominator_inverse.error());
	}
	auto slope = field_multiply(numerator.value(), denominator_inverse.value());
	if (!slope)
	{
		return Result<P256Point>::failure(slope.error());
	}
	auto slope_squared = field_multiply(slope.value(), slope.value());
	if (!slope_squared)
	{
		return Result<P256Point>::failure(slope_squared.error());
	}
	auto x3_without_right = field_subtract(slope_squared.value(), left.value().x);
	if (!x3_without_right)
	{
		return Result<P256Point>::failure(x3_without_right.error());
	}
	auto x3 = field_subtract(x3_without_right.value(), right.value().x);
	if (!x3)
	{
		return Result<P256Point>::failure(x3.error());
	}
	auto x_delta = field_subtract(left.value().x, x3.value());
	if (!x_delta)
	{
		return Result<P256Point>::failure(x_delta.error());
	}
	auto slope_times_delta = field_multiply(slope.value(), x_delta.value());
	if (!slope_times_delta)
	{
		return Result<P256Point>::failure(slope_times_delta.error());
	}
	auto y3 = field_subtract(slope_times_delta.value(), left.value().y);
	if (!y3)
	{
		return Result<P256Point>::failure(y3.error());
	}

	return make_affine_point(x3.value(), y3.value());
}

Result<P256Point> p256_scalar_multiply(std::span<const std::uint8_t> scalar, const P256Point &point)
{
	if (point.infinity)
	{
		return Result<P256Point>::success(p256_point_at_infinity());
	}

	auto canonical = p256_point_from_coordinates(point.x.bytes(), point.y.bytes());
	if (!canonical)
	{
		return Result<P256Point>::failure(canonical.error());
	}
	auto addend = load_affine_point(canonical.value());
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

Result<P256Point> p256_base_point_multiply(std::span<const std::uint8_t> scalar)
{
	auto base = p256_base_point();
	if (!base)
	{
		return Result<P256Point>::failure(base.error());
	}

	return p256_scalar_multiply(scalar, base.value());
}

Result<ByteBuffer> p256_scalar_inverse(std::span<const std::uint8_t> scalar)
{
	auto reduced = scalar_reduce(scalar);
	if (!reduced)
	{
		return Result<ByteBuffer>::failure(reduced.error());
	}
	if (reduced.value().is_zero())
	{
		return Result<ByteBuffer>::failure(p256_error(ErrorCode::invalid_argument, "scalar has no inverse"));
	}
	auto modulus = scalar_modulus();
	if (!modulus)
	{
		return Result<ByteBuffer>::failure(modulus.error());
	}
	auto exponent = scalar_inverse_exponent();
	if (!exponent)
	{
		return Result<ByteBuffer>::failure(exponent.error());
	}

	auto inverse = BigInt::mod_exp(reduced.value(), exponent.value(), modulus.value());
	if (!inverse)
	{
		return Result<ByteBuffer>::failure(inverse.error());
	}

	return Result<ByteBuffer>::success(inverse.value().to_be_bytes());
}

Result<ByteBuffer> p256_scalar_multiply_mod(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs)
{
	auto left = scalar_reduce(lhs);
	if (!left)
	{
		return Result<ByteBuffer>::failure(left.error());
	}
	auto right = scalar_reduce(rhs);
	if (!right)
	{
		return Result<ByteBuffer>::failure(right.error());
	}
	auto modulus = scalar_modulus();
	if (!modulus)
	{
		return Result<ByteBuffer>::failure(modulus.error());
	}

	auto product = BigInt::mod_multiply(left.value(), right.value(), modulus.value());
	if (!product)
	{
		return Result<ByteBuffer>::failure(product.error());
	}

	return Result<ByteBuffer>::success(product.value().to_be_bytes());
}

Result<ByteBuffer> p256_x_mod_order(const P256Point &point)
{
	if (point.infinity)
	{
		return Result<ByteBuffer>::failure(p256_error(ErrorCode::invalid_key, "point at infinity has no x-coordinate"));
	}
	auto affine = load_affine_point(point);
	if (!affine)
	{
		return Result<ByteBuffer>::failure(affine.error());
	}
	auto on_curve = require_on_curve_affine(affine.value());
	if (!on_curve)
	{
		return Result<ByteBuffer>::failure(on_curve.error());
	}
	auto modulus = scalar_modulus();
	if (!modulus)
	{
		return Result<ByteBuffer>::failure(modulus.error());
	}
	auto reduced = reduce_mod(affine.value().x, modulus.value());
	if (!reduced)
	{
		return Result<ByteBuffer>::failure(reduced.error());
	}

	return Result<ByteBuffer>::success(reduced.value().to_be_bytes());
}

std::span<const std::uint8_t> p256_group_order() noexcept
{
	return n_bytes;
}

} // namespace crypto_core::internal
