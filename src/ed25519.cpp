#include "crypto_core/internal/ed25519.hpp"

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"
#include "crypto_core/internal/sha2.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto_core::internal
{
namespace
{

constexpr std::size_t encoded_point_size = 32;
constexpr std::size_t signature_size = 64;

constexpr std::array<std::uint8_t, 32> field_modulus_bytes{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED};

constexpr std::array<std::uint8_t, 32> group_order_bytes{
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED};

constexpr std::array<std::uint8_t, 32> curve_d_bytes{
    0x52, 0x03, 0x6C, 0xEE, 0x2B, 0x6F, 0xFE, 0x73,
    0x8C, 0xC7, 0x40, 0x79, 0x77, 0x79, 0xE8, 0x98,
    0x00, 0x70, 0x0A, 0x4D, 0x41, 0x41, 0xD8, 0xAB,
    0x75, 0xEB, 0x4D, 0xCA, 0x13, 0x59, 0x78, 0xA3};

constexpr std::array<std::uint8_t, 32> sqrt_minus_one_bytes{
    0x2B, 0x83, 0x24, 0x80, 0x4F, 0xC1, 0xDF, 0x0B,
    0x2B, 0x4D, 0x00, 0x99, 0x3D, 0xFB, 0xD7, 0xA7,
    0x2F, 0x43, 0x18, 0x06, 0xAD, 0x2F, 0xE4, 0x78,
    0xC4, 0xEE, 0x1B, 0x27, 0x4A, 0x0E, 0xA0, 0xB0};

constexpr std::array<std::uint8_t, 32> sqrt_exponent_bytes{
    0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};

constexpr std::array<std::uint8_t, 32> inverse_exponent_bytes{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB};

constexpr std::array<std::uint8_t, 32> base_point_bytes{
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

struct ExtendedPoint final
{
	BigInt x;
	BigInt y;
	BigInt z;
	BigInt t;
};

[[nodiscard]] Error ed25519_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "ed25519", message);
}

[[nodiscard]] Result<BigInt> bigint(std::span<const std::uint8_t> bytes)
{
	return BigInt::from_be_bytes(bytes);
}

[[nodiscard]] Result<BigInt> zero()
{
	const std::array<std::uint8_t, 1> bytes{0x00};
	return bigint(bytes);
}

[[nodiscard]] Result<BigInt> one()
{
	const std::array<std::uint8_t, 1> bytes{0x01};
	return bigint(bytes);
}

[[nodiscard]] Result<BigInt> field_modulus()
{
	return bigint(field_modulus_bytes);
}

[[nodiscard]] Result<BigInt> group_order()
{
	return bigint(group_order_bytes);
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

[[nodiscard]] Result<BigInt> field_square(const BigInt &value)
{
	return field_multiply(value, value);
}

[[nodiscard]] Result<BigInt> field_inverse(const BigInt &value)
{
	auto modulus = field_modulus();
	auto exponent = bigint(inverse_exponent_bytes);
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}
	if (!exponent)
	{
		return Result<BigInt>::failure(exponent.error());
	}
	return BigInt::mod_exp(value, exponent.value(), modulus.value());
}

[[nodiscard]] bool is_odd(const BigInt &value)
{
	auto bytes = value.to_be_bytes();
	const auto span = bytes.bytes();
	return !span.empty() && ((span.back() & 1U) != 0U);
}

[[nodiscard]] Result<BigInt> from_le_bytes(std::span<const std::uint8_t> bytes)
{
	std::vector<std::uint8_t> reversed(bytes.rbegin(), bytes.rend());
	return bigint(reversed);
}

[[nodiscard]] Result<std::vector<std::uint8_t>> to_fixed_le_bytes(const BigInt &value, std::size_t size)
{
	auto be = value.to_be_bytes();
	std::vector<std::uint8_t> output(size);
	const auto bytes = be.bytes();
	if (bytes.size() > size && !(bytes.size() == 1U && bytes[0] == 0))
	{
		return Result<std::vector<std::uint8_t>>::failure(ed25519_error(ErrorCode::invalid_argument, "integer does not fit fixed-width output"));
	}
	for (std::size_t i = 0; i < bytes.size() && i < size; ++i)
	{
		output[i] = bytes[bytes.size() - 1U - i];
	}
	return Result<std::vector<std::uint8_t>>::success(std::move(output));
}

[[nodiscard]] Result<BigInt> reduce_mod_order(std::span<const std::uint8_t> little_endian)
{
	auto value = from_le_bytes(little_endian);
	auto order = group_order();
	auto z = zero();
	if (!value)
	{
		return Result<BigInt>::failure(value.error());
	}
	if (!order)
	{
		return Result<BigInt>::failure(order.error());
	}
	if (!z)
	{
		return Result<BigInt>::failure(z.error());
	}
	return BigInt::mod_add(value.value(), z.value(), order.value());
}

[[nodiscard]] Result<BigInt> multiply_mod_order(const BigInt &lhs, const BigInt &rhs)
{
	auto order = group_order();
	if (!order)
	{
		return Result<BigInt>::failure(order.error());
	}
	return BigInt::mod_multiply(lhs, rhs, order.value());
}

[[nodiscard]] Result<BigInt> add_mod_order(const BigInt &lhs, const BigInt &rhs)
{
	auto order = group_order();
	if (!order)
	{
		return Result<BigInt>::failure(order.error());
	}
	return BigInt::mod_add(lhs, rhs, order.value());
}

[[nodiscard]] Result<bool> scalar_is_canonical(std::span<const std::uint8_t> little_endian)
{
	auto value = from_le_bytes(little_endian);
	auto order = group_order();
	if (!value)
	{
		return Result<bool>::failure(value.error());
	}
	if (!order)
	{
		return Result<bool>::failure(order.error());
	}
	return Result<bool>::success(value.value().compare(order.value()) < 0);
}

[[nodiscard]] bool scalar_bit(std::span<const std::uint8_t> little_endian, std::size_t bit) noexcept
{
	const auto byte_index = bit / 8U;
	const auto bit_index = bit % 8U;
	return byte_index < little_endian.size() && ((little_endian[byte_index] >> bit_index) & 1U) != 0U;
}

[[nodiscard]] Result<ExtendedPoint> identity()
{
	auto z = zero();
	auto o = one();
	if (!z)
	{
		return Result<ExtendedPoint>::failure(z.error());
	}
	if (!o)
	{
		return Result<ExtendedPoint>::failure(o.error());
	}
	return Result<ExtendedPoint>::success(ExtendedPoint{z.value(), o.value(), o.value(), z.value()});
}

[[nodiscard]] Result<ExtendedPoint> make_affine_point(const BigInt &x, const BigInt &y)
{
	auto z = one();
	auto t = field_multiply(x, y);
	if (!z)
	{
		return Result<ExtendedPoint>::failure(z.error());
	}
	if (!t)
	{
		return Result<ExtendedPoint>::failure(t.error());
	}
	return Result<ExtendedPoint>::success(ExtendedPoint{x, y, z.value(), t.value()});
}

[[nodiscard]] Result<ExtendedPoint> point_add(const ExtendedPoint &lhs, const ExtendedPoint &rhs)
{
	auto y1_minus_x1 = field_subtract(lhs.y, lhs.x);
	auto y2_minus_x2 = field_subtract(rhs.y, rhs.x);
	auto y1_plus_x1 = field_add(lhs.y, lhs.x);
	auto y2_plus_x2 = field_add(rhs.y, rhs.x);
	auto d = bigint(curve_d_bytes);
	auto two_d = d ? field_add(d.value(), d.value()) : Result<BigInt>::failure(d.error());
	auto two_z1 = field_add(lhs.z, lhs.z);
	if (!y1_minus_x1)
	{
		return Result<ExtendedPoint>::failure(y1_minus_x1.error());
	}
	if (!y2_minus_x2)
	{
		return Result<ExtendedPoint>::failure(y2_minus_x2.error());
	}
	if (!y1_plus_x1)
	{
		return Result<ExtendedPoint>::failure(y1_plus_x1.error());
	}
	if (!y2_plus_x2)
	{
		return Result<ExtendedPoint>::failure(y2_plus_x2.error());
	}
	if (!two_d)
	{
		return Result<ExtendedPoint>::failure(two_d.error());
	}
	if (!two_z1)
	{
		return Result<ExtendedPoint>::failure(two_z1.error());
	}

	auto a = field_multiply(y1_minus_x1.value(), y2_minus_x2.value());
	auto b = field_multiply(y1_plus_x1.value(), y2_plus_x2.value());
	auto c0 = field_multiply(lhs.t, rhs.t);
	auto d0 = field_multiply(two_z1.value(), rhs.z);
	if (!a)
	{
		return Result<ExtendedPoint>::failure(a.error());
	}
	if (!b)
	{
		return Result<ExtendedPoint>::failure(b.error());
	}
	if (!c0)
	{
		return Result<ExtendedPoint>::failure(c0.error());
	}
	if (!d0)
	{
		return Result<ExtendedPoint>::failure(d0.error());
	}

	auto c = field_multiply(c0.value(), two_d.value());
	if (!c)
	{
		return Result<ExtendedPoint>::failure(c.error());
	}
	auto e = field_subtract(b.value(), a.value());
	auto f = field_subtract(d0.value(), c.value());
	auto g = field_add(d0.value(), c.value());
	auto h = field_add(b.value(), a.value());
	if (!e)
	{
		return Result<ExtendedPoint>::failure(e.error());
	}
	if (!f)
	{
		return Result<ExtendedPoint>::failure(f.error());
	}
	if (!g)
	{
		return Result<ExtendedPoint>::failure(g.error());
	}
	if (!h)
	{
		return Result<ExtendedPoint>::failure(h.error());
	}

	auto x3 = field_multiply(e.value(), f.value());
	auto y3 = field_multiply(g.value(), h.value());
	auto t3 = field_multiply(e.value(), h.value());
	auto z3 = field_multiply(f.value(), g.value());
	if (!x3)
	{
		return Result<ExtendedPoint>::failure(x3.error());
	}
	if (!y3)
	{
		return Result<ExtendedPoint>::failure(y3.error());
	}
	if (!t3)
	{
		return Result<ExtendedPoint>::failure(t3.error());
	}
	if (!z3)
	{
		return Result<ExtendedPoint>::failure(z3.error());
	}
	return Result<ExtendedPoint>::success(ExtendedPoint{x3.value(), y3.value(), z3.value(), t3.value()});
}

[[nodiscard]] Result<ExtendedPoint> scalar_multiply(std::span<const std::uint8_t> scalar, const ExtendedPoint &point)
{
	auto result = identity();
	if (!result)
	{
		return Result<ExtendedPoint>::failure(result.error());
	}
	auto addend = point;
	for (std::size_t bit = 0; bit < scalar.size() * 8U; ++bit)
	{
		if (scalar_bit(scalar, bit))
		{
			auto next = point_add(result.value(), addend);
			if (!next)
			{
				return Result<ExtendedPoint>::failure(next.error());
			}
			result = Result<ExtendedPoint>::success(next.value());
		}

		auto doubled = point_add(addend, addend);
		if (!doubled)
		{
			return Result<ExtendedPoint>::failure(doubled.error());
		}
		addend = doubled.value();
	}

	return result;
}

[[nodiscard]] Result<bool> points_equal(const ExtendedPoint &lhs, const ExtendedPoint &rhs)
{
	auto left_x = field_multiply(lhs.x, rhs.z);
	auto right_x = field_multiply(rhs.x, lhs.z);
	auto left_y = field_multiply(lhs.y, rhs.z);
	auto right_y = field_multiply(rhs.y, lhs.z);
	if (!left_x)
	{
		return Result<bool>::failure(left_x.error());
	}
	if (!right_x)
	{
		return Result<bool>::failure(right_x.error());
	}
	if (!left_y)
	{
		return Result<bool>::failure(left_y.error());
	}
	if (!right_y)
	{
		return Result<bool>::failure(right_y.error());
	}
	return Result<bool>::success(left_x.value().compare(right_x.value()) == 0 && left_y.value().compare(right_y.value()) == 0);
}

[[nodiscard]] Result<ExtendedPoint> decode_point(std::span<const std::uint8_t> encoded)
{
	if (encoded.size() != encoded_point_size)
	{
		return Result<ExtendedPoint>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 public key must be 32 bytes"));
	}

	std::array<std::uint8_t, encoded_point_size> y_bytes{};
	std::copy(encoded.begin(), encoded.end(), y_bytes.begin());
	const auto x_odd = (y_bytes.back() & 0x80U) != 0U;
	y_bytes.back() &= 0x7FU;

	auto y = from_le_bytes(y_bytes);
	auto p = field_modulus();
	if (!y)
	{
		return Result<ExtendedPoint>::failure(y.error());
	}
	if (!p)
	{
		return Result<ExtendedPoint>::failure(p.error());
	}
	if (y.value().compare(p.value()) >= 0)
	{
		return Result<ExtendedPoint>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 point y-coordinate is not canonical"));
	}

	auto y2 = field_square(y.value());
	auto one_value = one();
	auto d = bigint(curve_d_bytes);
	if (!y2)
	{
		return Result<ExtendedPoint>::failure(y2.error());
	}
	if (!one_value)
	{
		return Result<ExtendedPoint>::failure(one_value.error());
	}
	if (!d)
	{
		return Result<ExtendedPoint>::failure(d.error());
	}

	auto u = field_subtract(y2.value(), one_value.value());
	auto dy2 = field_multiply(d.value(), y2.value());
	if (!u)
	{
		return Result<ExtendedPoint>::failure(u.error());
	}
	if (!dy2)
	{
		return Result<ExtendedPoint>::failure(dy2.error());
	}
	auto v = field_add(dy2.value(), one_value.value());
	if (!v)
	{
		return Result<ExtendedPoint>::failure(v.error());
	}

	auto v_inverse = field_inverse(v.value());
	if (!v_inverse)
	{
		return Result<ExtendedPoint>::failure(v_inverse.error());
	}
	auto x2 = field_multiply(u.value(), v_inverse.value());
	if (!x2)
	{
		return Result<ExtendedPoint>::failure(x2.error());
	}

	auto exponent = bigint(sqrt_exponent_bytes);
	if (!exponent)
	{
		return Result<ExtendedPoint>::failure(exponent.error());
	}
	auto x = BigInt::mod_exp(x2.value(), exponent.value(), p.value());
	if (!x)
	{
		return Result<ExtendedPoint>::failure(x.error());
	}
	auto check = field_square(x.value());
	if (!check)
	{
		return Result<ExtendedPoint>::failure(check.error());
	}
	if (check.value().compare(x2.value()) != 0)
	{
		auto sqrt_minus_one = bigint(sqrt_minus_one_bytes);
		if (!sqrt_minus_one)
		{
			return Result<ExtendedPoint>::failure(sqrt_minus_one.error());
		}
		auto corrected = field_multiply(x.value(), sqrt_minus_one.value());
		if (!corrected)
		{
			return Result<ExtendedPoint>::failure(corrected.error());
		}
		x = Result<BigInt>::success(corrected.value());
		check = field_square(x.value());
		if (!check)
		{
			return Result<ExtendedPoint>::failure(check.error());
		}
		if (check.value().compare(x2.value()) != 0)
		{
			return Result<ExtendedPoint>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 point is not on the curve"));
		}
	}

	if (x.value().is_zero() && x_odd)
	{
		return Result<ExtendedPoint>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 point has invalid x parity"));
	}
	if (is_odd(x.value()) != x_odd)
	{
		auto negated = field_subtract(p.value(), x.value());
		if (!negated)
		{
			return Result<ExtendedPoint>::failure(negated.error());
		}
		x = Result<BigInt>::success(negated.value());
	}

	return make_affine_point(x.value(), y.value());
}

void clamp_scalar(std::array<std::uint8_t, 32> &scalar) noexcept
{
	scalar[0] &= 248U;
	scalar[31] &= 63U;
	scalar[31] |= 64U;
}

[[nodiscard]] Result<ByteBuffer> encode_point(const ExtendedPoint &point)
{
	auto z_inverse = field_inverse(point.z);
	if (!z_inverse)
	{
		return Result<ByteBuffer>::failure(z_inverse.error());
	}
	auto x = field_multiply(point.x, z_inverse.value());
	auto y = field_multiply(point.y, z_inverse.value());
	if (!x)
	{
		return Result<ByteBuffer>::failure(x.error());
	}
	if (!y)
	{
		return Result<ByteBuffer>::failure(y.error());
	}

	auto encoded = to_fixed_le_bytes(y.value(), encoded_point_size);
	if (!encoded)
	{
		return Result<ByteBuffer>::failure(encoded.error());
	}
	if (is_odd(x.value()))
	{
		encoded.value().back() |= 0x80U;
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(encoded.value())));
}

[[nodiscard]] Result<ByteBuffer> sha512(std::span<const std::uint8_t> input)
{
	Sha512Context context;
	auto updated = context.update(input);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	return context.final();
}

[[nodiscard]] Result<ByteBuffer> sha512(std::span<const std::uint8_t> first, std::span<const std::uint8_t> second)
{
	Sha512Context context;
	auto updated = context.update(first);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	updated = context.update(second);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	return context.final();
}

[[nodiscard]] Result<ByteBuffer> sha512(std::span<const std::uint8_t> first, std::span<const std::uint8_t> second, std::span<const std::uint8_t> third)
{
	Sha512Context context;
	auto updated = context.update(first);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	updated = context.update(second);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	updated = context.update(third);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}
	return context.final();
}

} // namespace

Result<ByteBuffer> sign_ed25519_seed(std::span<const std::uint8_t> seed, std::span<const std::uint8_t> message)
{
	if (seed.size() != encoded_point_size)
	{
		return Result<ByteBuffer>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 private seed must be 32 bytes"));
	}

	auto digest = sha512(seed);
	if (!digest)
	{
		return Result<ByteBuffer>::failure(digest.error());
	}
	if (digest.value().size() != 64)
	{
		return Result<ByteBuffer>::failure(ed25519_error(ErrorCode::internal_error, "SHA-512 digest must be 64 bytes"));
	}

	std::array<std::uint8_t, 32> scalar_bytes{};
	std::copy(digest.value().bytes().begin(), digest.value().bytes().begin() + static_cast<std::ptrdiff_t>(scalar_bytes.size()), scalar_bytes.begin());
	clamp_scalar(scalar_bytes);

	auto base = decode_point(base_point_bytes);
	if (!base)
	{
		return Result<ByteBuffer>::failure(base.error());
	}

	auto public_point = scalar_multiply(scalar_bytes, base.value());
	if (!public_point)
	{
		return Result<ByteBuffer>::failure(public_point.error());
	}
	auto public_key = encode_point(public_point.value());
	if (!public_key)
	{
		return Result<ByteBuffer>::failure(public_key.error());
	}

	auto prefix = digest.value().bytes().subspan(32, 32);
	auto r_digest = sha512(prefix, message);
	if (!r_digest)
	{
		return Result<ByteBuffer>::failure(r_digest.error());
	}
	auto r = reduce_mod_order(r_digest.value().bytes());
	if (!r)
	{
		return Result<ByteBuffer>::failure(r.error());
	}
	auto r_bytes = to_fixed_le_bytes(r.value(), 32);
	if (!r_bytes)
	{
		return Result<ByteBuffer>::failure(r_bytes.error());
	}

	auto r_point = scalar_multiply(r_bytes.value(), base.value());
	if (!r_point)
	{
		return Result<ByteBuffer>::failure(r_point.error());
	}
	auto r_encoded = encode_point(r_point.value());
	if (!r_encoded)
	{
		return Result<ByteBuffer>::failure(r_encoded.error());
	}

	auto k_digest = sha512(r_encoded.value().bytes(), public_key.value().bytes(), message);
	if (!k_digest)
	{
		return Result<ByteBuffer>::failure(k_digest.error());
	}
	auto k = reduce_mod_order(k_digest.value().bytes());
	auto a = from_le_bytes(scalar_bytes);
	if (!k)
	{
		return Result<ByteBuffer>::failure(k.error());
	}
	if (!a)
	{
		return Result<ByteBuffer>::failure(a.error());
	}
	auto k_times_a = multiply_mod_order(k.value(), a.value());
	if (!k_times_a)
	{
		return Result<ByteBuffer>::failure(k_times_a.error());
	}
	auto s = add_mod_order(r.value(), k_times_a.value());
	if (!s)
	{
		return Result<ByteBuffer>::failure(s.error());
	}
	auto s_bytes = to_fixed_le_bytes(s.value(), 32);
	if (!s_bytes)
	{
		return Result<ByteBuffer>::failure(s_bytes.error());
	}

	std::vector<std::uint8_t> signature;
	signature.reserve(signature_size);
	signature.insert(signature.end(), r_encoded.value().bytes().begin(), r_encoded.value().bytes().end());
	signature.insert(signature.end(), s_bytes.value().begin(), s_bytes.value().end());
	return Result<ByteBuffer>::success(ByteBuffer(std::move(signature)));
}

Result<void> validate_ed25519_public_key(std::span<const std::uint8_t> public_key)
{
	auto point = decode_point(public_key);
	if (!point)
	{
		return Result<void>::failure(point.error());
	}

	return Result<void>::success();
}

Result<bool> verify_ed25519(
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> signature,
    std::span<const std::uint8_t> message)
{
	if (public_key.size() != encoded_point_size)
	{
		return Result<bool>::failure(ed25519_error(ErrorCode::invalid_key, "Ed25519 public key must be 32 bytes"));
	}
	if (signature.size() != signature_size)
	{
		return Result<bool>::success(false);
	}

	auto s_canonical = scalar_is_canonical(signature.subspan(32, 32));
	if (!s_canonical)
	{
		return Result<bool>::failure(s_canonical.error());
	}
	if (!s_canonical.value())
	{
		return Result<bool>::success(false);
	}

	auto public_point = decode_point(public_key);
	if (!public_point)
	{
		return Result<bool>::failure(public_point.error());
	}
	auto r_point = decode_point(signature.first(32));
	if (!r_point)
	{
		return Result<bool>::success(false);
	}

	auto digest = sha512(signature.first(32), public_key, message);
	if (!digest)
	{
		return Result<bool>::failure(digest.error());
	}
	auto h = reduce_mod_order(digest.value().bytes());
	if (!h)
	{
		return Result<bool>::failure(h.error());
	}
	auto h_bytes = to_fixed_le_bytes(h.value(), 32);
	if (!h_bytes)
	{
		return Result<bool>::failure(h_bytes.error());
	}

	auto base = decode_point(base_point_bytes);
	if (!base)
	{
		return Result<bool>::failure(base.error());
	}
	auto left = scalar_multiply(signature.subspan(32, 32), base.value());
	if (!left)
	{
		return Result<bool>::failure(left.error());
	}
	auto h_a = scalar_multiply(h_bytes.value(), public_point.value());
	if (!h_a)
	{
		return Result<bool>::failure(h_a.error());
	}
	auto right = point_add(r_point.value(), h_a.value());
	if (!right)
	{
		return Result<bool>::failure(right.error());
	}
	return points_equal(left.value(), right.value());
}

} // namespace crypto_core::internal
