#include "crypto_core/internal/ecdsa.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"
#include "crypto_core/internal/ec_der.hpp"
#include "crypto_core/internal/p256.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace crypto_core::internal
{
namespace
{

constexpr std::size_t sha256_digest_size = 32;

[[nodiscard]] Error ecdsa_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "ecdsa", message);
}

[[nodiscard]] Result<BigInt> bigint(std::span<const std::uint8_t> bytes)
{
	return BigInt::from_be_bytes(bytes);
}

[[nodiscard]] Result<bool> invalid_signature()
{
	return Result<bool>::success(false);
}

[[nodiscard]] Result<bool> invalid_public_key()
{
	return Result<bool>::failure(ecdsa_error(ErrorCode::invalid_key, "invalid P-256 public key"));
}

[[nodiscard]] Result<bool> public_key_point(std::span<const std::uint8_t> public_key_der, P256Point &point)
{
	auto public_key = parse_p256_public_key_der(public_key_der);
	if (!public_key)
	{
		return Result<bool>::failure(public_key.error());
	}

	auto parsed_point = p256_point_from_coordinates(public_key.value().x.bytes(), public_key.value().y.bytes());
	if (!parsed_point)
	{
		return invalid_public_key();
	}

	auto on_curve = p256_is_on_curve(parsed_point.value());
	if (!on_curve)
	{
		return invalid_public_key();
	}
	if (!on_curve.value())
	{
		return invalid_public_key();
	}

	point = std::move(parsed_point.value());
	return Result<bool>::success(true);
}

} // namespace

Result<bool> verify_ecdsa_p256_sha256_digest(
    std::span<const std::uint8_t> public_key_der,
    std::span<const std::uint8_t> signature_der,
    std::span<const std::uint8_t> digest)
{
	if (digest.size() != sha256_digest_size)
	{
		return Result<bool>::failure(ecdsa_error(ErrorCode::invalid_argument, "SHA-256 digest must be 32 bytes"));
	}

	P256Point public_key_point_value;
	auto key_loaded = public_key_point(public_key_der, public_key_point_value);
	if (!key_loaded)
	{
		return Result<bool>::failure(key_loaded.error());
	}

	auto signature = parse_ecdsa_signature_der(signature_der);
	if (!signature)
	{
		return invalid_signature();
	}

	auto order = bigint(p256_group_order());
	if (!order)
	{
		return Result<bool>::failure(order.error());
	}

	auto r = bigint(signature.value().r.bytes());
	if (!r)
	{
		return Result<bool>::failure(r.error());
	}
	if (r.value().is_zero() || r.value().compare(order.value()) >= 0)
	{
		return invalid_signature();
	}
	auto s = bigint(signature.value().s.bytes());
	if (!s)
	{
		return Result<bool>::failure(s.error());
	}
	if (s.value().is_zero() || s.value().compare(order.value()) >= 0)
	{
		return invalid_signature();
	}

	auto z = bigint(digest);
	if (!z)
	{
		return Result<bool>::failure(z.error());
	}

	auto w = p256_scalar_inverse(signature.value().s.bytes());
	if (!w)
	{
		return invalid_signature();
	}

	auto z_bytes = z.value().to_be_bytes();
	auto u1 = p256_scalar_multiply_mod(z_bytes.bytes(), w.value().bytes());
	if (!u1)
	{
		return Result<bool>::failure(u1.error());
	}
	auto u2 = p256_scalar_multiply_mod(signature.value().r.bytes(), w.value().bytes());
	if (!u2)
	{
		return Result<bool>::failure(u2.error());
	}

	auto u1_g = p256_base_point_multiply(u1.value().bytes());
	if (!u1_g)
	{
		return Result<bool>::failure(u1_g.error());
	}
	auto u2_q = p256_scalar_multiply(u2.value().bytes(), public_key_point_value);
	if (!u2_q)
	{
		return Result<bool>::failure(u2_q.error());
	}
	auto r_point = p256_point_add(u1_g.value(), u2_q.value());
	if (!r_point)
	{
		return Result<bool>::failure(r_point.error());
	}
	if (r_point.value().infinity)
	{
		return invalid_signature();
	}

	auto x_mod_order = p256_x_mod_order(r_point.value());
	if (!x_mod_order)
	{
		return Result<bool>::failure(x_mod_order.error());
	}
	auto x = bigint(x_mod_order.value().bytes());
	if (!x)
	{
		return Result<bool>::failure(x.error());
	}

	return Result<bool>::success(x.value().compare(r.value()) == 0);
}

} // namespace crypto_core::internal
