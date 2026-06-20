#include "crypto_core/internal/ecdsa.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"
#include "crypto_core/internal/ec_der.hpp"
#include "crypto_core/internal/hmac.hpp"
#include "crypto_core/internal/p256.hpp"
#include "crypto_core/internal/p256_fixed.hpp"

#include <array>
#include <algorithm>
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

constexpr std::size_t sha256_digest_size = 32;

[[nodiscard]] Error ecdsa_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "ecdsa", message);
}

[[nodiscard]] Result<BigInt> bigint(std::span<const std::uint8_t> bytes)
{
	return BigInt::from_be_bytes(bytes);
}

[[nodiscard]] Result<ByteBuffer> fixed_32_bytes(const BigInt &value)
{
	auto minimal = value.to_be_bytes();
	if (minimal.size() > sha256_digest_size)
	{
		return Result<ByteBuffer>::failure(ecdsa_error(ErrorCode::internal_error, "scalar is too large"));
	}

	std::vector<std::uint8_t> output(sha256_digest_size);
	std::copy(minimal.bytes().begin(), minimal.bytes().end(), output.begin() + static_cast<std::ptrdiff_t>(sha256_digest_size - minimal.size()));
	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

[[nodiscard]] Result<ByteBuffer> hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> input)
{
	HmacContext context(HashAlgorithm::sha256, key);
	if (!context.initialized())
	{
		return Result<ByteBuffer>::failure(ecdsa_error(ErrorCode::provider_error, "failed to initialize RFC6979 HMAC"));
	}
	auto update = context.update(input);
	if (!update)
	{
		return Result<ByteBuffer>::failure(update.error());
	}
	return context.final();
}

[[nodiscard]] Result<ByteBuffer> bits_to_octets(std::span<const std::uint8_t> digest)
{
	auto z = bigint(digest);
	auto order = bigint(p256_group_order());
	if (!z)
	{
		return Result<ByteBuffer>::failure(z.error());
	}
	if (!order)
	{
		return Result<ByteBuffer>::failure(order.error());
	}
	auto reduced = BigInt::mod_add(z.value(), BigInt::from_be_bytes(std::array<std::uint8_t, 1>{0x00}).value(), order.value());
	if (!reduced)
	{
		return Result<ByteBuffer>::failure(reduced.error());
	}
	return fixed_32_bytes(reduced.value());
}

[[nodiscard]] bool valid_scalar(const BigInt &value, const BigInt &order) noexcept
{
	return !value.is_zero() && value.compare(order) < 0;
}

class Rfc6979P256Sha256 final
{
public:
	[[nodiscard]] static Result<Rfc6979P256Sha256> create(std::span<const std::uint8_t> private_scalar, std::span<const std::uint8_t> digest)
	{
		auto digest_octets = bits_to_octets(digest);
		if (!digest_octets)
		{
			return Result<Rfc6979P256Sha256>::failure(digest_octets.error());
		}

		Rfc6979P256Sha256 state;
		state.k_.assign(sha256_digest_size, 0x00U);
		state.v_.assign(sha256_digest_size, 0x01U);

		std::vector<std::uint8_t> input;
		input.reserve(state.v_.size() + 1U + private_scalar.size() + digest_octets.value().size());
		input.insert(input.end(), state.v_.begin(), state.v_.end());
		input.push_back(0x00U);
		input.insert(input.end(), private_scalar.begin(), private_scalar.end());
		input.insert(input.end(), digest_octets.value().bytes().begin(), digest_octets.value().bytes().end());
		auto k0 = hmac_sha256(state.k_, input);
		if (!k0)
		{
			return Result<Rfc6979P256Sha256>::failure(k0.error());
		}
		state.k_.assign(k0.value().bytes().begin(), k0.value().bytes().end());

		auto v0 = hmac_sha256(state.k_, state.v_);
		if (!v0)
		{
			return Result<Rfc6979P256Sha256>::failure(v0.error());
		}
		state.v_.assign(v0.value().bytes().begin(), v0.value().bytes().end());

		input.clear();
		input.insert(input.end(), state.v_.begin(), state.v_.end());
		input.push_back(0x01U);
		input.insert(input.end(), private_scalar.begin(), private_scalar.end());
		input.insert(input.end(), digest_octets.value().bytes().begin(), digest_octets.value().bytes().end());
		auto k1 = hmac_sha256(state.k_, input);
		if (!k1)
		{
			return Result<Rfc6979P256Sha256>::failure(k1.error());
		}
		state.k_.assign(k1.value().bytes().begin(), k1.value().bytes().end());

		auto v1 = hmac_sha256(state.k_, state.v_);
		if (!v1)
		{
			return Result<Rfc6979P256Sha256>::failure(v1.error());
		}
		state.v_.assign(v1.value().bytes().begin(), v1.value().bytes().end());
		return Result<Rfc6979P256Sha256>::success(std::move(state));
	}

	[[nodiscard]] Result<ByteBuffer> next()
	{
		auto next_v = hmac_sha256(k_, v_);
		if (!next_v)
		{
			return Result<ByteBuffer>::failure(next_v.error());
		}
		v_.assign(next_v.value().bytes().begin(), next_v.value().bytes().end());
		return Result<ByteBuffer>::success(ByteBuffer::copy_from(v_));
	}

	[[nodiscard]] Result<void> reject()
	{
		std::vector<std::uint8_t> input;
		input.reserve(v_.size() + 1U);
		input.insert(input.end(), v_.begin(), v_.end());
		input.push_back(0x00U);
		auto next_k = hmac_sha256(k_, input);
		if (!next_k)
		{
			return Result<void>::failure(next_k.error());
		}
		k_.assign(next_k.value().bytes().begin(), next_k.value().bytes().end());

		auto next_v = hmac_sha256(k_, v_);
		if (!next_v)
		{
			return Result<void>::failure(next_v.error());
		}
		v_.assign(next_v.value().bytes().begin(), next_v.value().bytes().end());
		return Result<void>::success();
	}

private:
	std::vector<std::uint8_t> k_;
	std::vector<std::uint8_t> v_;
};

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

	auto parsed_point = p256_fixed_point_from_coordinates(public_key.value().x.bytes(), public_key.value().y.bytes());
	if (!parsed_point)
	{
		return invalid_public_key();
	}

	auto on_curve = p256_fixed_is_on_curve(parsed_point.value());
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

Result<ByteBuffer> sign_ecdsa_p256_sha256_digest(std::span<const std::uint8_t> private_key_der, std::span<const std::uint8_t> digest)
{
	if (digest.size() != sha256_digest_size)
	{
		return Result<ByteBuffer>::failure(ecdsa_error(ErrorCode::invalid_argument, "SHA-256 digest must be 32 bytes"));
	}

	auto private_key = parse_p256_private_key_der(private_key_der);
	if (!private_key)
	{
		return Result<ByteBuffer>::failure(private_key.error());
	}

	auto order = bigint(p256_group_order());
	if (!order)
	{
		return Result<ByteBuffer>::failure(order.error());
	}
	auto private_scalar = bigint(private_key.value().private_scalar.bytes());
	if (!private_scalar)
	{
		return Result<ByteBuffer>::failure(private_scalar.error());
	}
	if (!valid_scalar(private_scalar.value(), order.value()))
	{
		return Result<ByteBuffer>::failure(ecdsa_error(ErrorCode::invalid_key, "invalid P-256 private scalar"));
	}

	auto nonce = Rfc6979P256Sha256::create(private_key.value().private_scalar.bytes(), digest);
	if (!nonce)
	{
		return Result<ByteBuffer>::failure(nonce.error());
	}

	constexpr std::size_t max_attempts = 16;
	for (std::size_t attempt = 0; attempt < max_attempts; ++attempt)
	{
		auto k_bytes = nonce.value().next();
		if (!k_bytes)
		{
			return Result<ByteBuffer>::failure(k_bytes.error());
		}
		auto k = bigint(k_bytes.value().bytes());
		if (!k)
		{
			return Result<ByteBuffer>::failure(k.error());
		}
		if (!valid_scalar(k.value(), order.value()))
		{
			auto rejected = nonce.value().reject();
			if (!rejected)
			{
				return Result<ByteBuffer>::failure(rejected.error());
			}
			continue;
		}

		auto point = p256_base_point_multiply(k_bytes.value().bytes());
		if (!point)
		{
			return Result<ByteBuffer>::failure(point.error());
		}
		if (point.value().infinity)
		{
			auto rejected = nonce.value().reject();
			if (!rejected)
			{
				return Result<ByteBuffer>::failure(rejected.error());
			}
			continue;
		}

		auto r = p256_x_mod_order(point.value());
		if (!r)
		{
			return Result<ByteBuffer>::failure(r.error());
		}
		auto r_int = bigint(r.value().bytes());
		if (!r_int)
		{
			return Result<ByteBuffer>::failure(r_int.error());
		}
		if (r_int.value().is_zero())
		{
			auto rejected = nonce.value().reject();
			if (!rejected)
			{
				return Result<ByteBuffer>::failure(rejected.error());
			}
			continue;
		}

		auto rd = BigInt::mod_multiply(r_int.value(), private_scalar.value(), order.value());
		auto z = bigint(digest);
		if (!rd)
		{
			return Result<ByteBuffer>::failure(rd.error());
		}
		if (!z)
		{
			return Result<ByteBuffer>::failure(z.error());
		}
		auto sum = BigInt::mod_add(z.value(), rd.value(), order.value());
		if (!sum)
		{
			return Result<ByteBuffer>::failure(sum.error());
		}

		auto k_inverse = p256_scalar_inverse(k_bytes.value().bytes());
		if (!k_inverse)
		{
			return Result<ByteBuffer>::failure(k_inverse.error());
		}
		auto sum_bytes = sum.value().to_be_bytes();
		auto s = p256_scalar_multiply_mod(k_inverse.value().bytes(), sum_bytes.bytes());
		if (!s)
		{
			return Result<ByteBuffer>::failure(s.error());
		}
		auto s_int = bigint(s.value().bytes());
		if (!s_int)
		{
			return Result<ByteBuffer>::failure(s_int.error());
		}
		if (s_int.value().is_zero())
		{
			auto rejected = nonce.value().reject();
			if (!rejected)
			{
				return Result<ByteBuffer>::failure(rejected.error());
			}
			continue;
		}

		return encode_ecdsa_signature_der(r.value().bytes(), s.value().bytes());
	}

	return Result<ByteBuffer>::failure(ecdsa_error(ErrorCode::provider_error, "failed to generate ECDSA signature"));
}

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

	auto r_valid = p256_fixed_scalar_is_valid_nonzero(signature.value().r.bytes());
	if (!r_valid)
	{
		return Result<bool>::failure(r_valid.error());
	}
	if (!r_valid.value())
	{
		return invalid_signature();
	}
	auto s_valid = p256_fixed_scalar_is_valid_nonzero(signature.value().s.bytes());
	if (!s_valid)
	{
		return Result<bool>::failure(s_valid.error());
	}
	if (!s_valid.value())
	{
		return invalid_signature();
	}

	auto w = p256_fixed_scalar_inverse(signature.value().s.bytes());
	if (!w)
	{
		return invalid_signature();
	}

	auto u1 = p256_fixed_scalar_multiply_mod(digest, w.value().bytes());
	if (!u1)
	{
		return Result<bool>::failure(u1.error());
	}
	auto u2 = p256_fixed_scalar_multiply_mod(signature.value().r.bytes(), w.value().bytes());
	if (!u2)
	{
		return Result<bool>::failure(u2.error());
	}

	auto u1_g = p256_fixed_base_point_multiply(u1.value().bytes());
	if (!u1_g)
	{
		return Result<bool>::failure(u1_g.error());
	}
	auto u2_q = p256_fixed_scalar_multiply(u2.value().bytes(), public_key_point_value);
	if (!u2_q)
	{
		return Result<bool>::failure(u2_q.error());
	}
	auto r_point = p256_fixed_point_add(u1_g.value(), u2_q.value());
	if (!r_point)
	{
		return Result<bool>::failure(r_point.error());
	}
	if (r_point.value().infinity)
	{
		return invalid_signature();
	}

	auto x_mod_order = p256_fixed_x_mod_order(r_point.value());
	if (!x_mod_order)
	{
		return Result<bool>::failure(x_mod_order.error());
	}

	return Result<bool>::success(x_mod_order.value() == signature.value().r);
}

} // namespace crypto_core::internal
