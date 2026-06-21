#include "crypto_core/internal/rsa.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"
#include "crypto_core/internal/rsa_fixed_bigint.hpp"

#include <array>
#include <cstddef>
#include <utility>
#include <vector>

namespace crypto_core::internal
{
namespace
{

[[nodiscard]] Error rsa_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "rsa", message);
}

[[nodiscard]] Result<ByteBuffer> left_pad_to_width(const BigInt &value, std::size_t width)
{
	auto bytes = value.to_be_bytes();
	if (bytes.size() > width)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::internal_error, "RSA output is wider than modulus"));
	}
	if (bytes.size() == width)
	{
		return Result<ByteBuffer>::success(std::move(bytes));
	}

	std::vector<std::uint8_t> output(width, 0);
	const auto offset = width - bytes.size();
	for (std::size_t i = 0; i < bytes.size(); ++i)
	{
		output[offset + i] = bytes.bytes()[i];
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

[[nodiscard]] Result<ByteBuffer> rsa_operation(std::span<const std::uint8_t> modulus_bytes, std::span<const std::uint8_t> exponent_bytes, std::span<const std::uint8_t> input)
{
	auto modulus = BigInt::from_be_bytes(modulus_bytes);
	auto exponent = BigInt::from_be_bytes(exponent_bytes);
	auto representative = BigInt::from_be_bytes(input);
	if (!modulus || !exponent || !representative)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (modulus.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA modulus must be non-zero"));
	}
	if (exponent.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA exponent must be non-zero"));
	}
	if (representative.value().compare(modulus.value()) >= 0)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA representative must be less than modulus"));
	}

	auto output = BigInt::mod_exp(representative.value(), exponent.value(), modulus.value());
	if (!output)
	{
		return Result<ByteBuffer>::failure(output.error());
	}

	return left_pad_to_width(output.value(), modulus_bytes.size());
}

[[nodiscard]] Result<BigInt> import_non_zero(std::span<const std::uint8_t> bytes, std::string_view name)
{
	auto value = BigInt::from_be_bytes(bytes);
	if (!value)
	{
		return Result<BigInt>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (value.value().is_zero())
	{
		return Result<BigInt>::failure(rsa_error(ErrorCode::invalid_key, name));
	}

	return value;
}

[[nodiscard]] Result<BigInt> fixed_mod_exp_to_bigint(
    std::span<const std::uint8_t> base_bytes,
    std::span<const std::uint8_t> exponent_bytes,
    std::span<const std::uint8_t> modulus_bytes,
    std::size_t exponent_bits)
{
	const auto fixed_width = (modulus_bytes.size() + 3U) / 4U;
	if (fixed_width == 0 || fixed_width > RsaFixedBigInt::kMaxLimbs)
	{
		return Result<BigInt>::failure(rsa_error(ErrorCode::invalid_key, "RSA fixed-width modulus is not supported"));
	}

	auto modulus = RsaFixedBigInt::from_be_bytes(modulus_bytes, fixed_width);
	if (!modulus)
	{
		return Result<BigInt>::failure(modulus.error());
	}
	auto base = RsaFixedBigInt::from_be_bytes_mod(base_bytes, modulus.value());
	if (!base)
	{
		return Result<BigInt>::failure(base.error());
	}
	auto output = RsaFixedBigInt::montgomery_mod_exp_secret(base.value(), exponent_bytes, modulus.value(), exponent_bits);
	if (!output)
	{
		return Result<BigInt>::failure(output.error());
	}

	auto output_bytes = output.value().to_be_bytes();
	if (output_bytes.size() < modulus_bytes.size())
	{
		return Result<BigInt>::failure(rsa_error(ErrorCode::internal_error, "RSA fixed-width output is too short"));
	}
	const auto reduced_bytes = output_bytes.bytes().subspan(output_bytes.size() - modulus_bytes.size());
	return BigInt::from_be_bytes(reduced_bytes);
}

[[nodiscard]] Result<ByteBuffer> crt_recombine(
    const BigInt &message1,
    const BigInt &message2,
    const BigInt &prime1,
    const BigInt &prime2,
    const BigInt &coefficient,
    const BigInt &modulus,
    std::size_t width)
{
	auto difference = BigInt::mod_subtract(message1, message2, prime1);
	if (!difference)
	{
		return Result<ByteBuffer>::failure(difference.error());
	}
	auto h = BigInt::mod_multiply(coefficient, difference.value(), prime1);
	if (!h)
	{
		return Result<ByteBuffer>::failure(h.error());
	}
	auto qh = BigInt::mod_multiply(prime2, h.value(), modulus);
	if (!qh)
	{
		return Result<ByteBuffer>::failure(qh.error());
	}
	auto output = BigInt::mod_add(message2, qh.value(), modulus);
	if (!output)
	{
		return Result<ByteBuffer>::failure(output.error());
	}

	return left_pad_to_width(output.value(), width);
}

} // namespace

Result<ByteBuffer> rsa_public_operation(const RsaPublicKeyMaterial &key, std::span<const std::uint8_t> input)
{
	return rsa_operation(key.modulus.bytes(), key.public_exponent.bytes(), input);
}

Result<ByteBuffer> rsa_private_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input)
{
	auto modulus = BigInt::from_be_bytes(key.modulus.bytes());
	auto exponent = BigInt::from_be_bytes(key.private_exponent.bytes());
	auto representative = BigInt::from_be_bytes(input);
	if (!modulus || !exponent || !representative)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (modulus.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA modulus must be non-zero"));
	}
	if (exponent.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA exponent must be non-zero"));
	}
	if (representative.value().compare(modulus.value()) >= 0)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA representative must be less than modulus"));
	}

	auto output = BigInt::mod_exp_secret(representative.value(), exponent.value(), modulus.value(), key.private_exponent.size() * 8U);
	if (!output)
	{
		return Result<ByteBuffer>::failure(output.error());
	}

	return left_pad_to_width(output.value(), key.modulus.size());
}

Result<ByteBuffer> rsa_private_crt_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input)
{
	auto modulus = import_non_zero(key.modulus.bytes(), "RSA modulus must be non-zero");
	auto representative = BigInt::from_be_bytes(input);
	auto prime1 = import_non_zero(key.prime1.bytes(), "RSA prime1 must be non-zero");
	auto prime2 = import_non_zero(key.prime2.bytes(), "RSA prime2 must be non-zero");
	auto exponent1 = import_non_zero(key.exponent1.bytes(), "RSA exponent1 must be non-zero");
	auto exponent2 = import_non_zero(key.exponent2.bytes(), "RSA exponent2 must be non-zero");
	auto coefficient = import_non_zero(key.coefficient.bytes(), "RSA coefficient must be non-zero");
	if (!modulus)
	{
		return Result<ByteBuffer>::failure(modulus.error());
	}
	if (!representative)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (!prime1)
	{
		return Result<ByteBuffer>::failure(prime1.error());
	}
	if (!prime2)
	{
		return Result<ByteBuffer>::failure(prime2.error());
	}
	if (!exponent1)
	{
		return Result<ByteBuffer>::failure(exponent1.error());
	}
	if (!exponent2)
	{
		return Result<ByteBuffer>::failure(exponent2.error());
	}
	if (!coefficient)
	{
		return Result<ByteBuffer>::failure(coefficient.error());
	}
	if (representative.value().compare(modulus.value()) >= 0)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA representative must be less than modulus"));
	}

	auto message1 = fixed_mod_exp_to_bigint(input, key.exponent1.bytes(), key.prime1.bytes(), key.prime1.size() * 8U);
	if (!message1)
	{
		return Result<ByteBuffer>::failure(message1.error());
	}
	auto message2 = fixed_mod_exp_to_bigint(input, key.exponent2.bytes(), key.prime2.bytes(), key.prime2.size() * 8U);
	if (!message2)
	{
		return Result<ByteBuffer>::failure(message2.error());
	}

	return crt_recombine(message1.value(), message2.value(), prime1.value(), prime2.value(), coefficient.value(), modulus.value(), key.modulus.size());
}

Result<ByteBuffer> rsa_private_crt_blinded_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input, std::span<const std::uint8_t> blinding_factor)
{
	auto modulus = import_non_zero(key.modulus.bytes(), "RSA modulus must be non-zero");
	auto public_exponent = import_non_zero(key.public_exponent.bytes(), "RSA public exponent must be non-zero");
	auto representative = BigInt::from_be_bytes(input);
	auto blinding = BigInt::from_be_bytes(blinding_factor);
	auto prime1 = import_non_zero(key.prime1.bytes(), "RSA prime1 must be non-zero");
	auto prime2 = import_non_zero(key.prime2.bytes(), "RSA prime2 must be non-zero");
	auto exponent1 = import_non_zero(key.exponent1.bytes(), "RSA exponent1 must be non-zero");
	auto exponent2 = import_non_zero(key.exponent2.bytes(), "RSA exponent2 must be non-zero");
	auto coefficient = import_non_zero(key.coefficient.bytes(), "RSA coefficient must be non-zero");
	if (!modulus)
	{
		return Result<ByteBuffer>::failure(modulus.error());
	}
	if (!public_exponent)
	{
		return Result<ByteBuffer>::failure(public_exponent.error());
	}
	if (!representative)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (!blinding)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_key, "RSA integer import failed"));
	}
	if (!prime1)
	{
		return Result<ByteBuffer>::failure(prime1.error());
	}
	if (!prime2)
	{
		return Result<ByteBuffer>::failure(prime2.error());
	}
	if (!exponent1)
	{
		return Result<ByteBuffer>::failure(exponent1.error());
	}
	if (!exponent2)
	{
		return Result<ByteBuffer>::failure(exponent2.error());
	}
	if (!coefficient)
	{
		return Result<ByteBuffer>::failure(coefficient.error());
	}
	if (representative.value().compare(modulus.value()) >= 0)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA representative must be less than modulus"));
	}
	if (blinding.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA blinding factor must be non-zero"));
	}

	const std::array<std::uint8_t, 1> one_bytes{0x01};
	const std::array<std::uint8_t, 1> two_bytes{0x02};
	auto one = BigInt::from_be_bytes(one_bytes);
	auto two = BigInt::from_be_bytes(two_bytes);
	if (!one || !two)
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::internal_error, "RSA constant import failed"));
	}

	auto blinding_mod_prime1 = BigInt::mod_multiply(blinding.value(), one.value(), prime1.value());
	auto blinding_mod_prime2 = BigInt::mod_multiply(blinding.value(), one.value(), prime2.value());
	if (!blinding_mod_prime1)
	{
		return Result<ByteBuffer>::failure(blinding_mod_prime1.error());
	}
	if (!blinding_mod_prime2)
	{
		return Result<ByteBuffer>::failure(blinding_mod_prime2.error());
	}
	if (blinding_mod_prime1.value().is_zero() || blinding_mod_prime2.value().is_zero())
	{
		return Result<ByteBuffer>::failure(rsa_error(ErrorCode::invalid_argument, "RSA blinding factor must be invertible"));
	}

	auto blinding_power = BigInt::mod_exp(blinding.value(), public_exponent.value(), modulus.value());
	if (!blinding_power)
	{
		return Result<ByteBuffer>::failure(blinding_power.error());
	}
	auto blinded_representative = BigInt::mod_multiply(representative.value(), blinding_power.value(), modulus.value());
	if (!blinded_representative)
	{
		return Result<ByteBuffer>::failure(blinded_representative.error());
	}

	auto blinded_representative_bytes = blinded_representative.value().to_be_bytes();
	auto blinded_message1 = fixed_mod_exp_to_bigint(blinded_representative_bytes.bytes(), key.exponent1.bytes(), key.prime1.bytes(), key.prime1.size() * 8U);
	auto blinded_message2 = fixed_mod_exp_to_bigint(blinded_representative_bytes.bytes(), key.exponent2.bytes(), key.prime2.bytes(), key.prime2.size() * 8U);
	if (!blinded_message1)
	{
		return Result<ByteBuffer>::failure(blinded_message1.error());
	}
	if (!blinded_message2)
	{
		return Result<ByteBuffer>::failure(blinded_message2.error());
	}

	auto prime1_minus_two = BigInt::mod_subtract(prime1.value(), two.value(), prime1.value());
	auto prime2_minus_two = BigInt::mod_subtract(prime2.value(), two.value(), prime2.value());
	if (!prime1_minus_two)
	{
		return Result<ByteBuffer>::failure(prime1_minus_two.error());
	}
	if (!prime2_minus_two)
	{
		return Result<ByteBuffer>::failure(prime2_minus_two.error());
	}

	auto blinding_mod_prime1_bytes = blinding_mod_prime1.value().to_be_bytes();
	auto blinding_mod_prime2_bytes = blinding_mod_prime2.value().to_be_bytes();
	auto prime1_minus_two_bytes = prime1_minus_two.value().to_be_bytes();
	auto prime2_minus_two_bytes = prime2_minus_two.value().to_be_bytes();
	auto inverse1 = fixed_mod_exp_to_bigint(blinding_mod_prime1_bytes.bytes(), prime1_minus_two_bytes.bytes(), key.prime1.bytes(), key.prime1.size() * 8U);
	auto inverse2 = fixed_mod_exp_to_bigint(blinding_mod_prime2_bytes.bytes(), prime2_minus_two_bytes.bytes(), key.prime2.bytes(), key.prime2.size() * 8U);
	if (!inverse1)
	{
		return Result<ByteBuffer>::failure(inverse1.error());
	}
	if (!inverse2)
	{
		return Result<ByteBuffer>::failure(inverse2.error());
	}

	auto message1 = BigInt::mod_multiply(blinded_message1.value(), inverse1.value(), prime1.value());
	auto message2 = BigInt::mod_multiply(blinded_message2.value(), inverse2.value(), prime2.value());
	if (!message1)
	{
		return Result<ByteBuffer>::failure(message1.error());
	}
	if (!message2)
	{
		return Result<ByteBuffer>::failure(message2.error());
	}

	return crt_recombine(message1.value(), message2.value(), prime1.value(), prime2.value(), coefficient.value(), modulus.value(), key.modulus.size());
}

} // namespace crypto_core::internal
