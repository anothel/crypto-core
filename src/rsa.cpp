#include "crypto_core/internal/rsa.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/bigint.hpp"

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

} // namespace

Result<ByteBuffer> rsa_public_operation(const RsaPublicKeyMaterial &key, std::span<const std::uint8_t> input)
{
	return rsa_operation(key.modulus.bytes(), key.public_exponent.bytes(), input);
}

Result<ByteBuffer> rsa_private_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input)
{
	return rsa_operation(key.modulus.bytes(), key.private_exponent.bytes(), input);
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

	auto message1 = BigInt::mod_exp(representative.value(), exponent1.value(), prime1.value());
	if (!message1)
	{
		return Result<ByteBuffer>::failure(message1.error());
	}
	auto message2 = BigInt::mod_exp(representative.value(), exponent2.value(), prime2.value());
	if (!message2)
	{
		return Result<ByteBuffer>::failure(message2.error());
	}

	auto difference = BigInt::mod_subtract(message1.value(), message2.value(), prime1.value());
	if (!difference)
	{
		return Result<ByteBuffer>::failure(difference.error());
	}
	auto h = BigInt::mod_multiply(coefficient.value(), difference.value(), prime1.value());
	if (!h)
	{
		return Result<ByteBuffer>::failure(h.error());
	}
	auto qh = BigInt::mod_multiply(prime2.value(), h.value(), modulus.value());
	if (!qh)
	{
		return Result<ByteBuffer>::failure(qh.error());
	}
	auto output = BigInt::mod_add(message2.value(), qh.value(), modulus.value());
	if (!output)
	{
		return Result<ByteBuffer>::failure(output.error());
	}

	return left_pad_to_width(output.value(), key.modulus.size());
}

} // namespace crypto_core::internal
