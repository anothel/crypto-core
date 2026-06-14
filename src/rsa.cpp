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

} // namespace

Result<ByteBuffer> rsa_public_operation(const RsaPublicKeyMaterial &key, std::span<const std::uint8_t> input)
{
	return rsa_operation(key.modulus.bytes(), key.public_exponent.bytes(), input);
}

Result<ByteBuffer> rsa_private_operation(const RsaPrivateKeyMaterial &key, std::span<const std::uint8_t> input)
{
	return rsa_operation(key.modulus.bytes(), key.private_exponent.bytes(), input);
}

} // namespace crypto_core::internal
