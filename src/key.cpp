#include "crypto_core/key.hpp"

#include "crypto_core/error.hpp"

namespace crypto_core
{
namespace
{

bool is_known_algorithm(KeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KeyAlgorithm::generic_secret:
	case KeyAlgorithm::aes_128:
	case KeyAlgorithm::aes_192:
	case KeyAlgorithm::aes_256:
	case KeyAlgorithm::hmac_sha256:
	case KeyAlgorithm::hmac_sha512:
		return true;
	}

	return false;
}

Result<void> validate_secret_key_material(KeyAlgorithm algorithm, std::span<const std::uint8_t> bytes) noexcept
{
	if (!is_known_algorithm(algorithm))
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "key", "key algorithm is not supported"));
	}

	const auto expected_size = key_algorithm_secret_size(algorithm);
	if (expected_size != 0 && bytes.size() != expected_size)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "key", "secret key size does not match algorithm"));
	}
	if (expected_size == 0 && bytes.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "key", "secret key must not be empty"));
	}

	return Result<void>::success();
}

} // namespace

Result<SecretKey> SecretKey::import_raw(KeyAlgorithm algorithm, std::span<const std::uint8_t> bytes, KeyUsageMask usages)
{
	auto validation = validate_secret_key_material(algorithm, bytes);
	if (!validation)
	{
		return Result<SecretKey>::failure(validation.error());
	}

	auto buffer = SecureBuffer::copy_from(bytes);
	if (!buffer)
	{
		return Result<SecretKey>::failure(buffer.error());
	}

	return Result<SecretKey>::success(SecretKey(algorithm, usages, std::move(buffer.value())));
}

Result<SecretKey> SecretKey::import_raw(KeyAlgorithm algorithm, std::span<const std::uint8_t> bytes, KeyUsage usage)
{
	return import_raw(algorithm, bytes, key_usage_value(usage));
}

Result<SecretKey> SecretKey::from_buffer(KeyAlgorithm algorithm, SecureBuffer bytes, KeyUsageMask usages)
{
	auto validation = validate_secret_key_material(algorithm, bytes.bytes());
	if (!validation)
	{
		return Result<SecretKey>::failure(validation.error());
	}

	return Result<SecretKey>::success(SecretKey(algorithm, usages, std::move(bytes)));
}

Result<SecretKey> SecretKey::from_buffer(KeyAlgorithm algorithm, SecureBuffer bytes, KeyUsage usage)
{
	return from_buffer(algorithm, std::move(bytes), key_usage_value(usage));
}

Result<SecureBuffer> SecretKey::export_raw() const
{
	return bytes_.clone();
}

} // namespace crypto_core
