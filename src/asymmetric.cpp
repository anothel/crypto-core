#include "crypto_core/asymmetric.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/provider.hpp"

namespace crypto_core
{
namespace
{

bool is_known_algorithm(AsymmetricKeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::rsa:
	case AsymmetricKeyAlgorithm::ecdsa_p256:
	case AsymmetricKeyAlgorithm::ecdsa_p384:
	case AsymmetricKeyAlgorithm::ed25519:
		return true;
	}

	return false;
}

Result<void> validate_der_key_material(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der) noexcept
{
	if (!is_known_algorithm(algorithm))
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "asymmetric", "asymmetric key algorithm is not supported"));
	}

	if (der.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "DER key must not be empty"));
	}

	return Result<void>::success();
}

} // namespace

Result<PublicKey> PublicKey::import_der(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der, KeyUsageMask usages)
{
	auto validation = validate_der_key_material(algorithm, der);
	if (!validation)
	{
		return Result<PublicKey>::failure(validation.error());
	}

	return Result<PublicKey>::success(PublicKey(algorithm, usages, ByteBuffer::copy_from(der)));
}

Result<PublicKey> PublicKey::import_der(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der, KeyUsage usage)
{
	return import_der(algorithm, der, key_usage_value(usage));
}

Result<PrivateKey> PrivateKey::import_der(AsymmetricKeyAlgorithm algorithm, SecureBuffer der, KeyUsageMask usages)
{
	auto validation = validate_der_key_material(algorithm, der.bytes());
	if (!validation)
	{
		return Result<PrivateKey>::failure(validation.error());
	}

	return Result<PrivateKey>::success(PrivateKey(algorithm, usages, std::move(der)));
}

Result<PrivateKey> PrivateKey::import_der(AsymmetricKeyAlgorithm algorithm, SecureBuffer der, KeyUsage usage)
{
	return import_der(algorithm, std::move(der), key_usage_value(usage));
}

Result<ByteBuffer> sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept
{
	return sign(default_provider(), params, message);
}

Result<ByteBuffer> sign(ICryptoProvider &provider, const SignParams &params, std::span<const std::uint8_t> message) noexcept
{
	return provider.sign(params, message);
}

Result<VerifyResult> verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept
{
	return verify(default_provider(), params, message);
}

Result<VerifyResult> verify(ICryptoProvider &provider, const VerifyParams &params, std::span<const std::uint8_t> message) noexcept
{
	return provider.verify(params, message);
}

Result<ByteBuffer> asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	return asymmetric_encrypt(default_provider(), params, plaintext);
}

Result<ByteBuffer> asymmetric_encrypt(ICryptoProvider &provider, const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	return provider.asymmetric_encrypt(params, plaintext);
}

Result<ByteBuffer> asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	return asymmetric_decrypt(default_provider(), params, ciphertext);
}

Result<ByteBuffer> asymmetric_decrypt(ICryptoProvider &provider, const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	return provider.asymmetric_decrypt(params, ciphertext);
}

Result<SecureBuffer> derive_shared_secret(const SharedSecretParams &params) noexcept
{
	return derive_shared_secret(default_provider(), params);
}

Result<SecureBuffer> derive_shared_secret(ICryptoProvider &provider, const SharedSecretParams &params) noexcept
{
	return provider.derive_shared_secret(params);
}

} // namespace crypto_core
