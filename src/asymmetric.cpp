#include "crypto_core/asymmetric.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/ec_der.hpp"
#include "crypto_core/internal/rsa_der.hpp"
#include "crypto_core/provider.hpp"

namespace crypto_core
{
namespace
{

constexpr std::size_t ed25519_raw_key_size = 32;

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

	if (algorithm == AsymmetricKeyAlgorithm::ed25519)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "Ed25519 DER import is not implemented; use raw Ed25519 import APIs"));
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

	return Result<PublicKey>::success(PublicKey(algorithm, usages, ByteBuffer::copy_from(der), true));
}

Result<PublicKey> PublicKey::import_der(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der, KeyUsage usage)
{
	return import_der(algorithm, der, key_usage_value(usage));
}

Result<PublicKey> PublicKey::import_spki_der(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der, KeyUsageMask usages)
{
	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::rsa: {
		auto parsed = internal::parse_rsa_spki_public_key_der(der);
		if (!parsed)
		{
			return Result<PublicKey>::failure(parsed.error());
		}
		break;
	}
	case AsymmetricKeyAlgorithm::ecdsa_p256: {
		auto parsed = internal::parse_p256_public_key_der(der);
		if (!parsed)
		{
			return Result<PublicKey>::failure(parsed.error());
		}
		break;
	}
	case AsymmetricKeyAlgorithm::ecdsa_p384:
	case AsymmetricKeyAlgorithm::ed25519:
		return Result<PublicKey>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "SPKI DER import is not implemented for this algorithm"));
	}

	return Result<PublicKey>::success(PublicKey(algorithm, usages, ByteBuffer::copy_from(der), true));
}

Result<PublicKey> PublicKey::import_spki_der(AsymmetricKeyAlgorithm algorithm, std::span<const std::uint8_t> der, KeyUsage usage)
{
	return import_spki_der(algorithm, der, key_usage_value(usage));
}

Result<PublicKey> PublicKey::import_rsa_pkcs1_der(std::span<const std::uint8_t> der, KeyUsageMask usages)
{
	auto parsed = internal::parse_rsa_pkcs1_public_key_der(der);
	if (!parsed)
	{
		return Result<PublicKey>::failure(parsed.error());
	}

	return Result<PublicKey>::success(PublicKey(AsymmetricKeyAlgorithm::rsa, usages, ByteBuffer::copy_from(der), true));
}

Result<PublicKey> PublicKey::import_rsa_pkcs1_der(std::span<const std::uint8_t> der, KeyUsage usage)
{
	return import_rsa_pkcs1_der(der, key_usage_value(usage));
}

Result<PublicKey> PublicKey::import_raw_ed25519(std::span<const std::uint8_t> raw_public_key, KeyUsageMask usages)
{
	if (raw_public_key.size() != ed25519_raw_key_size)
	{
		return Result<PublicKey>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "Ed25519 raw public key must be 32 bytes"));
	}

	return Result<PublicKey>::success(PublicKey(AsymmetricKeyAlgorithm::ed25519, usages, ByteBuffer::copy_from(raw_public_key), false));
}

Result<PublicKey> PublicKey::import_raw_ed25519(std::span<const std::uint8_t> raw_public_key, KeyUsage usage)
{
	return import_raw_ed25519(raw_public_key, key_usage_value(usage));
}

Result<PrivateKey> PrivateKey::import_der(AsymmetricKeyAlgorithm algorithm, SecureBuffer der, KeyUsageMask usages)
{
	auto validation = validate_der_key_material(algorithm, der.bytes());
	if (!validation)
	{
		return Result<PrivateKey>::failure(validation.error());
	}

	return Result<PrivateKey>::success(PrivateKey(algorithm, usages, std::move(der), true));
}

Result<PrivateKey> PrivateKey::import_der(AsymmetricKeyAlgorithm algorithm, SecureBuffer der, KeyUsage usage)
{
	return import_der(algorithm, std::move(der), key_usage_value(usage));
}

Result<PrivateKey> PrivateKey::import_rsa_pkcs1_der(SecureBuffer der, KeyUsageMask usages)
{
	auto parsed = internal::parse_rsa_pkcs1_private_key_der(der.bytes());
	if (!parsed)
	{
		return Result<PrivateKey>::failure(parsed.error());
	}

	return Result<PrivateKey>::success(PrivateKey(AsymmetricKeyAlgorithm::rsa, usages, std::move(der), true));
}

Result<PrivateKey> PrivateKey::import_rsa_pkcs1_der(SecureBuffer der, KeyUsage usage)
{
	return import_rsa_pkcs1_der(std::move(der), key_usage_value(usage));
}

Result<PrivateKey> PrivateKey::import_raw_ed25519_seed(SecureBuffer raw_seed, KeyUsageMask usages)
{
	if (raw_seed.size() != ed25519_raw_key_size)
	{
		return Result<PrivateKey>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "Ed25519 raw private seed must be 32 bytes"));
	}

	return Result<PrivateKey>::success(PrivateKey(AsymmetricKeyAlgorithm::ed25519, usages, std::move(raw_seed), false));
}

Result<PrivateKey> PrivateKey::import_raw_ed25519_seed(SecureBuffer raw_seed, KeyUsage usage)
{
	return import_raw_ed25519_seed(std::move(raw_seed), key_usage_value(usage));
}

Result<ByteBuffer> PublicKey::export_der() const
{
	if (!der_encoded_)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "public key material is not DER encoded"));
	}

	return Result<ByteBuffer>::success(ByteBuffer::copy_from(material_.bytes()));
}

Result<SecureBuffer> PrivateKey::export_der() const
{
	if (!der_encoded_)
	{
		return Result<SecureBuffer>::failure(make_error(ErrorCode::invalid_key, "asymmetric", "private key material is not DER encoded"));
	}

	return material_.clone();
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

Result<KeyPair> generate_key_pair(const GenerateKeyPairParams &params) noexcept
{
	return generate_key_pair(default_provider(), params);
}

Result<KeyPair> generate_key_pair(ICryptoProvider &provider, const GenerateKeyPairParams &params) noexcept
{
	return provider.generate_key_pair(params);
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
