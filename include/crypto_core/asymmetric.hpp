#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/hash.hpp"
#include "crypto_core/key.hpp"
#include "crypto_core/result.hpp"
#include "crypto_core/secure_buffer.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace crypto_core
{

class ICryptoProvider;

enum class AsymmetricKeyAlgorithm
{
	rsa,
	ecdsa_p256,
	ecdsa_p384,
	ed25519,
};

enum class SignatureAlgorithm
{
	rsa_pss,
	rsa_pss_sha256,
	ecdsa_p256_sha256,
	ecdsa_p384_sha384,
	ed25519,
};

enum class AsymmetricEncryptionAlgorithm
{
	rsa_oaep,
	rsa_oaep_sha256,
};

enum class KeyAgreementAlgorithm
{
	ecdh_p256,
	ecdh_p384,
};

enum class VerifyStatus
{
	valid,
	invalid,
};

[[nodiscard]] constexpr std::string_view asymmetric_key_algorithm_name(AsymmetricKeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::rsa:
		return "RSA";
	case AsymmetricKeyAlgorithm::ecdsa_p256:
		return "ECDSA-P256";
	case AsymmetricKeyAlgorithm::ecdsa_p384:
		return "ECDSA-P384";
	case AsymmetricKeyAlgorithm::ed25519:
		return "Ed25519";
	}

	return "unknown";
}

[[nodiscard]] constexpr std::string_view signature_algorithm_name(SignatureAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case SignatureAlgorithm::rsa_pss:
		return "RSA-PSS";
	case SignatureAlgorithm::rsa_pss_sha256:
		return "RSA-PSS-SHA256";
	case SignatureAlgorithm::ecdsa_p256_sha256:
		return "ECDSA-P256-SHA256";
	case SignatureAlgorithm::ecdsa_p384_sha384:
		return "ECDSA-P384-SHA384";
	case SignatureAlgorithm::ed25519:
		return "Ed25519";
	}

	return "unknown";
}

[[nodiscard]] constexpr std::string_view asymmetric_encryption_algorithm_name(AsymmetricEncryptionAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricEncryptionAlgorithm::rsa_oaep:
		return "RSA-OAEP";
	case AsymmetricEncryptionAlgorithm::rsa_oaep_sha256:
		return "RSA-OAEP-SHA256";
	}

	return "unknown";
}

[[nodiscard]] constexpr std::string_view key_agreement_algorithm_name(KeyAgreementAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KeyAgreementAlgorithm::ecdh_p256:
		return "ECDH-P256";
	case KeyAgreementAlgorithm::ecdh_p384:
		return "ECDH-P384";
	}

	return "unknown";
}

[[nodiscard]] constexpr std::string_view verify_status_name(VerifyStatus status) noexcept
{
	switch (status)
	{
	case VerifyStatus::valid:
		return "valid";
	case VerifyStatus::invalid:
		return "invalid";
	}

	return "unknown";
}

class PublicKey final
{
public:
	[[nodiscard]] static Result<PublicKey> import_der(
	    AsymmetricKeyAlgorithm algorithm,
	    std::span<const std::uint8_t> der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PublicKey> import_der(
	    AsymmetricKeyAlgorithm algorithm,
	    std::span<const std::uint8_t> der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PublicKey> import_spki_der(
	    AsymmetricKeyAlgorithm algorithm,
	    std::span<const std::uint8_t> der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PublicKey> import_spki_der(
	    AsymmetricKeyAlgorithm algorithm,
	    std::span<const std::uint8_t> der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PublicKey> import_rsa_pkcs1_der(
	    std::span<const std::uint8_t> der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PublicKey> import_rsa_pkcs1_der(
	    std::span<const std::uint8_t> der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PublicKey> import_raw_ed25519(
	    std::span<const std::uint8_t> raw_public_key,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PublicKey> import_raw_ed25519(
	    std::span<const std::uint8_t> raw_public_key,
	    KeyUsage usage);

	[[nodiscard]] AsymmetricKeyAlgorithm algorithm() const noexcept
	{
		return algorithm_;
	}

	[[nodiscard]] KeyUsageMask usages() const noexcept
	{
		return usages_;
	}

	[[nodiscard]] bool allows(KeyUsage usage) const noexcept
	{
		return has_key_usage(usages_, usage);
	}

	[[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
	{
		return material_.bytes();
	}

	[[nodiscard]] std::size_t size() const noexcept
	{
		return material_.size();
	}

	[[nodiscard]] bool empty() const noexcept
	{
		return material_.empty();
	}

	[[nodiscard]] bool is_der_encoded() const noexcept
	{
		return der_encoded_;
	}

	[[nodiscard]] Result<ByteBuffer> export_der() const;

private:
	PublicKey(AsymmetricKeyAlgorithm algorithm, KeyUsageMask usages, ByteBuffer material, bool der_encoded) noexcept
	    : algorithm_(algorithm), usages_(usages), material_(std::move(material)), der_encoded_(der_encoded)
	{
	}

	AsymmetricKeyAlgorithm algorithm_{AsymmetricKeyAlgorithm::rsa};
	KeyUsageMask usages_{key_usage_value(KeyUsage::none)};
	ByteBuffer material_;
	bool der_encoded_{false};
};

class PrivateKey final
{
public:
	PrivateKey(const PrivateKey &) = delete;
	PrivateKey &operator=(const PrivateKey &) = delete;
	PrivateKey(PrivateKey &&) noexcept = default;
	PrivateKey &operator=(PrivateKey &&) noexcept = default;

	[[nodiscard]] static Result<PrivateKey> import_der(
	    AsymmetricKeyAlgorithm algorithm,
	    SecureBuffer der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PrivateKey> import_der(
	    AsymmetricKeyAlgorithm algorithm,
	    SecureBuffer der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PrivateKey> import_pkcs8_der(
	    AsymmetricKeyAlgorithm algorithm,
	    SecureBuffer der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PrivateKey> import_pkcs8_der(
	    AsymmetricKeyAlgorithm algorithm,
	    SecureBuffer der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PrivateKey> import_rsa_pkcs1_der(
	    SecureBuffer der,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PrivateKey> import_rsa_pkcs1_der(
	    SecureBuffer der,
	    KeyUsage usage);
	[[nodiscard]] static Result<PrivateKey> import_raw_ed25519_seed(
	    SecureBuffer raw_seed,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<PrivateKey> import_raw_ed25519_seed(
	    SecureBuffer raw_seed,
	    KeyUsage usage);

	[[nodiscard]] AsymmetricKeyAlgorithm algorithm() const noexcept
	{
		return algorithm_;
	}

	[[nodiscard]] KeyUsageMask usages() const noexcept
	{
		return usages_;
	}

	[[nodiscard]] bool allows(KeyUsage usage) const noexcept
	{
		return has_key_usage(usages_, usage);
	}

	[[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
	{
		return material_.bytes();
	}

	[[nodiscard]] std::size_t size() const noexcept
	{
		return material_.size();
	}

	[[nodiscard]] bool empty() const noexcept
	{
		return material_.empty();
	}

	[[nodiscard]] bool is_der_encoded() const noexcept
	{
		return der_encoded_;
	}

	[[nodiscard]] Result<SecureBuffer> export_der() const;

private:
	PrivateKey(AsymmetricKeyAlgorithm algorithm, KeyUsageMask usages, SecureBuffer material, bool der_encoded) noexcept
	    : algorithm_(algorithm), usages_(usages), material_(std::move(material)), der_encoded_(der_encoded)
	{
	}

	AsymmetricKeyAlgorithm algorithm_{AsymmetricKeyAlgorithm::rsa};
	KeyUsageMask usages_{key_usage_value(KeyUsage::none)};
	SecureBuffer material_;
	bool der_encoded_{false};
};

struct KeyPair final
{
	PublicKey public_key;
	PrivateKey private_key;
};

struct RsaKeyGenerationParams final
{
	std::size_t modulus_bits{2048};
	std::uint32_t public_exponent{65537};
	KeyUsageMask public_usages{KeyUsage::verify | KeyUsage::encrypt};
	KeyUsageMask private_usages{KeyUsage::sign | KeyUsage::decrypt};
};

struct EcKeyGenerationParams final
{
	KeyUsageMask public_usages{key_usage_value(KeyUsage::verify)};
	KeyUsageMask private_usages{key_usage_value(KeyUsage::sign)};
};

struct GenerateKeyPairParams final
{
	AsymmetricKeyAlgorithm algorithm;
	RsaKeyGenerationParams rsa{};
	EcKeyGenerationParams ec{};
};

struct VerifyResult final
{
	VerifyStatus status{VerifyStatus::invalid};

	[[nodiscard]] static constexpr VerifyResult valid() noexcept
	{
		return VerifyResult{VerifyStatus::valid};
	}

	[[nodiscard]] static constexpr VerifyResult invalid() noexcept
	{
		return VerifyResult{VerifyStatus::invalid};
	}

	[[nodiscard]] constexpr bool is_valid() const noexcept
	{
		return status == VerifyStatus::valid;
	}
};

struct RsaPssParams final
{
	HashAlgorithm message_hash{HashAlgorithm::sha256};
	HashAlgorithm mgf1_hash{HashAlgorithm::sha256};
	std::size_t salt_length{digest_size(HashAlgorithm::sha256)};

	[[nodiscard]] static constexpr RsaPssParams for_hash(HashAlgorithm hash) noexcept
	{
		return RsaPssParams{hash, hash, digest_size(hash)};
	}
};

struct RsaOaepParams final
{
	HashAlgorithm message_hash{HashAlgorithm::sha256};
	HashAlgorithm mgf1_hash{HashAlgorithm::sha256};
	ByteBuffer label{};

	[[nodiscard]] static RsaOaepParams for_hash(HashAlgorithm hash)
	{
		return RsaOaepParams{hash, hash, ByteBuffer{}};
	}

	[[nodiscard]] static RsaOaepParams with_label(HashAlgorithm hash, std::span<const std::uint8_t> label)
	{
		return RsaOaepParams{hash, hash, ByteBuffer::copy_from(label)};
	}
};

struct SignParams final
{
	SignatureAlgorithm algorithm;
	const PrivateKey *private_key;
	RsaPssParams rsa_pss{};
};

struct VerifyParams final
{
	SignatureAlgorithm algorithm;
	const PublicKey *public_key;
	std::span<const std::uint8_t> signature;
	RsaPssParams rsa_pss{};
};

struct AsymmetricEncryptParams final
{
	AsymmetricEncryptionAlgorithm algorithm;
	const PublicKey *public_key;
	RsaOaepParams rsa_oaep{};
};

struct AsymmetricDecryptParams final
{
	AsymmetricEncryptionAlgorithm algorithm;
	const PrivateKey *private_key;
	RsaOaepParams rsa_oaep{};
};

struct SharedSecretParams final
{
	KeyAgreementAlgorithm algorithm;
	const PrivateKey *private_key;
	const PublicKey *peer_public_key;
};

[[nodiscard]] Result<ByteBuffer> sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept;
[[nodiscard]] Result<ByteBuffer> sign(ICryptoProvider &provider, const SignParams &params, std::span<const std::uint8_t> message) noexcept;

[[nodiscard]] Result<VerifyResult> verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept;
[[nodiscard]] Result<VerifyResult> verify(ICryptoProvider &provider, const VerifyParams &params, std::span<const std::uint8_t> message) noexcept;

[[nodiscard]] Result<KeyPair> generate_key_pair(const GenerateKeyPairParams &params) noexcept;
[[nodiscard]] Result<KeyPair> generate_key_pair(ICryptoProvider &provider, const GenerateKeyPairParams &params) noexcept;

[[nodiscard]] Result<ByteBuffer> asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
[[nodiscard]] Result<ByteBuffer> asymmetric_encrypt(ICryptoProvider &provider, const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;

[[nodiscard]] Result<ByteBuffer> asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;
[[nodiscard]] Result<ByteBuffer> asymmetric_decrypt(ICryptoProvider &provider, const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;

[[nodiscard]] Result<SecureBuffer> derive_shared_secret(const SharedSecretParams &params) noexcept;
[[nodiscard]] Result<SecureBuffer> derive_shared_secret(ICryptoProvider &provider, const SharedSecretParams &params) noexcept;

} // namespace crypto_core
