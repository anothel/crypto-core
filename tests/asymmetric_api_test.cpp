#include "crypto_core/crypto_core.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

class MinimalHashContext final : public crypto_core::IHashContext
{
public:
	crypto_core::Result<void> update(std::span<const std::uint8_t>) noexcept override
	{
		return crypto_core::Result<void>::success();
	}

	crypto_core::Result<crypto_core::ByteBuffer> final() noexcept override
	{
		return crypto_core::Result<crypto_core::ByteBuffer>::success(crypto_core::ByteBuffer{});
	}
};

class UnsupportedAsymmetricProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "UnsupportedAsymmetricProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<MinimalHashContext>());
	}
};

class InvalidSignatureProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "InvalidSignatureProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	bool supports(crypto_core::SignatureAlgorithm algorithm) const noexcept override
	{
		return algorithm == crypto_core::SignatureAlgorithm::ed25519;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<MinimalHashContext>());
	}

	crypto_core::Result<crypto_core::VerifyResult> verify(
	    const crypto_core::VerifyParams &,
	    std::span<const std::uint8_t>) noexcept override
	{
		return crypto_core::Result<crypto_core::VerifyResult>::success(crypto_core::VerifyResult::invalid());
	}
};

void test_asymmetric_algorithm_metadata()
{
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::rsa) == std::string_view{"RSA"});
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256) == std::string_view{"ECDSA-P256"});
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::ed25519) == std::string_view{"Ed25519"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::rsa_pss) == std::string_view{"RSA-PSS"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::rsa_pss_sha256) == std::string_view{"RSA-PSS-SHA256"});
	require(crypto_core::asymmetric_encryption_algorithm_name(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep) == std::string_view{"RSA-OAEP"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256) == std::string_view{"ECDSA-P256-SHA256"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::ed25519) == std::string_view{"Ed25519"});
	require(crypto_core::verify_status_name(crypto_core::VerifyStatus::valid) == std::string_view{"valid"});
	require(crypto_core::verify_status_name(crypto_core::VerifyStatus::invalid) == std::string_view{"invalid"});
}

void test_rsa_pss_params_are_explicit()
{
	const auto defaults = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	require(defaults.message_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.salt_length == crypto_core::digest_size(crypto_core::HashAlgorithm::sha256));

	const crypto_core::RsaPssParams custom{
	    crypto_core::HashAlgorithm::sha512,
	    crypto_core::HashAlgorithm::sha256,
	    20,
	};
	require(custom.message_hash == crypto_core::HashAlgorithm::sha512);
	require(custom.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(custom.salt_length == 20);
}

void test_rsa_oaep_params_own_label()
{
	const std::array<std::uint8_t, 3> label{1, 2, 3};
	auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha512, label);
	require(params.message_hash == crypto_core::HashAlgorithm::sha512);
	require(params.mgf1_hash == crypto_core::HashAlgorithm::sha512);
	require(params.label.size() == label.size());
	params.label.bytes()[0] = 0xFFU;
	require(label[0] == 1U);

	const auto defaults = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	require(defaults.message_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.label.empty());
}

void test_public_and_private_key_import_export()
{
	const std::array<std::uint8_t, 4> public_der{1, 2, 3, 4};
	const std::array<std::uint8_t, 5> private_der{9, 8, 7, 6, 5};

	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, public_der, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	require(public_key.has_value());
	require(public_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(public_key.value().allows(crypto_core::KeyUsage::verify));
	require(public_key.value().allows(crypto_core::KeyUsage::encrypt));
	require(!public_key.value().allows(crypto_core::KeyUsage::decrypt));
	require(public_key.value().size() == public_der.size());

	auto exported_public = public_key.value().export_der();
	require(exported_public.size() == public_der.size());
	exported_public.bytes()[0] = 0xFFU;
	require(public_key.value().bytes()[0] == 1U);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(private_der);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(private_buffer.value()), crypto_core::KeyUsage::sign | crypto_core::KeyUsage::decrypt);
	require(private_key.has_value());
	require(private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(private_key.value().allows(crypto_core::KeyUsage::sign));
	require(private_key.value().allows(crypto_core::KeyUsage::decrypt));
	require(!private_key.value().allows(crypto_core::KeyUsage::verify));
	require(private_key.value().size() == private_der.size());

	auto exported_private = private_key.value().export_der();
	require(exported_private.has_value());
	require(exported_private.value().size() == private_der.size());
	exported_private.value().bytes()[0] = 0xAAU;
	require(private_key.value().bytes()[0] == 9U);
}

void test_asymmetric_keys_reject_empty_der()
{
	const std::array<std::uint8_t, 0> empty{};

	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, empty, crypto_core::KeyUsage::verify);
	require(!public_key.has_value());
	require(public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(empty);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, std::move(private_buffer.value()), crypto_core::KeyUsage::sign);
	require(!private_key.has_value());
	require(private_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_private_key_and_key_pair_are_move_only()
{
	static_assert(std::is_copy_constructible_v<crypto_core::PublicKey>);
	static_assert(!std::is_copy_constructible_v<crypto_core::PrivateKey>);
	static_assert(!std::is_copy_assignable_v<crypto_core::PrivateKey>);
	static_assert(std::is_move_constructible_v<crypto_core::PrivateKey>);
	static_assert(std::is_move_assignable_v<crypto_core::PrivateKey>);
	static_assert(!std::is_copy_constructible_v<crypto_core::KeyPair>);
	static_assert(!std::is_copy_assignable_v<crypto_core::KeyPair>);
	static_assert(std::is_move_constructible_v<crypto_core::KeyPair>);
	static_assert(std::is_move_assignable_v<crypto_core::KeyPair>);
}

void test_rsa_key_generation_params_have_safe_defaults()
{
	const crypto_core::RsaKeyGenerationParams params{};
	require(params.modulus_bits == 2048);
	require(params.public_exponent == 65537);
	require(crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::verify));
	require(crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::encrypt));
	require(crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::sign));
	require(crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::decrypt));
}

void test_default_provider_reports_rsa_pss_signature_support()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss));
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss_sha256));
	require(!provider.supports(crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256));
	require(!provider.supports(crypto_core::KeyAgreementAlgorithm::ecdh_p256));
}

void test_asymmetric_provider_defaults_return_unsupported_algorithm()
{
	UnsupportedAsymmetricProvider provider;
	const std::array<std::uint8_t, 3> message{1, 2, 3};
	const std::array<std::uint8_t, 3> key_der{4, 5, 6};
	const std::array<std::uint8_t, 2> signature{7, 8};

	auto private_buffer = crypto_core::SecureBuffer::copy_from(key_der);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(private_buffer.value()), crypto_core::KeyUsage::sign | crypto_core::KeyUsage::decrypt | crypto_core::KeyUsage::derive);
	require(private_key.has_value());
	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, key_der, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	require(public_key.has_value());

	auto sign_result = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key.value(), crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!sign_result.has_value());
	require(sign_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto verify_result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key.value(), signature, crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!verify_result.has_value());
	require(verify_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto encrypt_result = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &public_key.value(), crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!encrypt_result.has_value());
	require(encrypt_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto decrypt_result = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key.value(), crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!decrypt_result.has_value());
	require(decrypt_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto secret_result = crypto_core::derive_shared_secret(provider, {crypto_core::KeyAgreementAlgorithm::ecdh_p256, &private_key.value(), &public_key.value()});
	require(!secret_result.has_value());
	require(secret_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto key_pair_result = crypto_core::generate_key_pair(provider, {crypto_core::AsymmetricKeyAlgorithm::rsa});
	require(!key_pair_result.has_value());
	require(key_pair_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

void test_invalid_signature_is_successful_verify_result()
{
	InvalidSignatureProvider provider;
	const std::array<std::uint8_t, 3> message{1, 2, 3};
	const std::array<std::uint8_t, 3> key_der{4, 5, 6};
	const std::array<std::uint8_t, 2> signature{7, 8};
	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, key_der, crypto_core::KeyUsage::verify);
	require(public_key.has_value());

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key.value(), signature}, message);
	require(result.has_value());
	require(result.value().status == crypto_core::VerifyStatus::invalid);
	require(!result.value().is_valid());
}

} // namespace

int main()
{
	test_asymmetric_algorithm_metadata();
	test_rsa_pss_params_are_explicit();
	test_rsa_oaep_params_own_label();
	test_public_and_private_key_import_export();
	test_asymmetric_keys_reject_empty_der();
	test_private_key_and_key_pair_are_move_only();
	test_rsa_key_generation_params_have_safe_defaults();
	test_default_provider_reports_rsa_pss_signature_support();
	test_asymmetric_provider_defaults_return_unsupported_algorithm();
	test_invalid_signature_is_successful_verify_result();
	return 0;
}
