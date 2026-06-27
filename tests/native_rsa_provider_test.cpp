#include "crypto_core/crypto_core.hpp"

#include "rsa_test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
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

crypto_core::PublicKey import_rsa_verify_key()
{
	return crypto_core::test_support::rsa_reference_verify_key();
}

crypto_core::PublicKey import_rsa_sign_verify_key()
{
	return crypto_core::test_support::rsa_reference_sign_verify_key();
}

crypto_core::PrivateKey import_rsa_sign_key()
{
	return crypto_core::test_support::rsa_reference_sign_key();
}

class FailingRng final : public crypto_core::IRng
{
public:
	crypto_core::Result<void> generate(std::span<std::uint8_t>) noexcept override
	{
		return crypto_core::Result<void>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::provider_error, "test", "rng generation failed"));
	}
};

class FailingRngNativeProvider final : public crypto_core::NativeProvider
{
public:
	explicit FailingRngNativeProvider(bool fail_create) noexcept
	    : fail_create_(fail_create)
	{
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IRng>> create_rng(crypto_core::RngAlgorithm algorithm) noexcept override
	{
		requested_algorithm = algorithm;
		++create_rng_calls;
		if (fail_create_)
		{
			return crypto_core::Result<std::unique_ptr<crypto_core::IRng>>::failure(
			    crypto_core::make_error(crypto_core::ErrorCode::provider_error, "test", "rng creation failed"));
		}
		return crypto_core::Result<std::unique_ptr<crypto_core::IRng>>::success(std::make_unique<FailingRng>());
	}

	crypto_core::RngAlgorithm requested_algorithm{crypto_core::RngAlgorithm::os_random};
	int create_rng_calls{0};

private:
	bool fail_create_{false};
};

void require_provider_error(auto result)
{
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::provider_error);
}

void test_native_provider_verifies_rsa_pss_sha256_signature()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_verify_key();
	const auto message = crypto_core::test_support::bytes("rsa pss message");

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, crypto_core::test_support::rsa_reference_pss_signature()}, message.bytes());
	require(result.has_value());
	require(result.value().is_valid());
}

void test_native_provider_rejects_tampered_rsa_pss_inputs()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_verify_key();
	const auto message = crypto_core::test_support::bytes("rsa pss message");
	const auto tampered_message = crypto_core::test_support::bytes("rsa pss tampered");

	auto bad_message = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, crypto_core::test_support::rsa_reference_pss_signature()}, tampered_message.bytes());
	require(bad_message.has_value());
	require(!bad_message.value().is_valid());

	auto tampered_signature = std::vector<std::uint8_t>(
	    crypto_core::test_support::rsa_reference_pss_signature().begin(),
	    crypto_core::test_support::rsa_reference_pss_signature().end());
	tampered_signature[0] ^= 0x80U;
	auto bad_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, tampered_signature}, message.bytes());
	require(bad_signature.has_value());
	require(!bad_signature.value().is_valid());
}

void test_native_provider_rejects_rsa_pss_parameter_misuse()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_verify_key();
	auto private_key = import_rsa_sign_key();
	const auto message = crypto_core::test_support::bytes("rsa pss message");

	auto wrong_salt = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	wrong_salt.salt_length = 31;
	auto bad_verify = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key, crypto_core::test_support::rsa_reference_pss_signature(), wrong_salt}, message.bytes());
	require(bad_verify.has_value());
	require(!bad_verify.value().is_valid());

	auto too_large_salt = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	too_large_salt.salt_length = 95;
	auto bad_sign = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key, too_large_salt}, message.bytes());
	require(!bad_sign.has_value());
	require(bad_sign.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_native_provider_signs_rsa_pss_sha256_and_verifies_result()
{
	crypto_core::NativeProvider provider;
	auto private_key = import_rsa_sign_key();
	auto public_key = import_rsa_sign_verify_key();
	const auto message = crypto_core::test_support::bytes("native rsa pss signing");

	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &private_key}, message.bytes());
	require(signature.has_value());
	require(signature.value().size() == 128);

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, signature.value().bytes()}, message.bytes());
	require(verified.has_value());
	require(verified.value().is_valid());

	auto tampered = signature.value();
	tampered.bytes()[0] ^= 0x80U;
	auto bad_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, tampered.bytes()}, message.bytes());
	require(bad_signature.has_value());
	require(!bad_signature.value().is_valid());
}

void test_native_provider_encrypts_and_decrypts_rsa_oaep_sha256()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_sign_verify_key();
	auto private_key = import_rsa_sign_key();
	const auto plaintext = crypto_core::test_support::bytes("native rsa oaep");

	auto ciphertext = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &public_key}, plaintext.bytes());
	require(ciphertext.has_value());
	require(ciphertext.value().size() == 128);

	auto decrypted = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key}, ciphertext.value().bytes());
	require(decrypted.has_value());
	require(decrypted.value() == plaintext);
}

void test_native_provider_rsa_oaep_uses_label_and_rejects_tampering()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_sign_verify_key();
	auto private_key = import_rsa_sign_key();
	const auto plaintext = crypto_core::test_support::bytes("labeled oaep");
	const auto label = crypto_core::test_support::bytes("context label");
	const auto wrong_label = crypto_core::test_support::bytes("wrong label");
	const auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, label.bytes());
	const auto wrong_params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, wrong_label.bytes());

	auto ciphertext = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &public_key, params}, plaintext.bytes());
	require(ciphertext.has_value());

	auto decrypted = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key, params}, ciphertext.value().bytes());
	require(decrypted.has_value());
	require(decrypted.value() == plaintext);

	auto wrong = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key, wrong_params}, ciphertext.value().bytes());
	require(!wrong.has_value());
	require(wrong.error().code() == crypto_core::ErrorCode::authentication_failed);

	auto tampered = ciphertext.value();
	tampered.bytes()[0] ^= 0x80U;
	auto bad = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key, params}, tampered.bytes());
	require(!bad.has_value());
	require(bad.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_native_provider_rejects_rsa_oaep_parameter_misuse()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_sign_verify_key();
	auto private_key = import_rsa_sign_key();
	std::vector<std::uint8_t> too_large_plaintext(63, 0xA5U);
	const std::array<std::uint8_t, 16> short_ciphertext{};

	auto too_large = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &public_key}, too_large_plaintext);
	require(!too_large.has_value());
	require(too_large.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto short_input = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key}, short_ciphertext);
	require(!short_input.has_value());
	require(short_input.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_native_provider_propagates_rsa_rng_creation_failure()
{
	auto private_key = import_rsa_sign_key();
	auto public_key = import_rsa_sign_verify_key();
	const auto message = crypto_core::test_support::bytes("rsa rng failure");
	const auto plaintext = crypto_core::test_support::bytes("rsa oaep rng");
	auto zero_salt = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	zero_salt.salt_length = 0;

	FailingRngNativeProvider pss_salt_provider(true);
	require_provider_error(crypto_core::sign(pss_salt_provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &private_key}, message.bytes()));
	require(pss_salt_provider.create_rng_calls == 1);
	require(pss_salt_provider.requested_algorithm == crypto_core::RngAlgorithm::os_random);

	FailingRngNativeProvider pss_blinding_provider(true);
	require_provider_error(crypto_core::sign(pss_blinding_provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key, zero_salt}, message.bytes()));
	require(pss_blinding_provider.create_rng_calls == 1);

	FailingRngNativeProvider oaep_encrypt_provider(true);
	require_provider_error(crypto_core::asymmetric_encrypt(oaep_encrypt_provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &public_key}, plaintext.bytes()));
	require(oaep_encrypt_provider.create_rng_calls == 1);

	FailingRngNativeProvider oaep_decrypt_provider(true);
	require_provider_error(crypto_core::asymmetric_decrypt(
	    oaep_decrypt_provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key},
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext()));
	require(oaep_decrypt_provider.create_rng_calls == 1);
}

void test_native_provider_propagates_rsa_rng_generation_failure()
{
	auto private_key = import_rsa_sign_key();
	auto public_key = import_rsa_sign_verify_key();
	const auto message = crypto_core::test_support::bytes("rsa rng failure");
	const auto plaintext = crypto_core::test_support::bytes("rsa oaep rng");
	auto zero_salt = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	zero_salt.salt_length = 0;

	FailingRngNativeProvider pss_salt_provider(false);
	require_provider_error(crypto_core::sign(pss_salt_provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &private_key}, message.bytes()));
	require(pss_salt_provider.create_rng_calls == 1);
	require(pss_salt_provider.requested_algorithm == crypto_core::RngAlgorithm::os_random);

	FailingRngNativeProvider pss_blinding_provider(false);
	require_provider_error(crypto_core::sign(pss_blinding_provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key, zero_salt}, message.bytes()));
	require(pss_blinding_provider.create_rng_calls == 1);

	FailingRngNativeProvider oaep_encrypt_provider(false);
	require_provider_error(crypto_core::asymmetric_encrypt(oaep_encrypt_provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &public_key}, plaintext.bytes()));
	require(oaep_encrypt_provider.create_rng_calls == 1);

	FailingRngNativeProvider oaep_decrypt_provider(false);
	require_provider_error(crypto_core::asymmetric_decrypt(
	    oaep_decrypt_provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key},
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext()));
	require(oaep_decrypt_provider.create_rng_calls == 1);
}

} // namespace

int main()
{
	test_native_provider_verifies_rsa_pss_sha256_signature();
	test_native_provider_rejects_tampered_rsa_pss_inputs();
	test_native_provider_rejects_rsa_pss_parameter_misuse();
	test_native_provider_signs_rsa_pss_sha256_and_verifies_result();
	test_native_provider_encrypts_and_decrypts_rsa_oaep_sha256();
	test_native_provider_rsa_oaep_uses_label_and_rejects_tampering();
	test_native_provider_rejects_rsa_oaep_parameter_misuse();
	test_native_provider_propagates_rsa_rng_creation_failure();
	test_native_provider_propagates_rsa_rng_generation_failure();
	return 0;
}
