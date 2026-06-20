#include "crypto_core/crypto_core.hpp"

#include "rsa_test_vectors.hpp"

#include <cstdint>
#include <cstdlib>
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

} // namespace

int main()
{
	test_native_provider_verifies_rsa_pss_sha256_signature();
	test_native_provider_rejects_tampered_rsa_pss_inputs();
	test_native_provider_signs_rsa_pss_sha256_and_verifies_result();
	test_native_provider_encrypts_and_decrypts_rsa_oaep_sha256();
	test_native_provider_rsa_oaep_uses_label_and_rejects_tampering();
	return 0;
}
