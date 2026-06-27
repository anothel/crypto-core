#include "crypto_core/crypto_core.hpp"

#include "rsa_test_vectors.hpp"

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

void test_native_provider_verifies_reference_rsa_pss_vector()
{
	crypto_core::NativeProvider provider;
	auto public_key = crypto_core::test_support::rsa_reference_verify_key();
	const auto message = crypto_core::test_support::bytes("rsa pss message");

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, crypto_core::test_support::rsa_reference_pss_signature()}, message.bytes());
	require(result.has_value());
	require(result.value().is_valid());
}

void test_native_provider_rejects_tampered_reference_rsa_pss_vector()
{
	crypto_core::NativeProvider provider;
	auto public_key = crypto_core::test_support::rsa_reference_verify_key();
	auto wrong_public_key = crypto_core::test_support::rsa_reference_sign_verify_key();
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

	auto wrong_key = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &wrong_public_key, crypto_core::test_support::rsa_reference_pss_signature()}, message.bytes());
	require(wrong_key.has_value());
	require(!wrong_key.value().is_valid());

	auto wrong_hash_params = crypto_core::verify(
	    provider,
	    {crypto_core::SignatureAlgorithm::rsa_pss, &public_key, crypto_core::test_support::rsa_reference_pss_signature(), crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha512)},
	    message.bytes());
	require(wrong_hash_params.has_value());
	require(!wrong_hash_params.value().is_valid());

	auto short_signature = std::vector<std::uint8_t>(
	    crypto_core::test_support::rsa_reference_pss_signature().begin(),
	    crypto_core::test_support::rsa_reference_pss_signature().end() - 1);
	auto short_result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &public_key, short_signature}, message.bytes());
	require(short_result.has_value());
	require(!short_result.value().is_valid());
}

void test_native_provider_decrypts_reference_rsa_oaep_vector()
{
	crypto_core::NativeProvider provider;
	auto private_key = crypto_core::test_support::rsa_reference_sign_key();
	const auto expected = crypto_core::test_support::bytes("native rsa oaep");

	auto decrypted = crypto_core::asymmetric_decrypt(
	    provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key},
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext());
	require(decrypted.has_value());
	require(decrypted.value() == expected);
}

void test_native_provider_rejects_tampered_reference_rsa_oaep_vector()
{
	crypto_core::NativeProvider provider;
	auto private_key = crypto_core::test_support::rsa_reference_sign_key();
	auto tampered = std::vector<std::uint8_t>(
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext().begin(),
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext().end());
	tampered[0] ^= 0x80U;

	auto decrypted = crypto_core::asymmetric_decrypt(
	    provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key},
	    tampered);
	require(!decrypted.has_value());
	require(decrypted.error().code() == crypto_core::ErrorCode::authentication_failed);

	const auto wrong_label = crypto_core::test_support::bytes("wrong label");
	auto wrong_label_params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, wrong_label.bytes());
	auto wrong_label_result = crypto_core::asymmetric_decrypt(
	    provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key, wrong_label_params},
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext());
	require(!wrong_label_result.has_value());
	require(wrong_label_result.error().code() == crypto_core::ErrorCode::authentication_failed);

	auto wrong_hash_result = crypto_core::asymmetric_decrypt(
	    provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key, crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha512)},
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext());
	require(!wrong_hash_result.has_value());
	require(wrong_hash_result.error().code() == crypto_core::ErrorCode::authentication_failed);

	auto short_ciphertext = std::vector<std::uint8_t>(
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext().begin(),
	    crypto_core::test_support::rsa_reference_oaep_sha256_ciphertext().end() - 1);
	auto short_result = crypto_core::asymmetric_decrypt(
	    provider,
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key},
	    short_ciphertext);
	require(!short_result.has_value());
	require(short_result.error().code() == crypto_core::ErrorCode::authentication_failed);
}

} // namespace

int main()
{
	test_native_provider_verifies_reference_rsa_pss_vector();
	test_native_provider_rejects_tampered_reference_rsa_pss_vector();
	test_native_provider_decrypts_reference_rsa_oaep_vector();
	test_native_provider_rejects_tampered_reference_rsa_oaep_vector();
	return 0;
}
