#include "crypto_core/crypto_core.hpp"

#include "test_vectors.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <span>
#include <string_view>
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

std::vector<std::uint8_t> hex(std::string_view value)
{
	auto decoded = crypto_core::test_support::decode_hex(value);
	require(decoded.has_value());
	return std::move(decoded.value());
}

void require_buffer_eq(const crypto_core::ByteBuffer &actual, std::span<const std::uint8_t> expected)
{
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

crypto_core::AeadEncryptParams encrypt_params(
    crypto_core::AeadAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad = {},
    std::size_t tag_size = 16)
{
	return crypto_core::AeadEncryptParams{
	    algorithm,
	    key,
	    nonce,
	    aad,
	    tag_size,
	};
}

crypto_core::AeadDecryptParams decrypt_params(
    crypto_core::AeadAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> tag)
{
	return crypto_core::AeadDecryptParams{
	    algorithm,
	    key,
	    nonce,
	    aad,
	    tag,
	};
}

void test_aead_algorithm_metadata()
{
	require(std::string_view{crypto_core::aead_algorithm_name(crypto_core::AeadAlgorithm::aes_128_gcm)} == "AES-128-GCM");
	require(std::string_view{crypto_core::aead_algorithm_name(crypto_core::AeadAlgorithm::aes_192_gcm)} == "AES-192-GCM");
	require(std::string_view{crypto_core::aead_algorithm_name(crypto_core::AeadAlgorithm::aes_256_gcm)} == "AES-256-GCM");
}

void test_native_provider_supports_aes_gcm()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::AeadAlgorithm::aes_128_gcm));
	require(provider.supports(crypto_core::AeadAlgorithm::aes_192_gcm));
	require(provider.supports(crypto_core::AeadAlgorithm::aes_256_gcm));
}

void test_aes_128_gcm_known_answer_vectors()
{
	crypto_core::NativeProvider provider;
	auto key = hex("00000000000000000000000000000000");
	auto nonce = hex("000000000000000000000000");

	auto empty = crypto_core::aead_encrypt(provider, encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce), {});
	require(empty.has_value());
	require(empty.value().ciphertext.empty());
	require_buffer_eq(empty.value().tag, hex("58e2fccefa7e3061367f1d57a4e7455a"));

	auto plaintext = hex("00000000000000000000000000000000");
	auto encrypted = crypto_core::aead_encrypt(provider, encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce), plaintext);
	require(encrypted.has_value());
	require_buffer_eq(encrypted.value().ciphertext, hex("0388dace60b6a392f328c2b971b2fe78"));
	require_buffer_eq(encrypted.value().tag, hex("ab6e47d42cec13bdf53a67b21257bddf"));

	auto decrypted = crypto_core::aead_decrypt(provider, decrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, encrypted.value().tag.bytes()), encrypted.value().ciphertext.bytes());
	require(decrypted.has_value());
	require_buffer_eq(decrypted.value(), plaintext);
}

void test_aes_gcm_aad_round_trip_uses_default_provider()
{
	auto key = hex("feffe9928665731c6d6a8f9467308308");
	auto nonce = hex("cafebabefacedbaddecaf888");
	auto aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
	auto plaintext = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72");

	auto encrypted = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, aad), plaintext);
	require(encrypted.has_value());

	auto decrypted = crypto_core::aead_decrypt(decrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, aad, encrypted.value().tag.bytes()), encrypted.value().ciphertext.bytes());
	require(decrypted.has_value());
	require_buffer_eq(decrypted.value(), plaintext);
}

void test_aes_gcm_rejects_invalid_inputs()
{
	auto key = hex("00000000000000000000000000000000");
	auto nonce = hex("000000000000000000000000");
	std::vector<std::uint8_t> plaintext(16);

	std::vector<std::uint8_t> bad_key(15);
	auto invalid_key = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, bad_key, nonce), plaintext);
	require(!invalid_key.has_value());
	require(invalid_key.error().code() == crypto_core::ErrorCode::invalid_key);

	std::vector<std::uint8_t> bad_nonce;
	auto invalid_nonce = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, bad_nonce), plaintext);
	require(!invalid_nonce.has_value());
	require(invalid_nonce.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto invalid_tag_size = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, 3), plaintext);
	require(!invalid_tag_size.has_value());
	require(invalid_tag_size.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_aes_gcm_authentication_failure()
{
	auto key = hex("00000000000000000000000000000000");
	auto nonce = hex("000000000000000000000000");
	auto plaintext = hex("00000000000000000000000000000000");

	auto encrypted = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce), plaintext);
	require(encrypted.has_value());

	auto tag = std::vector<std::uint8_t>(encrypted.value().tag.bytes().begin(), encrypted.value().tag.bytes().end());
	tag[0] ^= 0x01U;

	auto decrypted = crypto_core::aead_decrypt(decrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, tag), encrypted.value().ciphertext.bytes());
	require(!decrypted.has_value());
	require(decrypted.error().code() == crypto_core::ErrorCode::authentication_failed);
}

} // namespace

int main()
{
	test_aead_algorithm_metadata();
	test_native_provider_supports_aes_gcm();
	test_aes_128_gcm_known_answer_vectors();
	test_aes_gcm_aad_round_trip_uses_default_provider();
	test_aes_gcm_rejects_invalid_inputs();
	test_aes_gcm_authentication_failure();
	return 0;
}
