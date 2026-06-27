#include "crypto_core/crypto_core.hpp"

#include "test_vectors.hpp"

#include <algorithm>
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

constexpr std::string_view gcm_vector_data =
    "[AES-128-GCM Empty]\n"
    "KEY = 00000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = \n"
    "CIPHERTEXT = \n"
    "TAG = 58e2fccefa7e3061367f1d57a4e7455a\n"
    "\n"
    "[AES-128-GCM OneBlock]\n"
    "KEY = 00000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = 00000000000000000000000000000000\n"
    "CIPHERTEXT = 0388dace60b6a392f328c2b971b2fe78\n"
    "TAG = ab6e47d42cec13bdf53a67b21257bddf\n"
    "\n"
    "[AES-192-GCM Empty]\n"
    "KEY = 000000000000000000000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = \n"
    "CIPHERTEXT = \n"
    "TAG = cd33b28ac773f74ba00ed1f312572435\n"
    "\n"
    "[AES-192-GCM OneBlock]\n"
    "KEY = 000000000000000000000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = 00000000000000000000000000000000\n"
    "CIPHERTEXT = 98e7247c07f0fe411c267e4384b0f600\n"
    "TAG = 2ff58d80033927ab8ef4d4587514f0fb\n"
    "\n"
    "[AES-256-GCM Empty]\n"
    "KEY = 0000000000000000000000000000000000000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = \n"
    "CIPHERTEXT = \n"
    "TAG = 530f8afbc74536b9a963b4f1c4cb738b\n"
    "\n"
    "[AES-256-GCM OneBlock]\n"
    "KEY = 0000000000000000000000000000000000000000000000000000000000000000\n"
    "NONCE = 000000000000000000000000\n"
    "AAD = \n"
    "PLAINTEXT = 00000000000000000000000000000000\n"
    "CIPHERTEXT = cea7403d4d606b6e074ec5d3baf39d18\n"
    "TAG = d0d1c8a799996bf0265b98b5d48ab919\n";

crypto_core::AeadAlgorithm gcm_algorithm(const crypto_core::test_support::GcmTestVector &vector)
{
	const auto metadata = crypto_core::test_support::parse_label_metadata(crypto_core::test_support::KeyValueRecord{vector.label, {}});
	require(!metadata.empty());
	if (metadata[0] == "AES-128-GCM")
	{
		return crypto_core::AeadAlgorithm::aes_128_gcm;
	}
	if (metadata[0] == "AES-192-GCM")
	{
		return crypto_core::AeadAlgorithm::aes_192_gcm;
	}
	require(metadata[0] == "AES-256-GCM");
	return crypto_core::AeadAlgorithm::aes_256_gcm;
}

std::vector<crypto_core::test_support::GcmTestVector> load_gcm_vectors()
{
	auto records = crypto_core::test_support::parse_key_value_records(gcm_vector_data);
	require(records.has_value());

	std::vector<crypto_core::test_support::GcmTestVector> vectors;
	for (const auto &record : records.value())
	{
		auto vector = crypto_core::test_support::make_gcm_vector(record);
		require(vector.has_value());
		vectors.push_back(std::move(vector.value()));
	}
	return vectors;
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

void test_aes_gcm_known_answer_vectors()
{
	crypto_core::NativeProvider provider;
	auto vectors = load_gcm_vectors();
	for (const auto &vector : vectors)
	{
		const auto algorithm = gcm_algorithm(vector);
		auto encrypted = crypto_core::aead_encrypt(provider, encrypt_params(algorithm, vector.key, vector.nonce, vector.aad), vector.plaintext);
		require(encrypted.has_value());
		require_buffer_eq(encrypted.value().ciphertext, vector.ciphertext);
		require_buffer_eq(encrypted.value().tag, vector.tag);

		auto decrypted = crypto_core::aead_decrypt(provider, decrypt_params(algorithm, vector.key, vector.nonce, vector.aad, vector.tag), vector.ciphertext);
		require(decrypted.has_value());
		require_buffer_eq(decrypted.value(), vector.plaintext);
	}
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

	auto too_large_tag_size = crypto_core::aead_encrypt(encrypt_params(crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, 17), plaintext);
	require(!too_large_tag_size.has_value());
	require(too_large_tag_size.error().code() == crypto_core::ErrorCode::invalid_argument);
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

void test_aes_gcm_rejects_wrong_inputs_and_tag_lengths()
{
	for (const auto &vector : load_gcm_vectors())
	{
		const auto algorithm = gcm_algorithm(vector);
		auto encrypted = crypto_core::aead_encrypt(encrypt_params(algorithm, vector.key, vector.nonce, vector.aad), vector.plaintext);
		require(encrypted.has_value());

		auto wrong_key = vector.key;
		wrong_key[0] ^= 0x01U;
		auto wrong_key_result = crypto_core::aead_decrypt(decrypt_params(algorithm, wrong_key, vector.nonce, vector.aad, encrypted.value().tag.bytes()), encrypted.value().ciphertext.bytes());
		require(!wrong_key_result.has_value());
		require(wrong_key_result.error().code() == crypto_core::ErrorCode::authentication_failed);

		auto wrong_nonce = vector.nonce;
		wrong_nonce[0] ^= 0x01U;
		auto wrong_nonce_result = crypto_core::aead_decrypt(decrypt_params(algorithm, vector.key, wrong_nonce, vector.aad, encrypted.value().tag.bytes()), encrypted.value().ciphertext.bytes());
		require(!wrong_nonce_result.has_value());
		require(wrong_nonce_result.error().code() == crypto_core::ErrorCode::authentication_failed);

		auto wrong_aad = vector.aad;
		wrong_aad.push_back(0x01U);
		auto wrong_aad_result = crypto_core::aead_decrypt(decrypt_params(algorithm, vector.key, vector.nonce, wrong_aad, encrypted.value().tag.bytes()), encrypted.value().ciphertext.bytes());
		require(!wrong_aad_result.has_value());
		require(wrong_aad_result.error().code() == crypto_core::ErrorCode::authentication_failed);

		if (!encrypted.value().ciphertext.empty())
		{
			auto tampered_ciphertext = std::vector<std::uint8_t>(encrypted.value().ciphertext.bytes().begin(), encrypted.value().ciphertext.bytes().end());
			tampered_ciphertext[0] ^= 0x01U;
			auto tampered_ciphertext_result = crypto_core::aead_decrypt(decrypt_params(algorithm, vector.key, vector.nonce, vector.aad, encrypted.value().tag.bytes()), tampered_ciphertext);
			require(!tampered_ciphertext_result.has_value());
			require(tampered_ciphertext_result.error().code() == crypto_core::ErrorCode::authentication_failed);
		}

		auto too_short_tag = std::vector<std::uint8_t>(11, 0);
		auto short_tag_result = crypto_core::aead_decrypt(decrypt_params(algorithm, vector.key, vector.nonce, vector.aad, too_short_tag), encrypted.value().ciphertext.bytes());
		require(!short_tag_result.has_value());
		require(short_tag_result.error().code() == crypto_core::ErrorCode::invalid_argument);

		auto too_long_tag = std::vector<std::uint8_t>(17, 0);
		auto long_tag_result = crypto_core::aead_decrypt(decrypt_params(algorithm, vector.key, vector.nonce, vector.aad, too_long_tag), encrypted.value().ciphertext.bytes());
		require(!long_tag_result.has_value());
		require(long_tag_result.error().code() == crypto_core::ErrorCode::invalid_argument);
	}
}

} // namespace

int main()
{
	test_aead_algorithm_metadata();
	test_native_provider_supports_aes_gcm();
	test_aes_gcm_known_answer_vectors();
	test_aes_gcm_aad_round_trip_uses_default_provider();
	test_aes_gcm_rejects_invalid_inputs();
	test_aes_gcm_authentication_failure();
	test_aes_gcm_rejects_wrong_inputs_and_tag_lengths();
	return 0;
}
