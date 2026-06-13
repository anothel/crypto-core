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

void require_buffer_eq(const crypto_core::ByteBuffer &actual, std::span<const std::uint8_t> expected)
{
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

crypto_core::CipherParams params(
    crypto_core::CipherAlgorithm algorithm,
    crypto_core::CipherDirection direction,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> iv,
    crypto_core::CipherPadding padding = crypto_core::CipherPadding::none)
{
	return crypto_core::CipherParams{
	    algorithm,
	    direction,
	    key,
	    iv,
	    padding,
	};
}

constexpr std::string_view cbc_vector_data =
    "[AES-128-CBC]\n"
    "KEY = 2b7e151628aed2a6abf7158809cf4f3c\n"
    "IV = 000102030405060708090a0b0c0d0e0f\n"
    "PLAINTEXT = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\n"
    "CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7\n"
    "\n"
    "[AES-192-CBC]\n"
    "KEY = 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b\n"
    "IV = 000102030405060708090a0b0c0d0e0f\n"
    "PLAINTEXT = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\n"
    "CIPHERTEXT = 4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
    "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd\n"
    "\n"
    "[AES-256-CBC]\n"
    "KEY = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\n"
    "IV = 000102030405060708090a0b0c0d0e0f\n"
    "PLAINTEXT = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\n"
    "CIPHERTEXT = f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b\n";

crypto_core::CipherAlgorithm cbc_algorithm(std::string_view label)
{
	if (label == "AES-128-CBC")
	{
		return crypto_core::CipherAlgorithm::aes_128_cbc;
	}
	if (label == "AES-192-CBC")
	{
		return crypto_core::CipherAlgorithm::aes_192_cbc;
	}
	require(label == "AES-256-CBC");
	return crypto_core::CipherAlgorithm::aes_256_cbc;
}

std::vector<crypto_core::test_support::CbcTestVector> load_cbc_vectors()
{
	auto records = crypto_core::test_support::parse_key_value_records(cbc_vector_data);
	require(records.has_value());

	std::vector<crypto_core::test_support::CbcTestVector> vectors;
	for (const auto &record : records.value())
	{
		auto vector = crypto_core::test_support::make_cbc_vector(record);
		require(vector.has_value());
		vectors.push_back(std::move(vector.value()));
	}
	return vectors;
}

void test_cipher_algorithm_metadata()
{
	require(std::string_view{crypto_core::cipher_algorithm_name(crypto_core::CipherAlgorithm::aes_128_cbc)} == "AES-128-CBC");
	require(std::string_view{crypto_core::cipher_algorithm_name(crypto_core::CipherAlgorithm::aes_192_cbc)} == "AES-192-CBC");
	require(std::string_view{crypto_core::cipher_algorithm_name(crypto_core::CipherAlgorithm::aes_256_cbc)} == "AES-256-CBC");
}

void test_native_provider_supports_aes_cbc()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::CipherAlgorithm::aes_128_cbc));
	require(provider.supports(crypto_core::CipherAlgorithm::aes_192_cbc));
	require(provider.supports(crypto_core::CipherAlgorithm::aes_256_cbc));
}

void test_aes_cbc_known_answer_vectors()
{
	crypto_core::NativeProvider provider;
	auto cbc_vectors = load_cbc_vectors();
	for (const auto &vector : cbc_vectors)
	{
		auto encrypted = crypto_core::cipher(provider, params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, vector.iv), vector.plaintext);
		require(encrypted.has_value());
		require_buffer_eq(encrypted.value(), vector.ciphertext);

		auto decrypted = crypto_core::cipher(provider, params(cbc_algorithm(vector.label), crypto_core::CipherDirection::decrypt, vector.key, vector.iv), encrypted.value().bytes());
		require(decrypted.has_value());
		require_buffer_eq(decrypted.value(), vector.plaintext);
	}
}

void test_aes_cbc_streaming_matches_one_shot()
{
	crypto_core::NativeProvider provider;
	auto cbc_vectors = load_cbc_vectors();
	const auto &vector = cbc_vectors[0];

	auto one_shot = crypto_core::cipher(provider, params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, vector.iv), vector.plaintext);
	require(one_shot.has_value());

	auto context = provider.create_cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, vector.iv));
	require(context.has_value());

	auto first = context.value()->update(std::span<const std::uint8_t>(vector.plaintext.data(), 17));
	require(first.has_value());
	auto second = context.value()->update(std::span<const std::uint8_t>(vector.plaintext.data() + 17, vector.plaintext.size() - 17));
	require(second.has_value());
	auto final = context.value()->final();
	require(final.has_value());

	std::vector<std::uint8_t> streamed;
	streamed.insert(streamed.end(), first.value().bytes().begin(), first.value().bytes().end());
	streamed.insert(streamed.end(), second.value().bytes().begin(), second.value().bytes().end());
	streamed.insert(streamed.end(), final.value().bytes().begin(), final.value().bytes().end());
	require(streamed == std::vector<std::uint8_t>(one_shot.value().bytes().begin(), one_shot.value().bytes().end()));
}

void test_aes_cbc_pkcs7_round_trip()
{
	auto cbc_vectors = load_cbc_vectors();
	const auto &vector = cbc_vectors[0];
	std::vector<std::uint8_t> plaintext{'h', 'e', 'l', 'l', 'o'};

	auto encrypted = crypto_core::cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, vector.iv, crypto_core::CipherPadding::pkcs7), plaintext);
	require(encrypted.has_value());
	require(encrypted.value().size() == 16);

	auto decrypted = crypto_core::cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::decrypt, vector.key, vector.iv, crypto_core::CipherPadding::pkcs7), encrypted.value().bytes());
	require(decrypted.has_value());
	require_buffer_eq(decrypted.value(), plaintext);
}

void test_aes_cbc_rejects_invalid_inputs()
{
	auto cbc_vectors = load_cbc_vectors();
	const auto &vector = cbc_vectors[0];

	std::vector<std::uint8_t> bad_key(15);
	auto invalid_key = crypto_core::cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, bad_key, vector.iv), vector.plaintext);
	require(!invalid_key.has_value());
	require(invalid_key.error().code() == crypto_core::ErrorCode::invalid_key);

	std::vector<std::uint8_t> bad_iv(15);
	auto invalid_iv = crypto_core::cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, bad_iv), vector.plaintext);
	require(!invalid_iv.has_value());
	require(invalid_iv.error().code() == crypto_core::ErrorCode::invalid_argument);

	std::vector<std::uint8_t> partial_block(17);
	auto invalid_plaintext = crypto_core::cipher(params(cbc_algorithm(vector.label), crypto_core::CipherDirection::encrypt, vector.key, vector.iv), partial_block);
	require(!invalid_plaintext.has_value());
	require(invalid_plaintext.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_cipher_algorithm_metadata();
	test_native_provider_supports_aes_cbc();
	test_aes_cbc_known_answer_vectors();
	test_aes_cbc_streaming_matches_one_shot();
	test_aes_cbc_pkcs7_round_trip();
	test_aes_cbc_rejects_invalid_inputs();
	return 0;
}
