#include "crypto_core/crypto_core.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
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

std::filesystem::path source_path(std::string_view relative)
{
	return std::filesystem::path{CRYPTO_CORE_SOURCE_DIR} / std::string{relative};
}

std::vector<std::uint8_t> read_bytes(std::string_view relative)
{
	std::ifstream input(source_path(relative), std::ios::binary);
	require(input.is_open());
	return std::vector<std::uint8_t>(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
}

std::string read_text(std::string_view relative)
{
	const auto bytes = read_bytes(relative);
	return std::string(bytes.begin(), bytes.end());
}

void test_invalid_encoding_corpus_rejects()
{
	require(!crypto_core::base64_decode(read_text("tests/corpus/invalid/base64_bad_padding.txt")).has_value());
	require(!crypto_core::base64url_decode(read_text("tests/corpus/invalid/base64url_standard_alphabet.txt")).has_value());
	require(!crypto_core::pem_decode(read_text("tests/corpus/invalid/pem_mismatched_label.pem")).has_value());
}

void test_invalid_key_import_corpus_rejects()
{
	const auto der = read_bytes("tests/corpus/invalid/der_truncated_sequence.der");
	require(!crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der, crypto_core::KeyUsage::verify).has_value());
	require(!crypto_core::PublicKey::import_rsa_pkcs1_der(der, crypto_core::KeyUsage::verify).has_value());

	auto private_der = crypto_core::SecureBuffer::copy_from(der);
	require(private_der.has_value());
	require(!crypto_core::PrivateKey::import_pkcs8_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(private_der.value()), crypto_core::KeyUsage::sign).has_value());

	auto sec1_der = crypto_core::SecureBuffer::copy_from(der);
	require(sec1_der.has_value());
	require(!crypto_core::PrivateKey::import_sec1_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, std::move(sec1_der.value()), crypto_core::KeyUsage::sign).has_value());
}

void test_aead_mutation_corpus_rejects()
{
	const std::vector<std::uint8_t> key(16, 0x11);
	const std::vector<std::uint8_t> nonce(12, 0x22);
	const auto tag = read_bytes("tests/corpus/invalid/aead_short_tag.bin");
	const auto ciphertext = read_bytes("tests/corpus/invalid/aead_tampered_ciphertext.bin");

	auto decrypted = crypto_core::aead_decrypt(
	    {crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, tag},
	    ciphertext);
	require(!decrypted.has_value());
	require(decrypted.error().code() == crypto_core::ErrorCode::invalid_argument ||
	        decrypted.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_fuzz_skeleton_is_tracked()
{
	require(std::filesystem::exists(source_path("tests/fuzz/fuzz_parser_boundaries.cpp")));
	require(std::filesystem::exists(source_path("docs/fuzzing.md")));
}

} // namespace

int main()
{
	test_invalid_encoding_corpus_rejects();
	test_invalid_key_import_corpus_rejects();
	test_aead_mutation_corpus_rejects();
	test_fuzz_skeleton_is_tracked();
	return 0;
}
