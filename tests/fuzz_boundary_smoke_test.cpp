#include "crypto_core/crypto_core.hpp"

#include "rsa_test_vectors.hpp"
#include "test_vectors.hpp"

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
	require(!crypto_core::base64_decode(read_text("tests/corpus/invalid/base64_invalid_character.txt")).has_value());
	require(!crypto_core::base64url_decode(read_text("tests/corpus/invalid/base64url_bad_padding.txt")).has_value());
	require(!crypto_core::base64url_decode(read_text("tests/corpus/invalid/base64url_standard_alphabet.txt")).has_value());
	require(!crypto_core::pem_decode(read_text("tests/corpus/invalid/pem_invalid_payload.pem")).has_value());
	require(!crypto_core::pem_decode(read_text("tests/corpus/invalid/pem_mismatched_label.pem")).has_value());
}

void test_invalid_key_import_corpus_rejects()
{
	const std::string_view corpus[] = {
	    "tests/corpus/invalid/der_declared_length_too_long.der",
	    "tests/corpus/invalid/der_short_length.der",
	    "tests/corpus/invalid/der_truncated_sequence.der",
	    "tests/corpus/invalid/der_wrong_tag.der",
	};

	for (const auto relative : corpus)
	{
		const auto der = read_bytes(relative);
		require(!crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der, crypto_core::KeyUsage::verify).has_value());
		require(!crypto_core::PublicKey::import_rsa_pkcs1_der(der, crypto_core::KeyUsage::verify).has_value());

		auto private_der = crypto_core::SecureBuffer::copy_from(der);
		require(private_der.has_value());
		require(!crypto_core::PrivateKey::import_pkcs8_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(private_der.value()), crypto_core::KeyUsage::sign).has_value());

		auto sec1_der = crypto_core::SecureBuffer::copy_from(der);
		require(sec1_der.has_value());
		require(!crypto_core::PrivateKey::import_sec1_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, std::move(sec1_der.value()), crypto_core::KeyUsage::sign).has_value());
	}
}

void test_aead_mutation_corpus_rejects()
{
	const std::vector<std::uint8_t> key(16, 0x11);
	const std::vector<std::uint8_t> nonce(12, 0x22);
	const std::string_view tag_corpus[] = {
	    "tests/corpus/invalid/aead_tiny_tag.bin",
	    "tests/corpus/invalid/aead_long_tag.bin",
	    "tests/corpus/invalid/aead_short_tag.bin",
	};
	const auto ciphertext = read_bytes("tests/corpus/invalid/aead_tampered_ciphertext.bin");
	for (const auto relative : tag_corpus)
	{
		const auto tag = read_bytes(relative);
		auto decrypted = crypto_core::aead_decrypt(
		    {crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, tag},
		    ciphertext);
		require(!decrypted.has_value());
		require(decrypted.error().code() == crypto_core::ErrorCode::invalid_argument ||
		        decrypted.error().code() == crypto_core::ErrorCode::authentication_failed);
	}

	const std::vector<std::uint8_t> tag(16, 0x33);
	const std::string_view ciphertext_corpus[] = {
	    "tests/corpus/invalid/aead_tiny_ciphertext.bin",
	    "tests/corpus/invalid/aead_tampered_ciphertext.bin",
	};
	for (const auto relative : ciphertext_corpus)
	{
		auto decrypted = crypto_core::aead_decrypt(
		    {crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, tag},
		    read_bytes(relative));
		require(!decrypted.has_value());
	}
}

void test_signature_and_oaep_corpus_rejects()
{
	crypto_core::NativeProvider provider;
	auto p256_public_der = crypto_core::test_support::decode_hex(
	    "3059301306072A8648CE3D020106082A8648CE3D03010703420004507A822E9DA764244CCE994EF0BB4ADEE4FD71B66585C56954BBAFC7BBD2FAA45424E4C9C7A95082E8AE73482CE33DAAB6C27530E728B3B8473A38D99704E480");
	require(p256_public_der.has_value());
	auto p256_public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, p256_public_der.value(), crypto_core::KeyUsage::verify);
	require(p256_public_key.has_value());
	const std::vector<std::uint8_t> message{'m', 's', 'g'};
	const std::string_view ecdsa_corpus[] = {
	    "tests/corpus/invalid/ecdsa_der_short_sequence.der",
	    "tests/corpus/invalid/ecdsa_der_truncated_signature.der",
	    "tests/corpus/invalid/ecdsa_der_wrong_tag.der",
	};
	for (const auto relative : ecdsa_corpus)
	{
		auto ecdsa = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &p256_public_key.value(), read_bytes(relative)}, message);
		require(!ecdsa.has_value() || !ecdsa.value().is_valid());
	}

	auto rsa_public_key = crypto_core::test_support::rsa_reference_verify_key();
	const auto rsa_message = crypto_core::test_support::bytes("rsa pss message");
	const std::string_view rsa_pss_corpus[] = {
	    "tests/corpus/invalid/rsa_pss_tiny_signature.bin",
	    "tests/corpus/invalid/rsa_pss_short_signature.bin",
	};
	for (const auto relative : rsa_pss_corpus)
	{
		auto rsa_pss = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &rsa_public_key, read_bytes(relative)}, rsa_message.bytes());
		require(!rsa_pss.has_value() || !rsa_pss.value().is_valid());
	}

	auto rsa_private_key = crypto_core::test_support::rsa_reference_sign_key();
	const std::string_view rsa_oaep_corpus[] = {
	    "tests/corpus/invalid/rsa_oaep_long_ciphertext.bin",
	    "tests/corpus/invalid/rsa_oaep_short_ciphertext.bin",
	    "tests/corpus/invalid/rsa_oaep_tiny_ciphertext.bin",
	};
	for (const auto relative : rsa_oaep_corpus)
	{
		auto rsa_oaep = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &rsa_private_key}, read_bytes(relative));
		require(!rsa_oaep.has_value());
	}
}

void test_fuzz_skeleton_is_tracked()
{
	require(std::filesystem::exists(source_path("tests/fuzz/fuzz_parser_boundaries.cpp")));
	require(std::filesystem::exists(source_path("docs/fuzzing.md")));
	const auto fuzzing = read_text("docs/fuzzing.md");
	require(fuzzing.find("base64_invalid_character.txt") != std::string::npos);
	require(fuzzing.find("base64url_bad_padding.txt") != std::string::npos);
	require(fuzzing.find("der_declared_length_too_long.der") != std::string::npos);
	require(fuzzing.find("der_short_length.der") != std::string::npos);
	require(fuzzing.find("der_wrong_tag.der") != std::string::npos);
	require(fuzzing.find("pem_invalid_payload.pem") != std::string::npos);
	require(fuzzing.find("aead_long_tag.bin") != std::string::npos);
	require(fuzzing.find("aead_tiny_ciphertext.bin") != std::string::npos);
	require(fuzzing.find("aead_tiny_tag.bin") != std::string::npos);
	require(fuzzing.find("ecdsa_der_short_sequence.der") != std::string::npos);
	require(fuzzing.find("ECDSA DER signature verify") != std::string::npos);
	require(fuzzing.find("ecdsa_der_wrong_tag.der") != std::string::npos);
	require(fuzzing.find("rsa_pss_tiny_signature.bin") != std::string::npos);
	require(fuzzing.find("RSA-PSS signature verify") != std::string::npos);
	require(fuzzing.find("RSA-OAEP decrypt") != std::string::npos);
	require(fuzzing.find("rsa_oaep_long_ciphertext.bin") != std::string::npos);
	require(fuzzing.find("rsa_oaep_tiny_ciphertext.bin") != std::string::npos);
}

} // namespace

int main()
{
	test_invalid_encoding_corpus_rejects();
	test_invalid_key_import_corpus_rejects();
	test_aead_mutation_corpus_rejects();
	test_signature_and_oaep_corpus_rejects();
	test_fuzz_skeleton_is_tracked();
	return 0;
}
