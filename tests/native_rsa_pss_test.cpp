#include "crypto_core/asymmetric.hpp"
#include "crypto_core/internal/rsa_pss.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

constexpr std::array<std::uint8_t, 32> sha256_abc{
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};

constexpr std::array<std::uint8_t, 128> pss_sha256_encoded_message{
    0x54, 0x61, 0xD1, 0x81, 0xCA, 0x04, 0xB8, 0x24, 0x59, 0x26, 0xD4, 0x5F, 0x0D, 0x34, 0x9A, 0x51,
    0x90, 0xE9, 0x0C, 0xB9, 0x55, 0xE6, 0xDF, 0x20, 0x01, 0x75, 0xF9, 0x1A, 0xBB, 0x96, 0x6D, 0x9D,
    0x6B, 0x4D, 0xE1, 0x59, 0xD0, 0x29, 0xDA, 0xD2, 0x06, 0xB0, 0x22, 0xB1, 0x50, 0xB8, 0xD0, 0x77,
    0x47, 0x2D, 0xAD, 0xF9, 0x95, 0x81, 0xD5, 0xC8, 0xF0, 0x84, 0xEC, 0x7B, 0xB4, 0x67, 0x79, 0x8E,
    0x0F, 0xCE, 0xC8, 0x6A, 0x28, 0x90, 0x81, 0xAC, 0x20, 0xBC, 0xC6, 0x07, 0xC2, 0x31, 0x57, 0x91,
    0x3D, 0xE3, 0xE7, 0x1D, 0xD0, 0x07, 0x7D, 0xF7, 0x58, 0xC8, 0x8A, 0xA7, 0xC5, 0x86, 0xD0, 0xF3,
    0xFA, 0xFA, 0x65, 0x80, 0xF3, 0x6A, 0xD9, 0x2F, 0x34, 0x06, 0x31, 0xF3, 0xA4, 0xD1, 0x8C, 0xC6,
    0x7A, 0xA3, 0x4A, 0xD6, 0x4F, 0x70, 0x60, 0x21, 0xD6, 0xF1, 0x63, 0x4D, 0x5B, 0x02, 0x0E, 0xBC};

void test_emsa_pss_verify_accepts_valid_encoding()
{
	const auto params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	auto result = crypto_core::internal::emsa_pss_verify(pss_sha256_encoded_message, 1023, sha256_abc, params);
	require(result.has_value());
	require(result.value());
}

void test_emsa_pss_verify_rejects_tampered_encoding()
{
	const auto params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	auto tampered_trailer = pss_sha256_encoded_message;
	tampered_trailer.back() = 0x00;
	auto trailer_result = crypto_core::internal::emsa_pss_verify(tampered_trailer, 1023, sha256_abc, params);
	require(trailer_result.has_value());
	require(!trailer_result.value());

	auto tampered_hash = pss_sha256_encoded_message;
	tampered_hash[96] ^= 0x01;
	auto hash_result = crypto_core::internal::emsa_pss_verify(tampered_hash, 1023, sha256_abc, params);
	require(hash_result.has_value());
	require(!hash_result.value());

	auto tampered_unused_bit = pss_sha256_encoded_message;
	tampered_unused_bit[0] |= 0x80U;
	auto unused_bit_result = crypto_core::internal::emsa_pss_verify(tampered_unused_bit, 1023, sha256_abc, params);
	require(unused_bit_result.has_value());
	require(!unused_bit_result.value());
}

void test_emsa_pss_verify_rejects_too_short_encoding()
{
	const auto params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	std::array<std::uint8_t, 16> short_encoding{};
	auto result = crypto_core::internal::emsa_pss_verify(short_encoding, 127, sha256_abc, params);
	require(result.has_value());
	require(!result.value());
}

void test_emsa_pss_verify_rejects_wrong_message_hash_size()
{
	const auto params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	std::array<std::uint8_t, 31> short_hash{};
	auto result = crypto_core::internal::emsa_pss_verify(pss_sha256_encoded_message, 1023, short_hash, params);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_emsa_pss_rejects_parameter_misuse()
{
	auto wrong_salt_params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	wrong_salt_params.salt_length = 31;
	auto wrong_salt = crypto_core::internal::emsa_pss_verify(pss_sha256_encoded_message, 1023, sha256_abc, wrong_salt_params);
	require(wrong_salt.has_value());
	require(!wrong_salt.value());

	const std::array<std::uint8_t, 31> short_salt{};
	auto wrong_salt_size = crypto_core::internal::emsa_pss_encode(1023, sha256_abc, short_salt, crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256));
	require(!wrong_salt_size.has_value());
	require(wrong_salt_size.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto unsupported_hash_params = crypto_core::RsaPssParams::for_hash(static_cast<crypto_core::HashAlgorithm>(255));
	auto unsupported_hash = crypto_core::internal::emsa_pss_verify(pss_sha256_encoded_message, 1023, sha256_abc, unsupported_hash_params);
	require(!unsupported_hash.has_value());
	require(unsupported_hash.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto unsupported_mgf_params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	unsupported_mgf_params.mgf1_hash = static_cast<crypto_core::HashAlgorithm>(255);
	auto unsupported_mgf = crypto_core::internal::emsa_pss_verify(pss_sha256_encoded_message, 1023, sha256_abc, unsupported_mgf_params);
	require(!unsupported_mgf.has_value());
	require(unsupported_mgf.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

void test_emsa_pss_encode_matches_known_encoding()
{
	const auto params = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	constexpr std::array<std::uint8_t, 32> salt{
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	auto encoded = crypto_core::internal::emsa_pss_encode(1023, sha256_abc, salt, params);
	require(encoded.has_value());
	require(encoded.value().size() == pss_sha256_encoded_message.size());
	for (std::size_t i = 0; i < pss_sha256_encoded_message.size(); ++i)
	{
		require(encoded.value().bytes()[i] == pss_sha256_encoded_message[i]);
	}
}

} // namespace

int main()
{
	test_emsa_pss_verify_accepts_valid_encoding();
	test_emsa_pss_verify_rejects_tampered_encoding();
	test_emsa_pss_verify_rejects_too_short_encoding();
	test_emsa_pss_verify_rejects_wrong_message_hash_size();
	test_emsa_pss_rejects_parameter_misuse();
	test_emsa_pss_encode_matches_known_encoding();
	return 0;
}
