#include "crypto_core/asymmetric.hpp"
#include "crypto_core/internal/rsa_oaep.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
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

crypto_core::ByteBuffer bytes(std::string_view text)
{
	return crypto_core::ByteBuffer::copy_from(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(text.data()), text.size()));
}

constexpr std::array<std::uint8_t, 32> fixed_seed{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

void test_eme_oaep_encode_decode_round_trip()
{
	const auto params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	const auto message = bytes("oaep message");

	auto encoded = crypto_core::internal::eme_oaep_encode(128, message.bytes(), fixed_seed, params);
	require(encoded.has_value());
	require(encoded.value().size() == 128);
	require(encoded.value().bytes()[0] == 0);

	auto decoded = crypto_core::internal::eme_oaep_decode(encoded.value().bytes(), params);
	require(decoded.has_value());
	require(decoded.value() == message);
}

void test_eme_oaep_honors_label()
{
	const auto label = bytes("label");
	const auto wrong_label = bytes("wrong");
	const auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, label.bytes());
	const auto wrong_params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, wrong_label.bytes());
	const auto message = bytes("labeled message");

	auto encoded = crypto_core::internal::eme_oaep_encode(128, message.bytes(), fixed_seed, params);
	require(encoded.has_value());

	auto decoded = crypto_core::internal::eme_oaep_decode(encoded.value().bytes(), params);
	require(decoded.has_value());
	require(decoded.value() == message);

	auto wrong = crypto_core::internal::eme_oaep_decode(encoded.value().bytes(), wrong_params);
	require(!wrong.has_value());
	require(wrong.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_eme_oaep_rejects_tampered_encoding()
{
	const auto params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	const auto message = bytes("oaep tamper");

	auto encoded = crypto_core::internal::eme_oaep_encode(128, message.bytes(), fixed_seed, params);
	require(encoded.has_value());

	auto tampered = encoded.value();
	tampered.bytes()[48] ^= 0x01U;
	auto decoded = crypto_core::internal::eme_oaep_decode(tampered.bytes(), params);
	require(!decoded.has_value());
	require(decoded.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_eme_oaep_rejects_non_zero_leading_byte()
{
	const auto params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	const auto message = bytes("oaep leading byte");

	auto encoded = crypto_core::internal::eme_oaep_encode(128, message.bytes(), fixed_seed, params);
	require(encoded.has_value());

	auto tampered = encoded.value();
	tampered.bytes()[0] = 0x01U;
	auto decoded = crypto_core::internal::eme_oaep_decode(tampered.bytes(), params);
	require(!decoded.has_value());
	require(decoded.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_eme_oaep_rejects_too_large_message()
{
	const auto params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	std::vector<std::uint8_t> message(63, 0xA5U);

	auto encoded = crypto_core::internal::eme_oaep_encode(128, message, fixed_seed, params);
	require(!encoded.has_value());
	require(encoded.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_eme_oaep_rejects_parameter_misuse()
{
	const auto params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	std::array<std::uint8_t, 31> short_seed{};
	const auto message = bytes("oaep params");

	auto wrong_seed = crypto_core::internal::eme_oaep_encode(128, message.bytes(), short_seed, params);
	require(!wrong_seed.has_value());
	require(wrong_seed.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto unsupported_hash_params = crypto_core::RsaOaepParams::for_hash(static_cast<crypto_core::HashAlgorithm>(255));
	auto unsupported_hash = crypto_core::internal::eme_oaep_decode(std::array<std::uint8_t, 128>{}, unsupported_hash_params);
	require(!unsupported_hash.has_value());
	require(unsupported_hash.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto unsupported_mgf_params = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	unsupported_mgf_params.mgf1_hash = static_cast<crypto_core::HashAlgorithm>(255);
	auto unsupported_mgf = crypto_core::internal::eme_oaep_decode(std::array<std::uint8_t, 128>{}, unsupported_mgf_params);
	require(!unsupported_mgf.has_value());
	require(unsupported_mgf.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

} // namespace

int main()
{
	test_eme_oaep_encode_decode_round_trip();
	test_eme_oaep_honors_label();
	test_eme_oaep_rejects_tampered_encoding();
	test_eme_oaep_rejects_non_zero_leading_byte();
	test_eme_oaep_rejects_too_large_message();
	test_eme_oaep_rejects_parameter_misuse();
	return 0;
}
