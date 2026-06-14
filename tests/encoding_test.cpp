#include "crypto_core/crypto_core.hpp"

#include <algorithm>
#include <cstdlib>
#include <span>
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

std::vector<std::uint8_t> bytes(std::string_view value)
{
	return std::vector<std::uint8_t>(value.begin(), value.end());
}

void require_buffer_eq(const crypto_core::ByteBuffer &actual, std::span<const std::uint8_t> expected)
{
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

void test_base64_known_answer_vectors()
{
	require(crypto_core::base64_encode({}) == "");
	require(crypto_core::base64_encode(bytes("f")) == "Zg==");
	require(crypto_core::base64_encode(bytes("fo")) == "Zm8=");
	require(crypto_core::base64_encode(bytes("foo")) == "Zm9v");
	require(crypto_core::base64_encode(bytes("foobar")) == "Zm9vYmFy");

	auto decoded = crypto_core::base64_decode("Zm9vYmFy");
	require(decoded.has_value());
	require_buffer_eq(decoded.value(), bytes("foobar"));
}

void test_base64_rejects_malformed_input()
{
	for (const auto input : {"Z", "Zg=", "Zg===", "Zm=9", "Zm9v\n", "Zm9v*", "===="})
	{
		auto decoded = crypto_core::base64_decode(input);
		require(!decoded.has_value());
		require(decoded.error().code() == crypto_core::ErrorCode::invalid_argument);
	}
}

void test_base64url_known_answer_vectors()
{
	const std::vector<std::uint8_t> value{0xfbU, 0xffU, 0xffU};
	require(crypto_core::base64url_encode(value) == "-___");
	require(crypto_core::base64url_encode(bytes("f")) == "Zg");
	require(crypto_core::base64url_encode(bytes("fo")) == "Zm8");

	auto decoded = crypto_core::base64url_decode("-___");
	require(decoded.has_value());
	require_buffer_eq(decoded.value(), value);

	auto padded = crypto_core::base64url_decode("Zg==");
	require(padded.has_value());
	require_buffer_eq(padded.value(), bytes("f"));
}

void test_base64url_rejects_standard_alphabet()
{
	auto decoded = crypto_core::base64url_decode("+///");
	require(!decoded.has_value());
	require(decoded.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_pem_encode_wraps_payload()
{
	auto encoded = crypto_core::pem_encode("TEST DATA", bytes("foobar"));
	require(encoded.has_value());
	require(encoded.value() ==
	        "-----BEGIN TEST DATA-----\n"
	        "Zm9vYmFy\n"
	        "-----END TEST DATA-----\n");
}

void test_pem_decode_round_trip()
{
	auto encoded = crypto_core::pem_encode("TEST DATA", bytes("foobar"));
	require(encoded.has_value());

	auto decoded = crypto_core::pem_decode(encoded.value());
	require(decoded.has_value());
	require(decoded.value().label == "TEST DATA");
	require_buffer_eq(decoded.value().payload, bytes("foobar"));
}

void test_pem_decode_rejects_malformed_armor()
{
	for (const auto input : {
	         "-----BEGIN TEST-----\nAAAA\n-----END OTHER-----\n",
	         "-----BEGIN TEST-----\n***\n-----END TEST-----\n",
	         "-----BEGIN TEST-----\nAAAA\n",
	         "-----BEGIN -----\nAAAA\n-----END -----\n",
	     })
	{
		auto decoded = crypto_core::pem_decode(input);
		require(!decoded.has_value());
		require(decoded.error().code() == crypto_core::ErrorCode::invalid_argument);
	}
}

void test_pem_encode_rejects_invalid_label()
{
	auto empty = crypto_core::pem_encode("", bytes("x"));
	require(!empty.has_value());
	require(empty.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto newline = crypto_core::pem_encode("BAD\nLABEL", bytes("x"));
	require(!newline.has_value());
	require(newline.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_base64_known_answer_vectors();
	test_base64_rejects_malformed_input();
	test_base64url_known_answer_vectors();
	test_base64url_rejects_standard_alphabet();
	test_pem_encode_wraps_payload();
	test_pem_decode_round_trip();
	test_pem_decode_rejects_malformed_armor();
	test_pem_encode_rejects_invalid_label();
	return 0;
}
