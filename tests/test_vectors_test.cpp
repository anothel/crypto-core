#include "test_vectors.hpp"

#include <cstdlib>
#include <string_view>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

void test_decode_hex_accepts_upper_and_lower_case()
{
	auto bytes = crypto_core::test_support::decode_hex("00aA10ff");
	require(bytes.has_value());
	require(bytes.value().size() == 4);
	require(bytes.value()[0] == 0x00U);
	require(bytes.value()[1] == 0xaaU);
	require(bytes.value()[2] == 0x10U);
	require(bytes.value()[3] == 0xffU);
}

void test_decode_hex_rejects_malformed_input()
{
	auto odd = crypto_core::test_support::decode_hex("abc");
	require(!odd.has_value());
	require(odd.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto bad_char = crypto_core::test_support::decode_hex("00xz");
	require(!bad_char.has_value());
	require(bad_char.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_parse_key_value_records()
{
	constexpr std::string_view input =
	    "[ENCRYPT]\n"
	    "KEY = 00010203\n"
	    "PLAINTEXT = 00112233\n"
	    "CIPHERTEXT = 69c4e0d8\n"
	    "\n"
	    "[DECRYPT]\n"
	    "KEY = 00010203\n"
	    "CIPHERTEXT = 69c4e0d8\n"
	    "PLAINTEXT = 00112233\n";

	auto records = crypto_core::test_support::parse_key_value_records(input);
	require(records.has_value());
	require(records.value().size() == 2);
	require(records.value()[0].label == "ENCRYPT");
	require(records.value()[0].field("KEY") == "00010203");
	require(records.value()[1].label == "DECRYPT");
	require(records.value()[1].field("PLAINTEXT") == "00112233");
}

void test_parse_key_value_records_rejects_duplicate_keys()
{
	constexpr std::string_view input =
	    "KEY = 0001\n"
	    "KEY = 0002\n";

	auto records = crypto_core::test_support::parse_key_value_records(input);
	require(!records.has_value());
	require(records.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_require_fields_rejects_missing_key()
{
	constexpr std::string_view input =
	    "KEY = 0001\n"
	    "PLAINTEXT = 0011\n";

	auto records = crypto_core::test_support::parse_key_value_records(input);
	require(records.has_value());

	auto result = crypto_core::test_support::require_fields(records.value()[0], {"KEY", "PLAINTEXT", "CIPHERTEXT"});
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_decode_hex_accepts_upper_and_lower_case();
	test_decode_hex_rejects_malformed_input();
	test_parse_key_value_records();
	test_parse_key_value_records_rejects_duplicate_keys();
	test_require_fields_rejects_missing_key();
	return 0;
}
