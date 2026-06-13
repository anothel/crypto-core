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

void test_parse_metadata_from_bracket_label()
{
	crypto_core::test_support::KeyValueRecord record;
	record.label = "AES-128-GCM Encrypt";

	auto metadata = crypto_core::test_support::parse_label_metadata(record);
	require(metadata.size() == 2);
	require(metadata[0] == "AES-128-GCM");
	require(metadata[1] == "Encrypt");
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

void test_required_field_returns_value_or_error()
{
	constexpr std::string_view input =
	    "KEY = 0001\n"
	    "PLAINTEXT = 0011\n";

	auto records = crypto_core::test_support::parse_key_value_records(input);
	require(records.has_value());

	auto key = crypto_core::test_support::required_field(records.value()[0], "KEY");
	require(key.has_value());
	require(key.value() == "0001");

	auto missing = crypto_core::test_support::required_field(records.value()[0], "CIPHERTEXT");
	require(!missing.has_value());
	require(missing.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_hex_field_decodes_required_field()
{
	constexpr std::string_view input =
	    "KEY = 0001aaFF\n"
	    "BAD = xyz\n";

	auto records = crypto_core::test_support::parse_key_value_records(input);
	require(records.has_value());

	auto key = crypto_core::test_support::hex_field(records.value()[0], "KEY");
	require(key.has_value());
	require(key.value().size() == 4);
	require(key.value()[0] == 0x00U);
	require(key.value()[1] == 0x01U);
	require(key.value()[2] == 0xaaU);
	require(key.value()[3] == 0xffU);

	auto bad = crypto_core::test_support::hex_field(records.value()[0], "BAD");
	require(!bad.has_value());
	require(bad.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_make_cbc_and_gcm_vectors_require_fields()
{
	constexpr std::string_view cbc_input =
	    "[AES-128-CBC]\n"
	    "KEY = 000102030405060708090a0b0c0d0e0f\n"
	    "IV = 000102030405060708090a0b0c0d0e0f\n"
	    "PLAINTEXT = 00112233445566778899aabbccddeeff\n"
	    "CIPHERTEXT = 69c4e0d86a7b0430d8cdb78070b4c55a\n";

	auto cbc_records = crypto_core::test_support::parse_key_value_records(cbc_input);
	require(cbc_records.has_value());
	auto cbc_vector = crypto_core::test_support::make_cbc_vector(cbc_records.value()[0]);
	require(cbc_vector.has_value());
	require(cbc_vector.value().label == "AES-128-CBC");
	require(cbc_vector.value().key.size() == 16);
	require(cbc_vector.value().iv.size() == 16);
	require(cbc_vector.value().plaintext.size() == 16);
	require(cbc_vector.value().ciphertext.size() == 16);

	constexpr std::string_view gcm_input =
	    "[AES-128-GCM]\n"
	    "KEY = 00000000000000000000000000000000\n"
	    "NONCE = 000000000000000000000000\n"
	    "AAD = \n"
	    "PLAINTEXT = \n"
	    "CIPHERTEXT = \n"
	    "TAG = 58e2fccefa7e3061367f1d57a4e7455a\n";

	auto gcm_records = crypto_core::test_support::parse_key_value_records(gcm_input);
	require(gcm_records.has_value());
	auto gcm_vector = crypto_core::test_support::make_gcm_vector(gcm_records.value()[0]);
	require(gcm_vector.has_value());
	require(gcm_vector.value().label == "AES-128-GCM");
	require(gcm_vector.value().key.size() == 16);
	require(gcm_vector.value().nonce.size() == 12);
	require(gcm_vector.value().aad.empty());
	require(gcm_vector.value().plaintext.empty());
	require(gcm_vector.value().ciphertext.empty());
	require(gcm_vector.value().tag.size() == 16);

	crypto_core::test_support::KeyValueRecord missing;
	missing.fields.emplace("KEY", "00");
	auto invalid = crypto_core::test_support::make_cbc_vector(missing);
	require(!invalid.has_value());
	require(invalid.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_make_digest_mac_and_kdf_vectors_require_fields()
{
	constexpr std::string_view digest_input =
	    "[SHA256]\n"
	    "MSG = 616263\n"
	    "MD = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";

	auto digest_records = crypto_core::test_support::parse_key_value_records(digest_input);
	require(digest_records.has_value());
	auto digest_vector = crypto_core::test_support::make_digest_vector(digest_records.value()[0]);
	require(digest_vector.has_value());
	require(digest_vector.value().label == "SHA256");
	require(digest_vector.value().message.size() == 3);
	require(digest_vector.value().digest.size() == 32);

	constexpr std::string_view mac_input =
	    "[HMAC-SHA256]\n"
	    "KEY = 4a656665\n"
	    "MSG = 7768617420646f2079612077616e7420666f72206e6f7468696e673f\n"
	    "MAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n";

	auto mac_records = crypto_core::test_support::parse_key_value_records(mac_input);
	require(mac_records.has_value());
	auto mac_vector = crypto_core::test_support::make_mac_vector(mac_records.value()[0]);
	require(mac_vector.has_value());
	require(mac_vector.value().label == "HMAC-SHA256");
	require(mac_vector.value().key.size() == 4);
	require(mac_vector.value().message.size() == 28);
	require(mac_vector.value().mac.size() == 32);

	constexpr std::string_view pbkdf2_input =
	    "[PBKDF2-HMAC-SHA256]\n"
	    "PASSWORD = 70617373776f7264\n"
	    "SALT = 73616c74\n"
	    "ITERATIONS = 2\n"
	    "DK = ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43\n";

	auto pbkdf2_records = crypto_core::test_support::parse_key_value_records(pbkdf2_input);
	require(pbkdf2_records.has_value());
	auto pbkdf2_vector = crypto_core::test_support::make_pbkdf2_vector(pbkdf2_records.value()[0]);
	require(pbkdf2_vector.has_value());
	require(pbkdf2_vector.value().iterations == 2);
	require(pbkdf2_vector.value().password.size() == 8);
	require(pbkdf2_vector.value().salt.size() == 4);
	require(pbkdf2_vector.value().derived_key.size() == 32);

	constexpr std::string_view hkdf_input =
	    "[HKDF-SHA256]\n"
	    "IKM = 0b0b\n"
	    "SALT = 0001\n"
	    "INFO = f0f1\n"
	    "OKM = 3cb25f\n";

	auto hkdf_records = crypto_core::test_support::parse_key_value_records(hkdf_input);
	require(hkdf_records.has_value());
	auto hkdf_vector = crypto_core::test_support::make_hkdf_vector(hkdf_records.value()[0]);
	require(hkdf_vector.has_value());
	require(hkdf_vector.value().ikm.size() == 2);
	require(hkdf_vector.value().salt.size() == 2);
	require(hkdf_vector.value().info.size() == 2);
	require(hkdf_vector.value().okm.size() == 3);

	constexpr std::string_view bad_iterations_input =
	    "PASSWORD = 00\n"
	    "SALT = 00\n"
	    "ITERATIONS = nope\n"
	    "DK = 00\n";

	auto bad_iterations_records = crypto_core::test_support::parse_key_value_records(bad_iterations_input);
	require(bad_iterations_records.has_value());
	auto bad_iterations = crypto_core::test_support::make_pbkdf2_vector(bad_iterations_records.value()[0]);
	require(!bad_iterations.has_value());
	require(bad_iterations.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_decode_hex_accepts_upper_and_lower_case();
	test_decode_hex_rejects_malformed_input();
	test_parse_key_value_records();
	test_parse_metadata_from_bracket_label();
	test_parse_key_value_records_rejects_duplicate_keys();
	test_require_fields_rejects_missing_key();
	test_required_field_returns_value_or_error();
	test_hex_field_decodes_required_field();
	test_make_cbc_and_gcm_vectors_require_fields();
	test_make_digest_mac_and_kdf_vectors_require_fields();
	return 0;
}
