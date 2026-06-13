#include "crypto_core/internal/aes.hpp"

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

void require_buffer_eq(const crypto_core::ByteBuffer &actual, std::span<const std::uint8_t> expected)
{
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

constexpr std::string_view aes_block_vectors =
    "[AES-128]\n"
    "KEY = 000102030405060708090a0b0c0d0e0f\n"
    "PLAINTEXT = 00112233445566778899aabbccddeeff\n"
    "CIPHERTEXT = 69c4e0d86a7b0430d8cdb78070b4c55a\n"
    "\n"
    "[AES-192]\n"
    "KEY = 000102030405060708090a0b0c0d0e0f1011121314151617\n"
    "PLAINTEXT = 00112233445566778899aabbccddeeff\n"
    "CIPHERTEXT = dda97ca4864cdfe06eaf70a0ec0d7191\n"
    "\n"
    "[AES-256]\n"
    "KEY = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
    "PLAINTEXT = 00112233445566778899aabbccddeeff\n"
    "CIPHERTEXT = 8ea2b7ca516745bfeafc49904b496089\n";

void test_aes_block_known_answer_vectors()
{
	auto records = crypto_core::test_support::parse_key_value_records(aes_block_vectors);
	require(records.has_value());

	for (const auto &record : records.value())
	{
		require(crypto_core::test_support::require_fields(record, {"KEY", "PLAINTEXT", "CIPHERTEXT"}).has_value());

		auto key = crypto_core::test_support::decode_hex(record.field("KEY"));
		auto plaintext = crypto_core::test_support::decode_hex(record.field("PLAINTEXT"));
		auto ciphertext = crypto_core::test_support::decode_hex(record.field("CIPHERTEXT"));
		require(key.has_value());
		require(plaintext.has_value());
		require(ciphertext.has_value());

		auto cipher = crypto_core::internal::AesBlockCipher::create(key.value());
		require(cipher.has_value());

		auto encrypted = cipher.value().encrypt_block(plaintext.value());
		require(encrypted.has_value());
		require_buffer_eq(encrypted.value(), ciphertext.value());

		auto decrypted = cipher.value().decrypt_block(ciphertext.value());
		require(decrypted.has_value());
		require_buffer_eq(decrypted.value(), plaintext.value());
	}
}

void test_aes_rejects_invalid_key_sizes()
{
	for (auto size : {15U, 17U, 31U, 33U})
	{
		std::vector<std::uint8_t> key(size);
		auto cipher = crypto_core::internal::AesBlockCipher::create(key);
		require(!cipher.has_value());
		require(cipher.error().code() == crypto_core::ErrorCode::invalid_key);
	}
}

void test_aes_rejects_invalid_block_sizes()
{
	std::vector<std::uint8_t> key(16);
	auto cipher = crypto_core::internal::AesBlockCipher::create(key);
	require(cipher.has_value());

	std::vector<std::uint8_t> short_block(15);
	auto encrypted = cipher.value().encrypt_block(short_block);
	require(!encrypted.has_value());
	require(encrypted.error().code() == crypto_core::ErrorCode::invalid_argument);

	std::vector<std::uint8_t> long_block(17);
	auto decrypted = cipher.value().decrypt_block(long_block);
	require(!decrypted.has_value());
	require(decrypted.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_aes_block_known_answer_vectors();
	test_aes_rejects_invalid_key_sizes();
	test_aes_rejects_invalid_block_sizes();
	return 0;
}
