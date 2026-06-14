#include "crypto_core/crypto_core.hpp"

#include <cstdlib>
#include <type_traits>
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

void test_key_algorithm_metadata()
{
	require(crypto_core::key_algorithm_name(crypto_core::KeyAlgorithm::aes_128) == "AES-128");
	require(crypto_core::key_algorithm_name(crypto_core::KeyAlgorithm::aes_192) == "AES-192");
	require(crypto_core::key_algorithm_name(crypto_core::KeyAlgorithm::aes_256) == "AES-256");
	require(crypto_core::key_algorithm_name(crypto_core::KeyAlgorithm::hmac_sha256) == "HMAC-SHA256");
	require(crypto_core::key_algorithm_secret_size(crypto_core::KeyAlgorithm::aes_128) == 16);
	require(crypto_core::key_algorithm_secret_size(crypto_core::KeyAlgorithm::aes_192) == 24);
	require(crypto_core::key_algorithm_secret_size(crypto_core::KeyAlgorithm::aes_256) == 32);
	require(crypto_core::key_algorithm_secret_size(crypto_core::KeyAlgorithm::hmac_sha256) == 0);
}

void test_key_usage_metadata()
{
	const auto usages = crypto_core::KeyUsage::encrypt | crypto_core::KeyUsage::decrypt;
	require(crypto_core::has_key_usage(usages, crypto_core::KeyUsage::encrypt));
	require(crypto_core::has_key_usage(usages, crypto_core::KeyUsage::decrypt));
	require(!crypto_core::has_key_usage(usages, crypto_core::KeyUsage::mac));
}

void test_secret_key_is_move_only()
{
	static_assert(!std::is_copy_constructible_v<crypto_core::SecretKey>);
	static_assert(!std::is_copy_assignable_v<crypto_core::SecretKey>);
	static_assert(std::is_move_constructible_v<crypto_core::SecretKey>);
	static_assert(std::is_move_assignable_v<crypto_core::SecretKey>);
}

void test_secret_key_imports_raw_aes_key()
{
	std::vector<std::uint8_t> raw(16, 0x11U);
	auto key = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_128, raw, crypto_core::KeyUsage::encrypt | crypto_core::KeyUsage::decrypt);
	require(key.has_value());
	require(key.value().algorithm() == crypto_core::KeyAlgorithm::aes_128);
	require(key.value().size() == raw.size());
	require(key.value().allows(crypto_core::KeyUsage::encrypt));
	require(key.value().allows(crypto_core::KeyUsage::decrypt));
	require(!key.value().allows(crypto_core::KeyUsage::mac));
	require(key.value().bytes()[0] == 0x11U);
}

void test_secret_key_rejects_invalid_raw_key_sizes()
{
	std::vector<std::uint8_t> short_aes_key(15, 0x11U);
	auto invalid_aes = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_128, short_aes_key, crypto_core::KeyUsage::encrypt);
	require(!invalid_aes.has_value());
	require(invalid_aes.error().code() == crypto_core::ErrorCode::invalid_key);

	std::vector<std::uint8_t> empty_hmac_key;
	auto invalid_hmac = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::hmac_sha256, empty_hmac_key, crypto_core::KeyUsage::mac);
	require(!invalid_hmac.has_value());
	require(invalid_hmac.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_secret_key_exports_clone()
{
	std::vector<std::uint8_t> raw(32, 0x22U);
	auto key = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_256, raw, crypto_core::KeyUsage::encrypt);
	require(key.has_value());

	auto exported = key.value().export_raw();
	require(exported.has_value());
	require(exported.value().size() == raw.size());
	exported.value().bytes()[0] = 0x99U;
	require(key.value().bytes()[0] == 0x22U);
}

void test_secret_key_can_take_secure_buffer_ownership()
{
	std::vector<std::uint8_t> raw(24, 0x33U);
	auto buffer = crypto_core::SecureBuffer::copy_from(raw);
	require(buffer.has_value());

	auto key = crypto_core::SecretKey::from_buffer(crypto_core::KeyAlgorithm::aes_192, std::move(buffer.value()), crypto_core::KeyUsage::encrypt);
	require(key.has_value());
	require(key.value().size() == 24);
	require(key.value().bytes()[0] == 0x33U);
}

} // namespace

int main()
{
	test_key_algorithm_metadata();
	test_key_usage_metadata();
	test_secret_key_is_move_only();
	test_secret_key_imports_raw_aes_key();
	test_secret_key_rejects_invalid_raw_key_sizes();
	test_secret_key_exports_clone();
	test_secret_key_can_take_secure_buffer_ownership();
	return 0;
}
