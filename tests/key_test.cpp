#include "crypto_core/crypto_core.hpp"

#include <cstdlib>
#include <span>
#include <string_view>
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

void test_key_store_stores_and_requires_secret_keys_by_id()
{
	crypto_core::KeyStore store;
	std::vector<std::uint8_t> raw(32, 0x44U);
	auto key = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_256, raw, crypto_core::KeyUsage::encrypt | crypto_core::KeyUsage::decrypt);
	require(key.has_value());

	auto inserted = store.insert_secret("aes-main", std::move(key.value()));
	require(inserted.has_value());
	require(store.contains("aes-main"));

	auto found = store.find_secret("aes-main");
	require(found != nullptr);
	require(found->algorithm() == crypto_core::KeyAlgorithm::aes_256);
	require(found->allows(crypto_core::KeyUsage::encrypt));

	auto required = store.require_secret("aes-main", crypto_core::KeyUsage::decrypt);
	require(required.has_value());
	require(required.value()->size() == raw.size());

	auto wrong_usage = store.require_secret("aes-main", crypto_core::KeyUsage::mac);
	require(!wrong_usage.has_value());
	require(wrong_usage.error().code() == crypto_core::ErrorCode::invalid_key);

	auto missing = store.require_secret("missing", crypto_core::KeyUsage::encrypt);
	require(!missing.has_value());
	require(missing.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_key_store_rejects_duplicate_ids()
{
	crypto_core::KeyStore store;
	std::vector<std::uint8_t> raw(16, 0x55U);
	auto first_key = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_128, raw, crypto_core::KeyUsage::encrypt);
	auto second_key = crypto_core::SecretKey::import_raw(crypto_core::KeyAlgorithm::aes_128, raw, crypto_core::KeyUsage::encrypt);
	require(first_key.has_value());
	require(second_key.has_value());

	auto first = store.insert_secret("duplicate", std::move(first_key.value()));
	require(first.has_value());

	auto second = store.insert_secret("duplicate", std::move(second_key.value()));
	require(!second.has_value());
	require(second.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_key_store_stores_asymmetric_keys_by_id()
{
	crypto_core::KeyStore store;
	const std::uint8_t public_der_bytes[] = {
	    0x30, 0x1B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x0A, 0x00,
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	const std::uint8_t private_der_bytes[] = {
	    0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C, 0xA1, 0x02,
	    0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01, 0x3D, 0x02,
	    0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31, 0x02, 0x01,
	    0x26};
	const auto public_der = std::span<const std::uint8_t>(public_der_bytes, sizeof(public_der_bytes));
	const auto private_der = std::span<const std::uint8_t>(private_der_bytes, sizeof(private_der_bytes));

	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, public_der, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	auto private_buffer = crypto_core::SecureBuffer::copy_from(private_der);
	require(public_key.has_value());
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(private_buffer.value()), crypto_core::KeyUsage::sign | crypto_core::KeyUsage::decrypt);
	require(private_key.has_value());

	require(store.insert_public("rsa-public", public_key.value()).has_value());
	require(store.insert_private("rsa-private", std::move(private_key.value())).has_value());

	auto public_required = store.require_public("rsa-public", crypto_core::KeyUsage::verify);
	require(public_required.has_value());
	require(public_required.value()->algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);

	auto private_required = store.require_private("rsa-private", crypto_core::KeyUsage::decrypt);
	require(private_required.has_value());
	require(private_required.value()->algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);

	auto wrong_usage = store.require_private("rsa-private", crypto_core::KeyUsage::verify);
	require(!wrong_usage.has_value());
	require(wrong_usage.error().code() == crypto_core::ErrorCode::invalid_key);
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
	test_key_store_stores_and_requires_secret_keys_by_id();
	test_key_store_rejects_duplicate_ids();
	test_key_store_stores_asymmetric_keys_by_id();
	return 0;
}
