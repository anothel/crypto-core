#include "crypto_core/crypto_core.hpp"
#include "crypto_core/internal/aes.hpp"

#include "test_vectors.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <openssl/evp.h>

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

void assert_same_digest(crypto_core::HashAlgorithm algorithm, std::string_view input)
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;

	auto native_digest = crypto_core::hash(native, algorithm, bytes(input).bytes());
	auto openssl_digest = crypto_core::hash(openssl, algorithm, bytes(input).bytes());

	require(native_digest.has_value());
	require(openssl_digest.has_value());
	require(native_digest.value() == openssl_digest.value());
}

void assert_same_mac(crypto_core::MacAlgorithm algorithm, std::string_view key, std::string_view input)
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;

	auto native_mac = crypto_core::mac(native, algorithm, bytes(key).bytes(), bytes(input).bytes());
	auto openssl_mac = crypto_core::mac(openssl, algorithm, bytes(key).bytes(), bytes(input).bytes());

	require(native_mac.has_value());
	require(openssl_mac.has_value());
	require(native_mac.value() == openssl_mac.value());
}

void assert_same_pbkdf2(crypto_core::KdfAlgorithm algorithm, std::uint32_t iterations, std::size_t output_size)
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;

	const auto password = bytes("password");
	const auto salt = bytes("salt");
	auto native_key = crypto_core::pbkdf2(native, algorithm, password.bytes(), salt.bytes(), iterations, output_size);
	auto openssl_key = crypto_core::pbkdf2(openssl, algorithm, password.bytes(), salt.bytes(), iterations, output_size);

	require(native_key.has_value());
	require(openssl_key.has_value());
	require(native_key.value() == openssl_key.value());
}

void assert_same_hkdf(crypto_core::KdfAlgorithm algorithm, std::size_t output_size)
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;

	const auto ikm = bytes("input key material");
	const auto salt = bytes("salt");
	const auto info = bytes("context info");
	auto native_key = crypto_core::hkdf(native, algorithm, ikm.bytes(), salt.bytes(), info.bytes(), output_size);
	auto openssl_key = crypto_core::hkdf(openssl, algorithm, ikm.bytes(), salt.bytes(), info.bytes(), output_size);

	require(native_key.has_value());
	require(openssl_key.has_value());
	require(native_key.value() == openssl_key.value());
}

const EVP_CIPHER *openssl_aes_ecb_cipher(std::size_t key_size)
{
	switch (key_size)
	{
	case 16:
		return EVP_aes_128_ecb();
	case 24:
		return EVP_aes_192_ecb();
	case 32:
		return EVP_aes_256_ecb();
	default:
		require(false);
		return nullptr;
	}
}

const EVP_CIPHER *openssl_aes_cbc_cipher(std::size_t key_size)
{
	switch (key_size)
	{
	case 16:
		return EVP_aes_128_cbc();
	case 24:
		return EVP_aes_192_cbc();
	case 32:
		return EVP_aes_256_cbc();
	default:
		require(false);
		return nullptr;
	}
}

crypto_core::ByteBuffer openssl_aes_ecb_crypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> input, bool encrypt)
{
	const auto *cipher = openssl_aes_ecb_cipher(key.size());
	auto *context = EVP_CIPHER_CTX_new();
	require(context != nullptr);

	const auto init_ok = encrypt ? EVP_EncryptInit_ex(context, cipher, nullptr, key.data(), nullptr) : EVP_DecryptInit_ex(context, cipher, nullptr, key.data(), nullptr);
	require(init_ok == 1);
	require(EVP_CIPHER_CTX_set_padding(context, 0) == 1);

	std::vector<std::uint8_t> output(input.size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(cipher)));
	int update_size = 0;
	const auto update_ok = encrypt ? EVP_EncryptUpdate(context, output.data(), &update_size, input.data(), static_cast<int>(input.size())) : EVP_DecryptUpdate(context, output.data(), &update_size, input.data(), static_cast<int>(input.size()));
	require(update_ok == 1);

	int final_size = 0;
	const auto final_ok = encrypt ? EVP_EncryptFinal_ex(context, output.data() + update_size, &final_size) : EVP_DecryptFinal_ex(context, output.data() + update_size, &final_size);
	require(final_ok == 1);

	EVP_CIPHER_CTX_free(context);
	output.resize(static_cast<std::size_t>(update_size + final_size));
	return crypto_core::ByteBuffer(std::move(output));
}

crypto_core::ByteBuffer openssl_aes_cbc_crypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv, std::span<const std::uint8_t> input, bool encrypt, bool padding)
{
	const auto *cipher = openssl_aes_cbc_cipher(key.size());
	auto *context = EVP_CIPHER_CTX_new();
	require(context != nullptr);

	const auto init_ok = encrypt ? EVP_EncryptInit_ex(context, cipher, nullptr, key.data(), iv.data()) : EVP_DecryptInit_ex(context, cipher, nullptr, key.data(), iv.data());
	require(init_ok == 1);
	require(EVP_CIPHER_CTX_set_padding(context, padding ? 1 : 0) == 1);

	std::vector<std::uint8_t> output(input.size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(cipher)));
	int update_size = 0;
	const auto update_ok = encrypt ? EVP_EncryptUpdate(context, output.data(), &update_size, input.data(), static_cast<int>(input.size())) : EVP_DecryptUpdate(context, output.data(), &update_size, input.data(), static_cast<int>(input.size()));
	require(update_ok == 1);

	int final_size = 0;
	const auto final_ok = encrypt ? EVP_EncryptFinal_ex(context, output.data() + update_size, &final_size) : EVP_DecryptFinal_ex(context, output.data() + update_size, &final_size);
	require(final_ok == 1);

	EVP_CIPHER_CTX_free(context);
	output.resize(static_cast<std::size_t>(update_size + final_size));
	return crypto_core::ByteBuffer(std::move(output));
}

void assert_same_aes_block(std::string_view key_hex, std::string_view plaintext_hex)
{
	auto key = crypto_core::test_support::decode_hex(key_hex);
	auto plaintext = crypto_core::test_support::decode_hex(plaintext_hex);
	require(key.has_value());
	require(plaintext.has_value());

	auto native = crypto_core::internal::AesBlockCipher::create(key.value());
	require(native.has_value());

	auto native_ciphertext = native.value().encrypt_block(plaintext.value());
	require(native_ciphertext.has_value());
	auto openssl_ciphertext = openssl_aes_ecb_crypt(key.value(), plaintext.value(), true);
	require(native_ciphertext.value() == openssl_ciphertext);

	auto native_plaintext = native.value().decrypt_block(openssl_ciphertext.bytes());
	require(native_plaintext.has_value());
	auto openssl_plaintext = openssl_aes_ecb_crypt(key.value(), openssl_ciphertext.bytes(), false);
	require(native_plaintext.value() == openssl_plaintext);
}

void assert_same_aes_cbc(crypto_core::CipherAlgorithm algorithm, std::string_view key_hex, std::string_view iv_hex, std::string_view plaintext_hex, crypto_core::CipherPadding padding)
{
	auto key = crypto_core::test_support::decode_hex(key_hex);
	auto iv = crypto_core::test_support::decode_hex(iv_hex);
	auto plaintext = crypto_core::test_support::decode_hex(plaintext_hex);
	require(key.has_value());
	require(iv.has_value());
	require(plaintext.has_value());

	crypto_core::NativeProvider native;
	const crypto_core::CipherParams encrypt_params{
	    algorithm,
	    crypto_core::CipherDirection::encrypt,
	    key.value(),
	    iv.value(),
	    padding,
	};
	auto native_ciphertext = crypto_core::cipher(native, encrypt_params, plaintext.value());
	require(native_ciphertext.has_value());

	const auto openssl_ciphertext = openssl_aes_cbc_crypt(key.value(), iv.value(), plaintext.value(), true, padding == crypto_core::CipherPadding::pkcs7);
	require(native_ciphertext.value() == openssl_ciphertext);

	const crypto_core::CipherParams decrypt_params{
	    algorithm,
	    crypto_core::CipherDirection::decrypt,
	    key.value(),
	    iv.value(),
	    padding,
	};
	auto native_plaintext = crypto_core::cipher(native, decrypt_params, openssl_ciphertext.bytes());
	require(native_plaintext.has_value());
	const auto openssl_plaintext = openssl_aes_cbc_crypt(key.value(), iv.value(), openssl_ciphertext.bytes(), false, padding == crypto_core::CipherPadding::pkcs7);
	require(native_plaintext.value() == openssl_plaintext);
}

void test_openssl_provider_metadata()
{
	crypto_core::OpenSSLProvider provider;
	require(provider.name() == std::string_view{"OpenSSLProvider"});
	require(provider.supports(crypto_core::HashAlgorithm::sha256));
	require(provider.supports(crypto_core::HashAlgorithm::sha512));
	require(provider.supports(crypto_core::MacAlgorithm::hmac_sha256));
	require(provider.supports(crypto_core::MacAlgorithm::hmac_sha512));
	require(provider.supports(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256));
	require(provider.supports(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512));
	require(provider.supports(crypto_core::KdfAlgorithm::hkdf_sha256));
	require(provider.supports(crypto_core::KdfAlgorithm::hkdf_sha512));
}

void test_openssl_matches_native_sha256()
{
	assert_same_digest(crypto_core::HashAlgorithm::sha256, "");
	assert_same_digest(crypto_core::HashAlgorithm::sha256, "abc");
	assert_same_digest(crypto_core::HashAlgorithm::sha256, "message digest");
}

void test_openssl_matches_native_sha512()
{
	assert_same_digest(crypto_core::HashAlgorithm::sha512, "");
	assert_same_digest(crypto_core::HashAlgorithm::sha512, "abc");
	assert_same_digest(crypto_core::HashAlgorithm::sha512, "message digest");
}

void test_openssl_streaming_matches_native()
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;

	auto native_context = native.create_hash(crypto_core::HashAlgorithm::sha256);
	auto openssl_context = openssl.create_hash(crypto_core::HashAlgorithm::sha256);
	require(native_context.has_value());
	require(openssl_context.has_value());

	require(native_context.value()->update(bytes("mes").bytes()).has_value());
	require(openssl_context.value()->update(bytes("mes").bytes()).has_value());
	require(native_context.value()->update(bytes("sage").bytes()).has_value());
	require(openssl_context.value()->update(bytes("sage").bytes()).has_value());

	auto native_digest = native_context.value()->final();
	auto openssl_digest = openssl_context.value()->final();
	require(native_digest.has_value());
	require(openssl_digest.has_value());
	require(native_digest.value() == openssl_digest.value());
}

void test_openssl_matches_native_hmac_sha256()
{
	assert_same_mac(crypto_core::MacAlgorithm::hmac_sha256, "Jefe", "what do ya want for nothing?");
	assert_same_mac(crypto_core::MacAlgorithm::hmac_sha256, "another key", "message digest");
}

void test_openssl_matches_native_hmac_sha512()
{
	assert_same_mac(crypto_core::MacAlgorithm::hmac_sha512, "Jefe", "what do ya want for nothing?");
	assert_same_mac(crypto_core::MacAlgorithm::hmac_sha512, "another key", "message digest");
}

void test_openssl_hmac_streaming_matches_native()
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;
	const auto key = bytes("Jefe");

	auto native_context = native.create_mac(crypto_core::MacAlgorithm::hmac_sha256, key.bytes());
	auto openssl_context = openssl.create_mac(crypto_core::MacAlgorithm::hmac_sha256, key.bytes());
	require(native_context.has_value());
	require(openssl_context.has_value());

	require(native_context.value()->update(bytes("what do ya ").bytes()).has_value());
	require(openssl_context.value()->update(bytes("what do ya ").bytes()).has_value());
	require(native_context.value()->update(bytes("want for nothing?").bytes()).has_value());
	require(openssl_context.value()->update(bytes("want for nothing?").bytes()).has_value());

	auto native_mac = native_context.value()->final();
	auto openssl_mac = openssl_context.value()->final();
	require(native_mac.has_value());
	require(openssl_mac.has_value());
	require(native_mac.value() == openssl_mac.value());
}

void test_openssl_matches_native_pbkdf2()
{
	assert_same_pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, 1, 32);
	assert_same_pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, 2, 32);
	assert_same_pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512, 1, 64);
	assert_same_pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512, 2, 64);
}

void test_openssl_matches_native_hkdf()
{
	assert_same_hkdf(crypto_core::KdfAlgorithm::hkdf_sha256, 42);
	assert_same_hkdf(crypto_core::KdfAlgorithm::hkdf_sha512, 42);
}

void test_openssl_matches_native_aes_block()
{
	assert_same_aes_block("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff");
	assert_same_aes_block("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff");
	assert_same_aes_block("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff");
}

void test_openssl_matches_native_aes_cbc()
{
	constexpr std::string_view iv = "000102030405060708090a0b0c0d0e0f";
	constexpr std::string_view plaintext =
	    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
	    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

	assert_same_aes_cbc(crypto_core::CipherAlgorithm::aes_128_cbc, "2b7e151628aed2a6abf7158809cf4f3c", iv, plaintext, crypto_core::CipherPadding::none);
	assert_same_aes_cbc(crypto_core::CipherAlgorithm::aes_192_cbc, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", iv, plaintext, crypto_core::CipherPadding::none);
	assert_same_aes_cbc(crypto_core::CipherAlgorithm::aes_256_cbc, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv, plaintext, crypto_core::CipherPadding::none);
	assert_same_aes_cbc(crypto_core::CipherAlgorithm::aes_128_cbc, "2b7e151628aed2a6abf7158809cf4f3c", iv, "68656c6c6f", crypto_core::CipherPadding::pkcs7);
}

} // namespace

int main()
{
	test_openssl_provider_metadata();
	test_openssl_matches_native_sha256();
	test_openssl_matches_native_sha512();
	test_openssl_streaming_matches_native();
	test_openssl_matches_native_hmac_sha256();
	test_openssl_matches_native_hmac_sha512();
	test_openssl_hmac_streaming_matches_native();
	test_openssl_matches_native_pbkdf2();
	test_openssl_matches_native_hkdf();
	test_openssl_matches_native_aes_block();
	test_openssl_matches_native_aes_cbc();
	return 0;
}

#else

int main()
{
	return 0;
}

#endif
