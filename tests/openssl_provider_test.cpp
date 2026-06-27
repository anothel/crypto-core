#include "crypto_core/crypto_core.hpp"
#include "crypto_core/internal/aes.hpp"

#include "test_vectors.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace
{

void require_check(bool condition, const char *file, int line)
{
	if (!condition)
	{
		std::fprintf(stderr, "openssl_provider_test failed: %s:%d\n", file, line);
		std::exit(1);
	}
}

#define require(condition) require_check((condition), __FILE__, __LINE__)

crypto_core::ByteBuffer bytes(std::string_view text)
{
	return crypto_core::ByteBuffer::copy_from(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(text.data()), text.size()));
}

bool bytes_equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right)
{
	return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
}

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

struct RsaDerKeyPair
{
	crypto_core::ByteBuffer public_key;
	crypto_core::SecureBuffer private_key;
};

std::vector<std::uint8_t> hex_bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

crypto_core::PublicKey import_ed25519_verify_key(std::string_view public_key_hex)
{
	auto raw_public_key = hex_bytes(public_key_hex);
	auto public_key = crypto_core::PublicKey::import_raw_ed25519(raw_public_key, crypto_core::KeyUsage::verify);
	require(public_key.has_value());
	return std::move(public_key.value());
}

crypto_core::PrivateKey import_ed25519_signing_seed(std::string_view seed_hex)
{
	auto raw_seed = hex_bytes(seed_hex);
	auto seed = crypto_core::SecureBuffer::copy_from(raw_seed);
	require(seed.has_value());

	auto private_key = crypto_core::PrivateKey::import_raw_ed25519_seed(std::move(seed.value()), crypto_core::KeyUsage::sign);
	require(private_key.has_value());
	return std::move(private_key.value());
}

crypto_core::ByteBuffer export_public_key_der(EVP_PKEY *key)
{
	const int size = i2d_PUBKEY(key, nullptr);
	require(size > 0);

	std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
	auto *out = der.data();
	require(i2d_PUBKEY(key, &out) == size);
	return crypto_core::ByteBuffer(std::move(der));
}

crypto_core::SecureBuffer export_private_key_der(EVP_PKEY *key)
{
	const int size = i2d_PrivateKey(key, nullptr);
	require(size > 0);

	std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
	auto *out = der.data();
	require(i2d_PrivateKey(key, &out) == size);
	return crypto_core::SecureBuffer(std::move(der));
}

RsaDerKeyPair generate_rsa_der_key_pair()
{
	EvpPkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
	require(context != nullptr);
	require(EVP_PKEY_keygen_init(context.get()) == 1);
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1);

	EVP_PKEY *raw_key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &raw_key) == 1);
	EvpPkeyPtr key(raw_key, EVP_PKEY_free);
	return RsaDerKeyPair{export_public_key_der(key.get()), export_private_key_der(key.get())};
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

const EVP_CIPHER *openssl_aes_gcm_cipher(std::size_t key_size)
{
	switch (key_size)
	{
	case 16:
		return EVP_aes_128_gcm();
	case 24:
		return EVP_aes_192_gcm();
	case 32:
		return EVP_aes_256_gcm();
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

crypto_core::AeadEncryptResult openssl_aes_gcm_encrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext,
    std::size_t tag_size)
{
	const auto *cipher = openssl_aes_gcm_cipher(key.size());
	auto *context = EVP_CIPHER_CTX_new();
	require(context != nullptr);
	require(EVP_EncryptInit_ex(context, cipher, nullptr, nullptr, nullptr) == 1);
	require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1);
	require(EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1);

	int out_size = 0;
	if (!aad.empty())
	{
		require(EVP_EncryptUpdate(context, nullptr, &out_size, aad.data(), static_cast<int>(aad.size())) == 1);
	}

	std::vector<std::uint8_t> ciphertext(plaintext.size());
	if (!plaintext.empty())
	{
		require(EVP_EncryptUpdate(context, ciphertext.data(), &out_size, plaintext.data(), static_cast<int>(plaintext.size())) == 1);
		ciphertext.resize(static_cast<std::size_t>(out_size));
	}

	std::array<std::uint8_t, 16> final_block{};
	int final_size = 0;
	require(EVP_EncryptFinal_ex(context, final_block.data(), &final_size) == 1);
	ciphertext.insert(ciphertext.end(), final_block.begin(), final_block.begin() + final_size);

	std::vector<std::uint8_t> tag(tag_size);
	require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1);
	EVP_CIPHER_CTX_free(context);
	return crypto_core::AeadEncryptResult{crypto_core::ByteBuffer(std::move(ciphertext)), crypto_core::ByteBuffer(std::move(tag))};
}

bool openssl_aes_gcm_decrypt_accepts(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag)
{
	const auto *cipher = openssl_aes_gcm_cipher(key.size());
	auto *context = EVP_CIPHER_CTX_new();
	require(context != nullptr);
	require(EVP_DecryptInit_ex(context, cipher, nullptr, nullptr, nullptr) == 1);
	require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1);
	require(EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1);

	int out_size = 0;
	if (!aad.empty())
	{
		require(EVP_DecryptUpdate(context, nullptr, &out_size, aad.data(), static_cast<int>(aad.size())) == 1);
	}
	std::vector<std::uint8_t> plaintext(ciphertext.size());
	if (!ciphertext.empty())
	{
		require(EVP_DecryptUpdate(context, plaintext.data(), &out_size, ciphertext.data(), static_cast<int>(ciphertext.size())) == 1);
	}
	require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<std::uint8_t *>(tag.data())) == 1);

	std::array<std::uint8_t, 16> final_block{};
	int final_size = 0;
	const auto ok = EVP_DecryptFinal_ex(context, final_block.data(), &final_size) == 1;
	EVP_CIPHER_CTX_free(context);
	return ok;
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

void assert_same_aes_gcm(crypto_core::AeadAlgorithm algorithm, std::string_view key_hex, std::string_view nonce_hex, std::string_view aad_hex, std::string_view plaintext_hex)
{
	auto key = crypto_core::test_support::decode_hex(key_hex);
	auto nonce = crypto_core::test_support::decode_hex(nonce_hex);
	auto aad = crypto_core::test_support::decode_hex(aad_hex);
	auto plaintext = crypto_core::test_support::decode_hex(plaintext_hex);
	require(key.has_value());
	require(nonce.has_value());
	require(aad.has_value());
	require(plaintext.has_value());

	crypto_core::NativeProvider native;
	const crypto_core::AeadEncryptParams encrypt_params{
	    algorithm,
	    key.value(),
	    nonce.value(),
	    aad.value(),
	    16,
	};
	auto native_encrypted = crypto_core::aead_encrypt(native, encrypt_params, plaintext.value());
	require(native_encrypted.has_value());

	auto openssl_encrypted = openssl_aes_gcm_encrypt(key.value(), nonce.value(), aad.value(), plaintext.value(), 16);
	require(native_encrypted.value().ciphertext == openssl_encrypted.ciphertext);
	require(native_encrypted.value().tag == openssl_encrypted.tag);

	const crypto_core::AeadDecryptParams decrypt_params{
	    algorithm,
	    key.value(),
	    nonce.value(),
	    aad.value(),
	    native_encrypted.value().tag.bytes(),
	};
	auto native_plaintext = crypto_core::aead_decrypt(native, decrypt_params, native_encrypted.value().ciphertext.bytes());
	require(native_plaintext.has_value());
	require(native_plaintext.value() == crypto_core::ByteBuffer::copy_from(plaintext.value()));

	auto bad_tag = std::vector<std::uint8_t>(native_encrypted.value().tag.bytes().begin(), native_encrypted.value().tag.bytes().end());
	bad_tag[0] ^= 0x80U;
	require(!openssl_aes_gcm_decrypt_accepts(key.value(), nonce.value(), aad.value(), native_encrypted.value().ciphertext.bytes(), bad_tag));
	const crypto_core::AeadDecryptParams bad_decrypt_params{
	    algorithm,
	    key.value(),
	    nonce.value(),
	    aad.value(),
	    bad_tag,
	};
	auto native_bad_decrypt = crypto_core::aead_decrypt(native, bad_decrypt_params, native_encrypted.value().ciphertext.bytes());
	require(!native_bad_decrypt.has_value());
	require(native_bad_decrypt.error().code() == crypto_core::ErrorCode::authentication_failed);
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
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss));
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss_sha256));
	require(provider.supports(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
	require(provider.supports(crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::sign, crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::verify, crypto_core::SignatureAlgorithm::ed25519));
	require(!provider.supports(crypto_core::CryptoOperation::keygen, crypto_core::AsymmetricKeyAlgorithm::ed25519));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256));
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

void test_openssl_matches_native_aes_gcm()
{
	constexpr std::string_view nonce = "cafebabefacedbaddecaf888";
	constexpr std::string_view aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
	constexpr std::string_view plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72";

	assert_same_aes_gcm(crypto_core::AeadAlgorithm::aes_128_gcm, "feffe9928665731c6d6a8f9467308308", nonce, aad, plaintext);
	assert_same_aes_gcm(crypto_core::AeadAlgorithm::aes_192_gcm, "000102030405060708090a0b0c0d0e0f1011121314151617", nonce, aad, plaintext);
	assert_same_aes_gcm(crypto_core::AeadAlgorithm::aes_256_gcm, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", nonce, aad, plaintext);
}

void test_openssl_rsa_pss_sign_verify_round_trip()
{
	crypto_core::OpenSSLProvider provider;
	auto der = generate_rsa_der_key_pair();

	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(der.private_key), crypto_core::KeyUsage::sign);
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der.public_key.bytes(), crypto_core::KeyUsage::verify);
	require(private_key.has_value());
	require(public_key.has_value());

	const auto message = bytes("rsa pss message");
	const auto pss = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key.value(), pss}, message.bytes());
	require(signature.has_value());
	require(!signature.value().empty());

	auto valid = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key.value(), signature.value().bytes(), pss}, message.bytes());
	require(valid.has_value());
	require(valid.value().is_valid());
}

void test_openssl_generates_usable_rsa_key_pair()
{
	crypto_core::OpenSSLProvider provider;

	auto key_pair = crypto_core::generate_key_pair(provider, {crypto_core::AsymmetricKeyAlgorithm::rsa});
	require(key_pair.has_value());
	require(key_pair.value().public_key.algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(key_pair.value().private_key.algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(key_pair.value().public_key.allows(crypto_core::KeyUsage::verify));
	require(key_pair.value().public_key.allows(crypto_core::KeyUsage::encrypt));
	require(key_pair.value().private_key.allows(crypto_core::KeyUsage::sign));
	require(key_pair.value().private_key.allows(crypto_core::KeyUsage::decrypt));

	const auto message = bytes("generated rsa key pair");
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &key_pair.value().private_key}, message.bytes());
	require(signature.has_value());

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &key_pair.value().public_key, signature.value().bytes()}, message.bytes());
	require(verified.has_value());
	require(verified.value().is_valid());

	const auto plaintext = bytes("generated rsa oaep");
	auto ciphertext = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &key_pair.value().public_key}, plaintext.bytes());
	require(ciphertext.has_value());

	auto decrypted = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &key_pair.value().private_key}, ciphertext.value().bytes());
	require(decrypted.has_value());
	require(decrypted.value() == plaintext);
}

void test_openssl_generates_usable_ecdsa_p256_key_pair()
{
	crypto_core::OpenSSLProvider provider;
	crypto_core::GenerateKeyPairParams params{crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256};
	params.ec.public_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::verify);
	params.ec.private_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::sign);

	auto key_pair = crypto_core::generate_key_pair(provider, params);
	require(key_pair.has_value());
	require(key_pair.value().public_key.algorithm() == crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256);
	require(key_pair.value().private_key.algorithm() == crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256);
	require(key_pair.value().public_key.allows(crypto_core::KeyUsage::verify));
	require(!key_pair.value().public_key.allows(crypto_core::KeyUsage::encrypt));
	require(key_pair.value().private_key.allows(crypto_core::KeyUsage::sign));
	require(!key_pair.value().private_key.allows(crypto_core::KeyUsage::decrypt));

	const auto message = bytes("generated ecdsa p256 key pair");
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().private_key}, message.bytes());
	require(signature.has_value());
	require(!signature.value().empty());

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, signature.value().bytes()}, message.bytes());
	require(verified.has_value());
	require(verified.value().is_valid());
}

void test_native_verifies_openssl_ecdsa_p256_signature()
{
	crypto_core::OpenSSLProvider openssl;
	crypto_core::NativeProvider native;
	crypto_core::GenerateKeyPairParams params{crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256};
	params.ec.public_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::verify);
	params.ec.private_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::sign);

	auto key_pair = crypto_core::generate_key_pair(openssl, params);
	require(key_pair.has_value());

	const auto message = bytes("openssl to native ecdsa p256");
	auto signature = crypto_core::sign(openssl, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().private_key}, message.bytes());
	require(signature.has_value());

	auto verified = crypto_core::verify(native, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, signature.value().bytes()}, message.bytes());
	require(verified.has_value());
	require(verified.value().is_valid());

	const auto tampered = bytes("openssl to native ecdsa tampered");
	auto invalid = crypto_core::verify(native, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, signature.value().bytes()}, tampered.bytes());
	require(invalid.has_value());
	require(!invalid.value().is_valid());
}

void test_openssl_verifies_native_ecdsa_p256_signature()
{
	crypto_core::OpenSSLProvider openssl;
	crypto_core::NativeProvider native;
	crypto_core::GenerateKeyPairParams params{crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256};
	params.ec.public_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::verify);
	params.ec.private_usages = crypto_core::key_usage_value(crypto_core::KeyUsage::sign);

	auto key_pair = crypto_core::generate_key_pair(openssl, params);
	require(key_pair.has_value());

	const auto message = bytes("native to openssl ecdsa p256");
	auto signature = crypto_core::sign(native, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().private_key}, message.bytes());
	require(signature.has_value());

	auto verified = crypto_core::verify(openssl, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, signature.value().bytes()}, message.bytes());
	require(verified.has_value());
	require(verified.value().is_valid());
}

void test_openssl_ecdsa_p256_verify_returns_invalid_for_bad_inputs()
{
	crypto_core::OpenSSLProvider provider;
	auto key_pair = crypto_core::generate_key_pair(provider, {crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256});
	require(key_pair.has_value());

	const auto message = bytes("ecdsa p256 message");
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().private_key}, message.bytes());
	require(signature.has_value());

	const auto tampered_message = bytes("ecdsa p256 tampered");
	auto bad_message = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, signature.value().bytes()}, tampered_message.bytes());
	require(bad_message.has_value());
	require(!bad_message.value().is_valid());

	auto tampered_signature = signature.value();
	tampered_signature.bytes()[tampered_signature.size() - 1] ^= 0x01U;
	auto bad_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, tampered_signature.bytes()}, message.bytes());
	require(bad_signature.has_value());
	require(!bad_signature.value().is_valid());

	const std::array<std::uint8_t, 0> empty_signature{};
	auto empty = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key_pair.value().public_key, empty_signature}, message.bytes());
	require(empty.has_value());
	require(!empty.value().is_valid());
}

void test_openssl_ecdsa_p256_rejects_rsa_keys()
{
	crypto_core::OpenSSLProvider provider;
	auto rsa_key_pair = crypto_core::generate_key_pair(provider, {crypto_core::AsymmetricKeyAlgorithm::rsa});
	require(rsa_key_pair.has_value());

	const auto message = bytes("wrong key family");
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &rsa_key_pair.value().private_key}, message.bytes());
	require(!signature.has_value());
	require(signature.error().code() == crypto_core::ErrorCode::invalid_key);

	const std::array<std::uint8_t, 8> fake_signature{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &rsa_key_pair.value().public_key, fake_signature}, message.bytes());
	require(!verified.has_value());
	require(verified.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_openssl_ed25519_interoperates_with_native()
{
	crypto_core::OpenSSLProvider openssl;
	crypto_core::NativeProvider native;

	auto private_key = import_ed25519_signing_seed("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60");
	auto public_key = import_ed25519_verify_key("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
	const std::array<std::uint8_t, 0> message{};
	const auto expected_signature = hex_bytes(
	    "E5564300C360AC729086E2CC806E828A"
	    "84877F1EB8E5D974D873E06522490155"
	    "5FB8821590A33BACC61E39701CF9B46B"
	    "D25BF5F0595BBE24655141438E7A100B");

	auto openssl_signature = crypto_core::sign(openssl, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	require(openssl_signature.has_value());
	require(bytes_equal(openssl_signature.value().bytes(), expected_signature));

	auto native_verified = crypto_core::verify(native, {crypto_core::SignatureAlgorithm::ed25519, &public_key, openssl_signature.value().bytes()}, message);
	require(native_verified.has_value());
	require(native_verified.value().is_valid());

	auto native_signature = crypto_core::sign(native, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	require(native_signature.has_value());
	require(bytes_equal(native_signature.value().bytes(), expected_signature));

	auto openssl_verified = crypto_core::verify(openssl, {crypto_core::SignatureAlgorithm::ed25519, &public_key, native_signature.value().bytes()}, message);
	require(openssl_verified.has_value());
	require(openssl_verified.value().is_valid());

	const auto tampered_message = bytes("tampered");
	auto bad_message = crypto_core::verify(openssl, {crypto_core::SignatureAlgorithm::ed25519, &public_key, expected_signature}, tampered_message.bytes());
	require(bad_message.has_value());
	require(!bad_message.value().is_valid());

	auto bad_signature = expected_signature;
	bad_signature[0] ^= 0x80U;
	auto invalid_signature = crypto_core::verify(openssl, {crypto_core::SignatureAlgorithm::ed25519, &public_key, bad_signature}, message);
	require(invalid_signature.has_value());
	require(!invalid_signature.value().is_valid());
}

void test_openssl_rsa_key_generation_rejects_weak_parameters()
{
	crypto_core::OpenSSLProvider provider;
	crypto_core::GenerateKeyPairParams params{crypto_core::AsymmetricKeyAlgorithm::rsa};
	params.rsa.modulus_bits = 1024;

	auto key_pair = crypto_core::generate_key_pair(provider, params);
	require(!key_pair.has_value());
	require(key_pair.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_openssl_rsa_pss_verify_returns_invalid_for_bad_inputs()
{
	crypto_core::OpenSSLProvider provider;
	auto der = generate_rsa_der_key_pair();

	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(der.private_key), crypto_core::KeyUsage::sign);
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der.public_key.bytes(), crypto_core::KeyUsage::verify);
	require(private_key.has_value());
	require(public_key.has_value());

	const auto message = bytes("rsa pss message");
	const auto pss = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key.value(), pss}, message.bytes());
	require(signature.has_value());

	const auto tampered_message = bytes("rsa pss tampered");
	auto bad_message = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key.value(), signature.value().bytes(), pss}, tampered_message.bytes());
	require(bad_message.has_value());
	require(!bad_message.value().is_valid());

	auto tampered_signature = signature.value();
	tampered_signature.bytes()[0] ^= 0x80U;
	auto bad_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key.value(), tampered_signature.bytes(), pss}, message.bytes());
	require(bad_signature.has_value());
	require(!bad_signature.value().is_valid());
}

void test_openssl_rsa_oaep_encrypt_decrypt_round_trip()
{
	crypto_core::OpenSSLProvider provider;
	auto der = generate_rsa_der_key_pair();

	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(der.private_key), crypto_core::KeyUsage::decrypt);
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der.public_key.bytes(), crypto_core::KeyUsage::encrypt);
	require(private_key.has_value());
	require(public_key.has_value());

	const auto plaintext = bytes("openssl rsa oaep message");
	const auto label = bytes("oaep label");
	const auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, label.bytes());

	auto ciphertext = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &public_key.value(), params}, plaintext.bytes());
	require(ciphertext.has_value());
	require(!ciphertext.value().empty());

	auto decrypted = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key.value(), params}, ciphertext.value().bytes());
	require(decrypted.has_value());
	require(decrypted.value() == plaintext);
}

void test_openssl_rsa_oaep_rejects_bad_inputs()
{
	crypto_core::OpenSSLProvider provider;
	auto der = generate_rsa_der_key_pair();

	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(der.private_key), crypto_core::KeyUsage::decrypt);
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der.public_key.bytes(), crypto_core::KeyUsage::encrypt);
	require(private_key.has_value());
	require(public_key.has_value());

	const auto plaintext = bytes("openssl rsa oaep tamper");
	const auto label = bytes("oaep label");
	const auto wrong_label = bytes("wrong label");
	const auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, label.bytes());
	const auto wrong_params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha256, wrong_label.bytes());

	auto ciphertext = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &public_key.value(), params}, plaintext.bytes());
	require(ciphertext.has_value());

	auto wrong = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key.value(), wrong_params}, ciphertext.value().bytes());
	require(!wrong.has_value());
	require(wrong.error().code() == crypto_core::ErrorCode::authentication_failed);

	auto tampered = ciphertext.value();
	tampered.bytes()[0] ^= 0x80U;
	auto bad = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key.value(), params}, tampered.bytes());
	require(!bad.has_value());
	require(bad.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_native_rsa_oaep_ciphertext_decrypts_with_openssl()
{
	crypto_core::NativeProvider native;
	crypto_core::OpenSSLProvider openssl;
	auto der = generate_rsa_der_key_pair();

	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(der.private_key), crypto_core::KeyUsage::decrypt);
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, der.public_key.bytes(), crypto_core::KeyUsage::encrypt);
	require(private_key.has_value());
	require(public_key.has_value());

	const auto plaintext = bytes("native to openssl oaep");
	auto ciphertext = crypto_core::asymmetric_encrypt(native, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &public_key.value()}, plaintext.bytes());
	require(ciphertext.has_value());

	auto decrypted = crypto_core::asymmetric_decrypt(openssl, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &private_key.value()}, ciphertext.value().bytes());
	require(decrypted.has_value());
	require(decrypted.value() == plaintext);
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
	test_openssl_matches_native_aes_gcm();
	test_openssl_rsa_pss_sign_verify_round_trip();
	test_openssl_generates_usable_rsa_key_pair();
	test_openssl_generates_usable_ecdsa_p256_key_pair();
	test_native_verifies_openssl_ecdsa_p256_signature();
	test_openssl_verifies_native_ecdsa_p256_signature();
	test_openssl_ecdsa_p256_verify_returns_invalid_for_bad_inputs();
	test_openssl_ecdsa_p256_rejects_rsa_keys();
	test_openssl_ed25519_interoperates_with_native();
	test_openssl_rsa_key_generation_rejects_weak_parameters();
	test_openssl_rsa_pss_verify_returns_invalid_for_bad_inputs();
	test_openssl_rsa_oaep_encrypt_decrypt_round_trip();
	test_openssl_rsa_oaep_rejects_bad_inputs();
	test_native_rsa_oaep_ciphertext_decrypts_with_openssl();
	return 0;
}

#else

int main()
{
	return 0;
}

#endif
