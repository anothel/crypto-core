#include "crypto_core/crypto_core.hpp"
#include "crypto_core/internal/ecdsa.hpp"

#include "test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

const char *current_test = "";

constexpr std::string_view public_key_spki_der_hex =
    "3059301306072A8648CE3D020106082A8648CE3D03010703420004507A822E9DA764244CCE994EF0BB4ADEE4FD71B66585C56954BBAFC7BBD2FAA45424E4C9C7A95082E8AE73482CE33DAAB6C27530E728B3B8473A38D99704E480";
constexpr std::string_view signature_der_hex =
    "304402205CE55BADA0C9A41C4C702AD67FB0AD0F2439673EC85A794DD0E2C8D002A1A685022054C14EA056B9D38183599E3C1B3C669F044507E543FF797FBCD25A06B72E7F95";
constexpr std::string_view signature_s_plus_n_der_hex =
    "304502205CE55BADA0C9A41C4C702AD67FB0AD0F2439673EC85A794DD0E2C8D002A1A68502210154C14E9F56B9D38283599E3C1B3C669EC12C0292EB171804B08C24C9B391A4E6";
constexpr std::string_view signature_r_n_der_hex =
    "3045022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551022054C14EA056B9D38183599E3C1B3C669F044507E543FF797FBCD25A06B72E7F95";
constexpr std::string_view digest_sha256_hex =
    "2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4D3";
constexpr std::string_view message_hex =
    "6E617469766520656364736120703235362066697874757265";
constexpr std::string_view off_curve_public_key_spki_der_hex =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view basepoint_public_key_spki_der_hex =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
constexpr std::string_view scalar_one_private_key_der_hex =
    "303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107";
// RFC 6979 Appendix A.2.5, ECDSA P-256 with SHA-256.
constexpr std::string_view rfc6979_public_key_spki_der_hex =
    "3059301306072A8648CE3D020106082A8648CE3D0301070342000460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
constexpr std::string_view rfc6979_sample_sha256_signature_der_hex =
    "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
constexpr std::string_view rfc6979_test_sha256_signature_der_hex =
    "3045022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D383670220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083";

constexpr std::array<std::uint8_t, 162> rsa_pss_public_key_der{
    0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xAE, 0x4D, 0xCB,
    0xEB, 0xEE, 0x77, 0x3B, 0xE8, 0x85, 0x6E, 0x61, 0xEB, 0xBD, 0xF2, 0xCE, 0x94, 0xE5, 0xBB, 0xE5,
    0x1B, 0xC4, 0x95, 0x7D, 0x3B, 0xEB, 0x78, 0x71, 0x31, 0x28, 0xFB, 0x95, 0x51, 0x03, 0xBA, 0xB0,
    0xDC, 0x5B, 0x34, 0xCD, 0x16, 0xCC, 0x3B, 0xB8, 0xEC, 0xF6, 0xA7, 0xF7, 0xDD, 0xB8, 0xEB, 0xC3,
    0x8A, 0xD7, 0x1D, 0x05, 0x47, 0x5D, 0x96, 0x0A, 0x50, 0x1E, 0x2F, 0x2B, 0x75, 0x22, 0x4A, 0x4A,
    0xCA, 0x7A, 0x95, 0x38, 0xBD, 0xA9, 0x5A, 0xEF, 0x8E, 0x24, 0x6B, 0xF5, 0x01, 0xE0, 0x50, 0x1C,
    0x8A, 0xAA, 0x28, 0x0F, 0x98, 0xFE, 0x48, 0xB5, 0xAC, 0xB2, 0x33, 0x01, 0x4F, 0x70, 0xE8, 0x87,
    0xFC, 0xB9, 0x3A, 0xF7, 0x46, 0x0A, 0x55, 0xA9, 0xF8, 0x66, 0x3F, 0xA5, 0x8E, 0x78, 0x0A, 0xD4,
    0x07, 0x59, 0xA0, 0x43, 0xEE, 0x9D, 0xB9, 0xE9, 0xA7, 0x74, 0x78, 0x02, 0x55, 0x02, 0x03, 0x01,
    0x00, 0x01};

void require(bool condition)
{
	if (!condition)
	{
		std::cerr << current_test << '\n';
		std::exit(1);
	}
}

#define RUN_TEST(test_name)        \
	do                             \
	{                              \
		current_test = #test_name; \
		test_name();               \
	} while (false)

std::vector<std::uint8_t> bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

std::vector<std::uint8_t> ascii_bytes(std::string_view value)
{
	return std::vector<std::uint8_t>(value.begin(), value.end());
}

std::vector<std::uint8_t> sha256(std::span<const std::uint8_t> message)
{
	auto digest = crypto_core::hash(crypto_core::HashAlgorithm::sha256, message);
	require(digest.has_value());
	return std::vector<std::uint8_t>(digest.value().bytes().begin(), digest.value().bytes().end());
}

crypto_core::PublicKey import_ecdsa_verify_key(std::string_view public_key_der_hex)
{
	auto public_key_der = bytes(public_key_der_hex);
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, public_key_der, crypto_core::KeyUsage::verify);
	require(key.has_value());
	return key.value();
}

crypto_core::PublicKey import_ecdsa_verify_key()
{
	return import_ecdsa_verify_key(public_key_spki_der_hex);
}

crypto_core::PublicKey import_basepoint_ecdsa_verify_key()
{
	auto public_key_der = bytes(basepoint_public_key_spki_der_hex);
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, public_key_der, crypto_core::KeyUsage::verify);
	require(key.has_value());
	return key.value();
}

crypto_core::PrivateKey import_scalar_one_ecdsa_sign_key(crypto_core::KeyUsage usage = crypto_core::KeyUsage::sign)
{
	auto private_key_der = bytes(scalar_one_private_key_der_hex);
	auto buffer = crypto_core::SecureBuffer::copy_from(private_key_der);
	require(buffer.has_value());
	auto key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, std::move(buffer.value()), usage);
	require(key.has_value());
	return std::move(key.value());
}

crypto_core::PublicKey import_ecdsa_key_without_verify_usage()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, public_key_der, crypto_core::KeyUsage::encrypt);
	require(key.has_value());
	return key.value();
}

crypto_core::PublicKey import_malformed_ecdsa_verify_key()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	public_key_der[0] = 0x31;
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, public_key_der, crypto_core::KeyUsage::verify);
	require(key.has_value());
	return key.value();
}

crypto_core::PublicKey import_rsa_verify_key()
{
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, rsa_pss_public_key_der, crypto_core::KeyUsage::verify);
	require(key.has_value());
	return key.value();
}

void test_ecdsa_helper_verifies_static_openssl_vector()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes(digest_sha256_hex);

	auto valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
	require(valid.has_value());
	require(valid.value());
}

void test_ecdsa_verifies_static_sha256_vector_table()
{
	struct Vector final
	{
		std::string_view public_key_der;
		std::string_view signature_der;
		std::vector<std::uint8_t> message;
	};

	std::array<Vector, 3> vectors{
	    Vector{public_key_spki_der_hex, signature_der_hex, bytes(message_hex)},
	    Vector{rfc6979_public_key_spki_der_hex, rfc6979_sample_sha256_signature_der_hex, ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, rfc6979_test_sha256_signature_der_hex, ascii_bytes("test")}};

	crypto_core::NativeProvider provider;
	for (const auto &vector : vectors)
	{
		auto public_key_der = bytes(vector.public_key_der);
		auto signature_der = bytes(vector.signature_der);
		auto digest = sha256(vector.message);
		auto helper_valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
		require(helper_valid.has_value());
		require(helper_valid.value());

		auto public_key = import_ecdsa_verify_key(vector.public_key_der);
		auto provider_valid = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, vector.message);
		require(provider_valid.has_value());
		require(provider_valid.value().is_valid());
	}
}

void test_native_provider_verifies_generated_ecdsa_vector_table()
{
	crypto_core::NativeProvider provider;
	auto private_key = import_scalar_one_ecdsa_sign_key();
	auto public_key = import_basepoint_ecdsa_verify_key();
	const std::array<std::vector<std::uint8_t>, 4> messages{
	    ascii_bytes(""),
	    ascii_bytes("sample"),
	    ascii_bytes("test"),
	    bytes("000102030405060708090A0B0C0D0E0F")};

	for (const auto &message : messages)
	{
		auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
		require(signature.has_value());

		auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature.value().bytes()}, message);
		require(result.has_value());
		require(result.value().is_valid());
	}
}

void test_ecdsa_rejects_invalid_sha256_vector_table()
{
	struct Vector final
	{
		std::string_view public_key_der;
		std::string_view signature_der;
		std::vector<std::uint8_t> message;
	};

	std::array<Vector, 7> vectors{
	    Vector{rfc6979_public_key_spki_der_hex, rfc6979_sample_sha256_signature_der_hex, ascii_bytes("test")},
	    Vector{rfc6979_public_key_spki_der_hex, rfc6979_test_sha256_signature_der_hex, ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, "3006020100020101", ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, "3006020101020100", ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, signature_r_n_der_hex, ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, signature_s_plus_n_der_hex, ascii_bytes("sample")},
	    Vector{rfc6979_public_key_spki_der_hex, "300602010102010200", ascii_bytes("sample")}};

	crypto_core::NativeProvider provider;
	for (const auto &vector : vectors)
	{
		auto public_key_der = bytes(vector.public_key_der);
		auto signature_der = bytes(vector.signature_der);
		auto digest = sha256(vector.message);
		auto helper_valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
		require(helper_valid.has_value());
		require(!helper_valid.value());

		auto public_key = import_ecdsa_verify_key(vector.public_key_der);
		auto provider_valid = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, vector.message);
		require(provider_valid.has_value());
		require(!provider_valid.value().is_valid());
	}
}

void test_ecdsa_helper_rejects_tampered_message_digest()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes(digest_sha256_hex);
	digest[0] ^= 0x01U;

	auto valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
	require(valid.has_value());
	require(!valid.value());
}

void test_ecdsa_helper_rejects_tampered_signature()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes(digest_sha256_hex);
	signature_der.back() ^= 0x01U;

	auto valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
	require(valid.has_value());
	require(!valid.value());
}

void test_ecdsa_helper_rejects_zero_r_or_s()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto digest = bytes(digest_sha256_hex);
	auto zero_r = bytes("3006020100020101");
	auto zero_s = bytes("3006020101020100");

	auto invalid_r = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, zero_r, digest);
	require(invalid_r.has_value());
	require(!invalid_r.value());

	auto invalid_s = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, zero_s, digest);
	require(invalid_s.has_value());
	require(!invalid_s.value());
}

void test_ecdsa_helper_rejects_out_of_range_r_or_s()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto digest = bytes(digest_sha256_hex);
	auto sig_s_plus_n = bytes(signature_s_plus_n_der_hex);
	auto sig_r_n = bytes(signature_r_n_der_hex);

	auto invalid_s = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, sig_s_plus_n, digest);
	require(invalid_s.has_value());
	require(!invalid_s.value());

	auto invalid_r = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, sig_r_n, digest);
	require(invalid_r.has_value());
	require(!invalid_r.value());
}

void test_ecdsa_helper_rejects_malformed_signature_as_invalid()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto digest = bytes(digest_sha256_hex);
	auto bad_signature = bytes("300602010102010200");

	auto malformed_sig = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, bad_signature, digest);
	require(malformed_sig.has_value());
	require(!malformed_sig.value());
}

void test_ecdsa_helper_rejects_bad_public_key_as_error()
{
	auto malformed_public_key_der = bytes(public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes(digest_sha256_hex);
	malformed_public_key_der[0] = 0x31;

	auto bad_key = crypto_core::internal::verify_ecdsa_p256_sha256_digest(malformed_public_key_der, signature_der, digest);
	require(!bad_key.has_value());
	require(bad_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_ecdsa_helper_rejects_off_curve_public_key_as_error()
{
	auto off_curve_public_key_der = bytes(off_curve_public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes(digest_sha256_hex);

	auto bad_key = crypto_core::internal::verify_ecdsa_p256_sha256_digest(off_curve_public_key_der, signature_der, digest);
	require(!bad_key.has_value());
	require(bad_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_ecdsa_helper_rejects_non_sha256_digest_size_as_error()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto signature_der = bytes(signature_der_hex);
	auto digest = bytes("2458A32EE9865404E73CE768CE4B4F9945B9AFB819404BE4DB3EA45EA479F4");

	auto result = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature_der, digest);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_ecdsa_helper_signs_and_verifies_digest()
{
	auto private_key_der = bytes(scalar_one_private_key_der_hex);
	auto public_key_der = bytes(basepoint_public_key_spki_der_hex);
	auto digest = bytes(digest_sha256_hex);

	auto signature = crypto_core::internal::sign_ecdsa_p256_sha256_digest(private_key_der, digest);
	require(signature.has_value());

	auto valid = crypto_core::internal::verify_ecdsa_p256_sha256_digest(public_key_der, signature.value().bytes(), digest);
	require(valid.has_value());
	require(valid.value());
}

void test_ecdsa_helper_signing_is_deterministic()
{
	auto private_key_der = bytes(scalar_one_private_key_der_hex);
	auto digest = bytes(digest_sha256_hex);

	auto first = crypto_core::internal::sign_ecdsa_p256_sha256_digest(private_key_der, digest);
	auto second = crypto_core::internal::sign_ecdsa_p256_sha256_digest(private_key_der, digest);
	require(first.has_value());
	require(second.has_value());
	require(first.value() == second.value());
}

void test_native_provider_reports_ecdsa_verify_support()
{
	crypto_core::NativeProvider provider;

	require(provider.supports(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
}

void test_native_provider_signs_and_verifies_ecdsa_signature()
{
	crypto_core::NativeProvider provider;
	auto private_key = import_scalar_one_ecdsa_sign_key();
	auto public_key = import_basepoint_ecdsa_verify_key();
	auto message = bytes(message_hex);

	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
	require(signature.has_value());

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature.value().bytes()}, message);
	require(result.has_value());
	require(result.value().is_valid());
}

void test_native_provider_ecdsa_signing_is_deterministic()
{
	crypto_core::NativeProvider provider;
	auto private_key = import_scalar_one_ecdsa_sign_key();
	auto message = bytes(message_hex);

	auto first = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
	auto second = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
	require(first.has_value());
	require(second.has_value());
	require(first.value() == second.value());
}

void test_native_provider_rejects_ecdsa_sign_without_private_key()
{
	crypto_core::NativeProvider provider;
	auto message = bytes(message_hex);

	auto result = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, nullptr}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_native_provider_rejects_ecdsa_sign_key_without_sign_usage()
{
	crypto_core::NativeProvider provider;
	auto private_key = import_scalar_one_ecdsa_sign_key(crypto_core::KeyUsage::verify);
	auto message = bytes(message_hex);

	auto result = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_native_provider_verifies_static_openssl_ecdsa_signature()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_ecdsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(result.has_value());
	require(result.value().is_valid());
}

void test_native_provider_rejects_tampered_ecdsa_message()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_ecdsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);
	message[0] ^= 0x01U;

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(result.has_value());
	require(!result.value().is_valid());
}

void test_native_provider_rejects_tampered_ecdsa_signature()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_ecdsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);
	signature_der.back() ^= 0x01U;

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(result.has_value());
	require(!result.value().is_valid());
}

void test_native_provider_rejects_empty_ecdsa_signature()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_ecdsa_verify_key();
	auto message = bytes(message_hex);
	std::span<const std::uint8_t> empty_signature;

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, empty_signature}, message);
	require(result.has_value());
	require(!result.value().is_valid());
}

void test_native_provider_rejects_rsa_key_for_ecdsa_verify()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_rsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_native_provider_rejects_ecdsa_key_without_verify_usage()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_ecdsa_key_without_verify_usage();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_native_provider_rejects_malformed_ecdsa_public_key()
{
	crypto_core::NativeProvider provider;
	auto public_key = import_malformed_ecdsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_default_provider_verifies_static_ecdsa_signature()
{
	auto public_key = import_ecdsa_verify_key();
	auto signature_der = bytes(signature_der_hex);
	auto message = bytes(message_hex);

	auto result = crypto_core::verify({crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature_der}, message);
	require(result.has_value());
	require(result.value().is_valid());
}

void test_default_provider_signs_ecdsa_signature()
{
	auto private_key = import_scalar_one_ecdsa_sign_key();
	auto public_key = import_basepoint_ecdsa_verify_key();
	auto message = bytes(message_hex);

	auto signature = crypto_core::sign({crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &private_key}, message);
	require(signature.has_value());

	auto result = crypto_core::verify({crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &public_key, signature.value().bytes()}, message);
	require(result.has_value());
	require(result.value().is_valid());
}

} // namespace

int main()
{
	RUN_TEST(test_ecdsa_helper_verifies_static_openssl_vector);
	RUN_TEST(test_ecdsa_verifies_static_sha256_vector_table);
	RUN_TEST(test_native_provider_verifies_generated_ecdsa_vector_table);
	RUN_TEST(test_ecdsa_rejects_invalid_sha256_vector_table);
	RUN_TEST(test_ecdsa_helper_rejects_tampered_message_digest);
	RUN_TEST(test_ecdsa_helper_rejects_tampered_signature);
	RUN_TEST(test_ecdsa_helper_rejects_zero_r_or_s);
	RUN_TEST(test_ecdsa_helper_rejects_out_of_range_r_or_s);
	RUN_TEST(test_ecdsa_helper_rejects_malformed_signature_as_invalid);
	RUN_TEST(test_ecdsa_helper_rejects_bad_public_key_as_error);
	RUN_TEST(test_ecdsa_helper_rejects_off_curve_public_key_as_error);
	RUN_TEST(test_ecdsa_helper_rejects_non_sha256_digest_size_as_error);
	RUN_TEST(test_ecdsa_helper_signs_and_verifies_digest);
	RUN_TEST(test_ecdsa_helper_signing_is_deterministic);
	RUN_TEST(test_native_provider_reports_ecdsa_verify_support);
	RUN_TEST(test_native_provider_signs_and_verifies_ecdsa_signature);
	RUN_TEST(test_native_provider_ecdsa_signing_is_deterministic);
	RUN_TEST(test_native_provider_rejects_ecdsa_sign_without_private_key);
	RUN_TEST(test_native_provider_rejects_ecdsa_sign_key_without_sign_usage);
	RUN_TEST(test_native_provider_verifies_static_openssl_ecdsa_signature);
	RUN_TEST(test_native_provider_rejects_tampered_ecdsa_message);
	RUN_TEST(test_native_provider_rejects_tampered_ecdsa_signature);
	RUN_TEST(test_native_provider_rejects_empty_ecdsa_signature);
	RUN_TEST(test_native_provider_rejects_rsa_key_for_ecdsa_verify);
	RUN_TEST(test_native_provider_rejects_ecdsa_key_without_verify_usage);
	RUN_TEST(test_native_provider_rejects_malformed_ecdsa_public_key);
	RUN_TEST(test_default_provider_verifies_static_ecdsa_signature);
	RUN_TEST(test_default_provider_signs_ecdsa_signature);
	return 0;
}
