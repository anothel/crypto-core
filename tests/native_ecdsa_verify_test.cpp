#include "crypto_core/crypto_core.hpp"
#include "crypto_core/internal/ecdsa.hpp"

#include "test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

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
		std::exit(1);
	}
}

std::vector<std::uint8_t> bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

crypto_core::PublicKey import_ecdsa_verify_key()
{
	auto public_key_der = bytes(public_key_spki_der_hex);
	auto key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, public_key_der, crypto_core::KeyUsage::verify);
	require(key.has_value());
	return key.value();
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

void test_native_provider_reports_ecdsa_verify_support()
{
	crypto_core::NativeProvider provider;

	require(provider.supports(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
}

void test_native_provider_keeps_ecdsa_sign_unsupported()
{
	crypto_core::NativeProvider provider;
	auto message = bytes(message_hex);

	auto result = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, nullptr}, message);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
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

} // namespace

int main()
{
	test_ecdsa_helper_verifies_static_openssl_vector();
	test_ecdsa_helper_rejects_tampered_message_digest();
	test_ecdsa_helper_rejects_tampered_signature();
	test_ecdsa_helper_rejects_zero_r_or_s();
	test_ecdsa_helper_rejects_out_of_range_r_or_s();
	test_ecdsa_helper_rejects_malformed_signature_as_invalid();
	test_ecdsa_helper_rejects_bad_public_key_as_error();
	test_ecdsa_helper_rejects_off_curve_public_key_as_error();
	test_ecdsa_helper_rejects_non_sha256_digest_size_as_error();
	test_native_provider_reports_ecdsa_verify_support();
	test_native_provider_keeps_ecdsa_sign_unsupported();
	test_native_provider_verifies_static_openssl_ecdsa_signature();
	test_native_provider_rejects_tampered_ecdsa_message();
	test_native_provider_rejects_tampered_ecdsa_signature();
	test_native_provider_rejects_empty_ecdsa_signature();
	test_native_provider_rejects_rsa_key_for_ecdsa_verify();
	test_native_provider_rejects_ecdsa_key_without_verify_usage();
	test_native_provider_rejects_malformed_ecdsa_public_key();
	test_default_provider_verifies_static_ecdsa_signature();
	return 0;
}
