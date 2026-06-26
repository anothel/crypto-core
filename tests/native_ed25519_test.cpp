#include "crypto_core/crypto_core.hpp"

#include "test_vectors.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

const char *current_check = "startup";

void require(bool condition)
{
	if (!condition)
	{
		std::fprintf(stderr, "native_ed25519_test failed: %s\n", current_check);
		std::exit(1);
	}
}

std::vector<std::uint8_t> bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

crypto_core::PublicKey import_ed25519_verify_key(std::span<const std::uint8_t> key)
{
	auto public_key = crypto_core::PublicKey::import_raw_ed25519(key, crypto_core::KeyUsage::verify);
	require(public_key.has_value());
	return public_key.value();
}

crypto_core::PrivateKey import_ed25519_signing_seed(std::span<const std::uint8_t> seed, crypto_core::KeyUsage usage = crypto_core::KeyUsage::sign)
{
	auto buffer = crypto_core::SecureBuffer::copy_from(seed);
	require(buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_raw_ed25519_seed(std::move(buffer.value()), usage);
	require(private_key.has_value());
	return std::move(private_key.value());
}

void test_native_provider_reports_ed25519_support()
{
	current_check = "provider supports Ed25519";
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::sign, crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::verify, crypto_core::SignatureAlgorithm::ed25519));
}

void test_native_provider_verifies_rfc8032_empty_message_vector()
{
	current_check = "RFC8032 empty-message vector verifies";
	crypto_core::NativeProvider provider;
	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	auto signature = bytes(
	    "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155"
	    "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
	const std::vector<std::uint8_t> message;

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature}, message);
	current_check = "RFC8032 vector returns Result";
	require(result.has_value());
	current_check = "RFC8032 vector is valid";
	require(result.value().is_valid());
}

void test_native_provider_rejects_tampered_ed25519_inputs()
{
	current_check = "tampered Ed25519 inputs setup";
	crypto_core::NativeProvider provider;
	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	auto signature = bytes(
	    "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155"
	    "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
	const auto message = bytes("01");

	auto bad_message = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature}, message);
	current_check = "tampered message returns Result";
	require(bad_message.has_value());
	current_check = "tampered message is invalid";
	require(!bad_message.value().is_valid());

	signature[0] ^= 0x01U;
	const std::vector<std::uint8_t> empty_message;
	auto bad_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature}, empty_message);
	current_check = "tampered signature returns Result";
	require(bad_signature.has_value());
	current_check = "tampered signature is invalid";
	require(!bad_signature.value().is_valid());
}

void test_native_provider_rejects_invalid_ed25519_key_and_signature_shapes()
{
	current_check = "invalid Ed25519 shape setup";
	crypto_core::NativeProvider provider;
	auto short_public_key = crypto_core::PublicKey::import_raw_ed25519(bytes("01"), crypto_core::KeyUsage::verify);
	current_check = "short Ed25519 public key import fails";
	require(!short_public_key.has_value());
	current_check = "short Ed25519 public key import invalid_key";
	require(short_public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto legacy_short_public_key =
	    crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, bytes("01"), crypto_core::KeyUsage::verify);
	current_check = "legacy Ed25519 DER public key import rejects raw-shaped input";
	require(!legacy_short_public_key.has_value());
	require(legacy_short_public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	auto short_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, bytes("00")}, bytes("00"));
	current_check = "short Ed25519 signature returns Result";
	require(short_signature.has_value());
	current_check = "short Ed25519 signature is invalid";
	require(!short_signature.value().is_valid());
}

void test_native_provider_rejects_non_canonical_ed25519_inputs()
{
	current_check = "non-canonical Ed25519 input setup";
	crypto_core::NativeProvider provider;
	auto non_canonical_public_key = crypto_core::PublicKey::import_raw_ed25519(bytes("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F"), crypto_core::KeyUsage::verify);
	current_check = "non-canonical Ed25519 public key import fails";
	require(!non_canonical_public_key.has_value());
	require(non_canonical_public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	auto signature = bytes(
	    "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155"
	    "EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010");
	const std::vector<std::uint8_t> message;

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature}, message);
	current_check = "non-canonical Ed25519 S returns Result";
	require(result.has_value());
	current_check = "non-canonical Ed25519 S is invalid";
	require(!result.value().is_valid());
}

void test_native_provider_signs_rfc8032_empty_message_vector()
{
	current_check = "RFC8032 empty-message signing vector setup";
	crypto_core::NativeProvider provider;
	auto private_key = import_ed25519_signing_seed(bytes("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60"));
	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	const std::vector<std::uint8_t> message;
	auto expected = bytes(
	    "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155"
	    "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");

	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	current_check = "RFC8032 empty-message signing returns Result";
	require(signature.has_value());
	current_check = "RFC8032 empty-message signature matches";
	require(signature.value() == crypto_core::ByteBuffer::copy_from(expected));

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature.value().bytes()}, message);
	current_check = "RFC8032 empty-message signed output verifies";
	require(verified.has_value());
	require(verified.value().is_valid());
}

void test_native_provider_signs_rfc8032_one_octet_message_vector_deterministically()
{
	current_check = "RFC8032 one-octet signing vector setup";
	crypto_core::NativeProvider provider;
	auto private_key = import_ed25519_signing_seed(bytes("4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB"));
	auto public_key = import_ed25519_verify_key(bytes("3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C"));
	auto message = bytes("72");
	auto expected = bytes(
	    "92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA"
	    "085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00");

	auto first = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	auto second = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	current_check = "RFC8032 one-octet signing returns Result";
	require(first.has_value());
	require(second.has_value());
	current_check = "RFC8032 one-octet signature matches";
	require(first.value() == crypto_core::ByteBuffer::copy_from(expected));
	current_check = "RFC8032 one-octet signature deterministic";
	require(first.value() == second.value());

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, first.value().bytes()}, message);
	current_check = "RFC8032 one-octet signed output verifies";
	require(verified.has_value());
	require(verified.value().is_valid());
}

void test_native_provider_signs_rfc8032_two_octet_message_vector()
{
	current_check = "RFC8032 two-octet signing vector setup";
	crypto_core::NativeProvider provider;
	auto private_key = import_ed25519_signing_seed(bytes("C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7"));
	auto public_key = import_ed25519_verify_key(bytes("FC51CD8E6218A1A38DA47ED00230F0580816ED13BA3303AC5DEB911548908025"));
	auto message = bytes("AF82");
	auto expected = bytes(
	    "6291D657DEEC24024827E69C3ABE01A30CE548A284743A445E3680D7DB5AC3AC"
	    "18FF9B538D16F290AE67F760984DC6594A7C15E9716ED28DC027BECEEA1EC40A");

	auto signature = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, &private_key}, message);
	current_check = "RFC8032 two-octet signing returns Result";
	require(signature.has_value());
	current_check = "RFC8032 two-octet signature matches";
	require(signature.value() == crypto_core::ByteBuffer::copy_from(expected));

	auto verified = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, signature.value().bytes()}, message);
	current_check = "RFC8032 two-octet signed output verifies";
	require(verified.has_value());
	require(verified.value().is_valid());
}

void test_native_provider_rejects_invalid_ed25519_signing_keys()
{
	current_check = "invalid Ed25519 signing key setup";
	crypto_core::NativeProvider provider;
	const std::vector<std::uint8_t> message;

	auto verify_usage_key = import_ed25519_signing_seed(bytes("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60"), crypto_core::KeyUsage::verify);
	auto wrong_usage = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, &verify_usage_key}, message);
	current_check = "Ed25519 verify usage key cannot sign";
	require(!wrong_usage.has_value());
	require(wrong_usage.error().code() == crypto_core::ErrorCode::invalid_key);

	auto short_buffer = crypto_core::SecureBuffer::copy_from(bytes("01"));
	require(short_buffer.has_value());
	auto legacy_short_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, std::move(short_buffer.value()), crypto_core::KeyUsage::sign);
	current_check = "legacy Ed25519 DER private key import rejects raw-shaped input";
	require(!legacy_short_key.has_value());
	require(legacy_short_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto null_key = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::ed25519, nullptr}, message);
	current_check = "null Ed25519 signing key fails";
	require(!null_key.has_value());
	require(null_key.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_native_provider_reports_ed25519_support();
	test_native_provider_verifies_rfc8032_empty_message_vector();
	test_native_provider_rejects_tampered_ed25519_inputs();
	test_native_provider_rejects_invalid_ed25519_key_and_signature_shapes();
	test_native_provider_rejects_non_canonical_ed25519_inputs();
	test_native_provider_signs_rfc8032_empty_message_vector();
	test_native_provider_signs_rfc8032_one_octet_message_vector_deterministically();
	test_native_provider_signs_rfc8032_two_octet_message_vector();
	test_native_provider_rejects_invalid_ed25519_signing_keys();
	return 0;
}
