#include "crypto_core/crypto_core.hpp"

#include "test_vectors.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
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
	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, key, crypto_core::KeyUsage::verify);
	require(public_key.has_value());
	return public_key.value();
}

void test_native_provider_reports_ed25519_support()
{
	current_check = "provider supports Ed25519";
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::SignatureAlgorithm::ed25519));
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
	auto short_public_key = import_ed25519_verify_key(bytes("01"));
	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &short_public_key, bytes("00")}, bytes("00"));
	current_check = "short Ed25519 public key fails";
	require(!result.has_value());
	current_check = "short Ed25519 public key invalid_key";
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);

	auto public_key = import_ed25519_verify_key(bytes("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"));
	auto short_signature = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key, bytes("00")}, bytes("00"));
	current_check = "short Ed25519 signature returns Result";
	require(short_signature.has_value());
	current_check = "short Ed25519 signature is invalid";
	require(!short_signature.value().is_valid());
}

} // namespace

int main()
{
	test_native_provider_reports_ed25519_support();
	test_native_provider_verifies_rfc8032_empty_message_vector();
	test_native_provider_rejects_tampered_ed25519_inputs();
	test_native_provider_rejects_invalid_ed25519_key_and_signature_shapes();
	return 0;
}
