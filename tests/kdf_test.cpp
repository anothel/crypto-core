#include "crypto_core/crypto_core.hpp"

#include <algorithm>
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

crypto_core::ByteBuffer repeated_byte(std::uint8_t value, std::size_t count)
{
	return crypto_core::ByteBuffer(std::vector<std::uint8_t>(count, value));
}

crypto_core::ByteBuffer byte_range(std::uint8_t first, std::uint8_t last)
{
	std::vector<std::uint8_t> out;
	for (std::uint8_t value = first; value <= last; ++value)
	{
		out.push_back(value);
	}
	return crypto_core::ByteBuffer(std::move(out));
}

std::vector<std::uint8_t> hex_to_bytes(std::string_view hex)
{
	auto value = [](char c) -> std::uint8_t {
		if (c >= '0' && c <= '9')
		{
			return static_cast<std::uint8_t>(c - '0');
		}
		if (c >= 'a' && c <= 'f')
		{
			return static_cast<std::uint8_t>(10 + c - 'a');
		}
		if (c >= 'A' && c <= 'F')
		{
			return static_cast<std::uint8_t>(10 + c - 'A');
		}
		require(false);
		return 0;
	};

	require(hex.size() % 2 == 0);
	std::vector<std::uint8_t> out;
	out.reserve(hex.size() / 2);
	for (std::size_t i = 0; i < hex.size(); i += 2)
	{
		out.push_back(static_cast<std::uint8_t>((value(hex[i]) << 4) | value(hex[i + 1])));
	}
	return out;
}

void require_kdf_eq(const crypto_core::ByteBuffer &actual, std::string_view expected_hex)
{
	const auto expected = hex_to_bytes(expected_hex);
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

void test_kdf_algorithm_metadata()
{
	require(std::string_view{crypto_core::kdf_algorithm_name(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256)} == std::string_view{"PBKDF2-HMAC-SHA256"});
	require(std::string_view{crypto_core::kdf_algorithm_name(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512)} == std::string_view{"PBKDF2-HMAC-SHA512"});
	require(std::string_view{crypto_core::kdf_algorithm_name(crypto_core::KdfAlgorithm::hkdf_sha256)} == std::string_view{"HKDF-SHA256"});
	require(std::string_view{crypto_core::kdf_algorithm_name(crypto_core::KdfAlgorithm::hkdf_sha512)} == std::string_view{"HKDF-SHA512"});
}

void test_native_provider_supports_kdf()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256));
	require(provider.supports(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512));
	require(provider.supports(crypto_core::KdfAlgorithm::hkdf_sha256));
	require(provider.supports(crypto_core::KdfAlgorithm::hkdf_sha512));
}

void test_pbkdf2_hmac_sha256_vectors()
{
	crypto_core::NativeProvider provider;
	auto derived1 = crypto_core::pbkdf2(provider, crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, bytes("password").bytes(), bytes("salt").bytes(), 1, 32);
	require(derived1.has_value());
	require_kdf_eq(derived1.value(), "120fb6cffcf8b32c43e7225256c4f837"
	                                 "a86548c92ccc35480805987cb70be17b");

	auto derived2 = crypto_core::pbkdf2(provider, crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, bytes("password").bytes(), bytes("salt").bytes(), 2, 32);
	require(derived2.has_value());
	require_kdf_eq(derived2.value(), "ae4d0c95af6b46d32d0adff928f06dd0"
	                                 "2a303f8ef3c251dfd6e2d85a95474c43");
}

void test_pbkdf2_hmac_sha512_vectors()
{
	crypto_core::NativeProvider provider;
	auto derived1 = crypto_core::pbkdf2(provider, crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512, bytes("password").bytes(), bytes("salt").bytes(), 1, 64);
	require(derived1.has_value());
	require_kdf_eq(derived1.value(), "867f70cf1ade02cff3752599a3a53dc4"
	                                 "af34c7a669815ae5d513554e1c8cf252"
	                                 "c02d470a285a0501bad999bfe943c08f"
	                                 "050235d7d68b1da55e63f73b60a57fce");

	auto derived2 = crypto_core::pbkdf2(provider, crypto_core::KdfAlgorithm::pbkdf2_hmac_sha512, bytes("password").bytes(), bytes("salt").bytes(), 2, 64);
	require(derived2.has_value());
	require_kdf_eq(derived2.value(), "e1d9c16aa681708a45f5c7c4e215ceb6"
	                                 "6e011a2e9f0040713f18aefdb866d53c"
	                                 "f76cab2868a39b9f7840edce4fef5a82"
	                                 "be67335c77a6068e04112754f27ccf4e");
}

void test_hkdf_sha256_vector()
{
	crypto_core::NativeProvider provider;
	const auto ikm = repeated_byte(0x0b, 22);
	const auto salt = byte_range(0x00, 0x0c);
	const auto info = byte_range(0xf0, 0xf9);
	auto derived = crypto_core::hkdf(provider, crypto_core::KdfAlgorithm::hkdf_sha256, ikm.bytes(), salt.bytes(), info.bytes(), 42);
	require(derived.has_value());
	require_kdf_eq(derived.value(), "3cb25f25faacd57a90434f64d0362f2a"
	                                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
	                                "34007208d5b887185865");
}

void test_hkdf_sha512_vector()
{
	crypto_core::NativeProvider provider;
	const auto ikm = repeated_byte(0x0b, 22);
	const auto salt = byte_range(0x00, 0x0c);
	const auto info = byte_range(0xf0, 0xf9);
	auto derived = crypto_core::hkdf(provider, crypto_core::KdfAlgorithm::hkdf_sha512, ikm.bytes(), salt.bytes(), info.bytes(), 42);
	require(derived.has_value());
	require_kdf_eq(derived.value(), "832390086cda71fb47625bb5ceb168e4"
	                                "c8e26a1a16ed34d9fc7fe92c14815793"
	                                "38da362cb8d9f925d7cb");
}

void test_kdf_validation_errors()
{
	crypto_core::NativeProvider provider;
	auto zero_iterations = crypto_core::pbkdf2(provider, crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, bytes("password").bytes(), bytes("salt").bytes(), 0, 32);
	require(!zero_iterations.has_value());
	require(zero_iterations.error().code() == crypto_core::ErrorCode::invalid_argument);

	auto zero_output = crypto_core::hkdf(provider, crypto_core::KdfAlgorithm::hkdf_sha256, bytes("ikm").bytes(), bytes("salt").bytes(), bytes("info").bytes(), 0);
	require(!zero_output.has_value());
	require(zero_output.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_default_provider_kdf()
{
	auto derived = crypto_core::pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, bytes("password").bytes(), bytes("salt").bytes(), 1, 32);
	require(derived.has_value());
	require_kdf_eq(derived.value(), "120fb6cffcf8b32c43e7225256c4f837"
	                                "a86548c92ccc35480805987cb70be17b");
}

} // namespace

int main()
{
	test_kdf_algorithm_metadata();
	test_native_provider_supports_kdf();
	test_pbkdf2_hmac_sha256_vectors();
	test_pbkdf2_hmac_sha512_vectors();
	test_hkdf_sha256_vector();
	test_hkdf_sha512_vector();
	test_kdf_validation_errors();
	test_default_provider_kdf();
	return 0;
}
