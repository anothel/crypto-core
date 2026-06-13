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

void require_mac_eq(const crypto_core::ByteBuffer &actual, std::string_view expected_hex)
{
	const auto expected = hex_to_bytes(expected_hex);
	require(actual.bytes().size() == expected.size());
	require(std::equal(actual.bytes().begin(), actual.bytes().end(), expected.begin()));
}

void test_mac_algorithm_metadata()
{
	require(crypto_core::mac_size(crypto_core::MacAlgorithm::hmac_sha256) == 32);
	require(crypto_core::mac_size(crypto_core::MacAlgorithm::hmac_sha512) == 64);
	require(std::string_view{crypto_core::mac_algorithm_name(crypto_core::MacAlgorithm::hmac_sha256)} == std::string_view{"HMAC-SHA256"});
	require(std::string_view{crypto_core::mac_algorithm_name(crypto_core::MacAlgorithm::hmac_sha512)} == std::string_view{"HMAC-SHA512"});
}

void test_native_provider_supports_hmac()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::MacAlgorithm::hmac_sha256));
	require(provider.supports(crypto_core::MacAlgorithm::hmac_sha512));
}

void test_hmac_sha256_known_answer_vectors()
{
	crypto_core::NativeProvider provider;
	const auto key1 = repeated_byte(0x0b, 20);
	const auto data1 = bytes("Hi There");
	auto mac1 = crypto_core::mac(provider, crypto_core::MacAlgorithm::hmac_sha256, key1.bytes(), data1.bytes());
	require(mac1.has_value());
	require_mac_eq(mac1.value(), "b0344c61d8db38535ca8afceaf0bf12b"
	                             "881dc200c9833da726e9376c2e32cff7");

	const auto key2 = bytes("Jefe");
	const auto data2 = bytes("what do ya want for nothing?");
	auto mac2 = crypto_core::mac(provider, crypto_core::MacAlgorithm::hmac_sha256, key2.bytes(), data2.bytes());
	require(mac2.has_value());
	require_mac_eq(mac2.value(), "5bdcc146bf60754e6a042426089575c7"
	                             "5a003f089d2739839dec58b964ec3843");
}

void test_hmac_sha512_known_answer_vectors()
{
	crypto_core::NativeProvider provider;
	const auto key1 = repeated_byte(0x0b, 20);
	const auto data1 = bytes("Hi There");
	auto mac1 = crypto_core::mac(provider, crypto_core::MacAlgorithm::hmac_sha512, key1.bytes(), data1.bytes());
	require(mac1.has_value());
	require_mac_eq(mac1.value(), "87aa7cdea5ef619d4ff0b4241a1d6cb0"
	                             "2379f4e2ce4ec2787ad0b30545e17cde"
	                             "daa833b7d6b8a702038b274eaea3f4e4"
	                             "be9d914eeb61f1702e696c203a126854");

	const auto key2 = bytes("Jefe");
	const auto data2 = bytes("what do ya want for nothing?");
	auto mac2 = crypto_core::mac(provider, crypto_core::MacAlgorithm::hmac_sha512, key2.bytes(), data2.bytes());
	require(mac2.has_value());
	require_mac_eq(mac2.value(), "164b7a7bfcf819e2e395fbe73b56e0a3"
	                             "87bd64222e831fd610270cd7ea250554"
	                             "9758bf75c05a994a6d034f65f8f0e6fd"
	                             "caeab1a34d4a6b4b636e070a38bce737");
}

void test_hmac_streaming_matches_one_shot()
{
	crypto_core::NativeProvider provider;
	const auto key = bytes("Jefe");
	auto context = provider.create_mac(crypto_core::MacAlgorithm::hmac_sha256, key.bytes());
	require(context.has_value());

	require(context.value()->update(bytes("what do ya ").bytes()).has_value());
	require(context.value()->update(bytes("want for nothing?").bytes()).has_value());
	auto streamed = context.value()->final();
	require(streamed.has_value());

	auto one_shot = crypto_core::mac(provider, crypto_core::MacAlgorithm::hmac_sha256, key.bytes(), bytes("what do ya want for nothing?").bytes());
	require(one_shot.has_value());
	require(streamed.value() == one_shot.value());
}

void test_update_after_final_fails()
{
	crypto_core::NativeProvider provider;
	const auto key = bytes("Jefe");
	auto context = provider.create_mac(crypto_core::MacAlgorithm::hmac_sha256, key.bytes());
	require(context.has_value());
	require(context.value()->update(bytes("abc").bytes()).has_value());
	require(context.value()->final().has_value());

	auto update_after_final = context.value()->update(bytes("x").bytes());
	require(!update_after_final.has_value());
	require(update_after_final.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_default_mac_uses_native_provider()
{
	const auto key = bytes("Jefe");
	const auto data = bytes("what do ya want for nothing?");
	auto digest = crypto_core::mac(crypto_core::MacAlgorithm::hmac_sha256, key.bytes(), data.bytes());
	require(digest.has_value());
	require_mac_eq(digest.value(), "5bdcc146bf60754e6a042426089575c7"
	                               "5a003f089d2739839dec58b964ec3843");
}

} // namespace

int main()
{
	test_mac_algorithm_metadata();
	test_native_provider_supports_hmac();
	test_hmac_sha256_known_answer_vectors();
	test_hmac_sha512_known_answer_vectors();
	test_hmac_streaming_matches_one_shot();
	test_update_after_final_fails();
	test_default_mac_uses_native_provider();
	return 0;
}
