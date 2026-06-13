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

void assert_digest_eq(const crypto_core::ByteBuffer &digest, std::string_view expected_hex)
{
	const auto expected = hex_to_bytes(expected_hex);
	require(digest.bytes().size() == expected.size());
	require(std::equal(digest.bytes().begin(), digest.bytes().end(), expected.begin()));
}

void test_native_provider_supports_sha2()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::HashAlgorithm::sha256));
	require(provider.supports(crypto_core::HashAlgorithm::sha512));
}

void test_default_provider_supports_sha2()
{
	auto &provider = crypto_core::default_provider();
	require(provider.name() == std::string_view{"NativeProvider"});
	require(provider.supports(crypto_core::HashAlgorithm::sha256));
	require(provider.supports(crypto_core::HashAlgorithm::sha512));
}

void test_sha256_known_answer_vectors()
{
	crypto_core::NativeProvider provider;

	auto empty = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, bytes("").bytes());
	require(empty.has_value());
	assert_digest_eq(empty.value(), "e3b0c44298fc1c149afbf4c8996fb924"
	                                "27ae41e4649b934ca495991b7852b855");

	auto abc = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, bytes("abc").bytes());
	require(abc.has_value());
	assert_digest_eq(abc.value(), "ba7816bf8f01cfea414140de5dae2223"
	                              "b00361a396177a9cb410ff61f20015ad");
}

void test_sha512_known_answer_vectors()
{
	crypto_core::NativeProvider provider;

	auto empty = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha512, bytes("").bytes());
	require(empty.has_value());
	assert_digest_eq(empty.value(), "cf83e1357eefb8bdf1542850d66d8007"
	                                "d620e4050b5715dc83f4a921d36ce9ce"
	                                "47d0d13c5d85f2b0ff8318d2877eec2f"
	                                "63b931bd47417a81a538327af927da3e");

	auto abc = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha512, bytes("abc").bytes());
	require(abc.has_value());
	assert_digest_eq(abc.value(), "ddaf35a193617abacc417349ae204131"
	                              "12e6fa4e89a97ea20a9eeee64b55d39a"
	                              "2192992a274fc1a836ba3c23a3feebbd"
	                              "454d4423643ce80e2a9ac94fa54ca49f");
}

void test_sha256_streaming_matches_one_shot()
{
	crypto_core::NativeProvider provider;
	auto context = provider.create_hash(crypto_core::HashAlgorithm::sha256);
	require(context.has_value());

	const auto first = bytes("ab");
	const auto second = bytes("c");
	require(context.value()->update(first.bytes()).has_value());
	require(context.value()->update(second.bytes()).has_value());
	auto streamed = context.value()->final();
	require(streamed.has_value());

	auto one_shot = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, bytes("abc").bytes());
	require(one_shot.has_value());
	require(streamed.value() == one_shot.value());
}

void test_sha512_streaming_matches_one_shot()
{
	crypto_core::NativeProvider provider;
	auto context = provider.create_hash(crypto_core::HashAlgorithm::sha512);
	require(context.has_value());

	const auto first = bytes("a");
	const auto second = bytes("bc");
	require(context.value()->update(first.bytes()).has_value());
	require(context.value()->update(second.bytes()).has_value());
	auto streamed = context.value()->final();
	require(streamed.has_value());

	auto one_shot = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha512, bytes("abc").bytes());
	require(one_shot.has_value());
	require(streamed.value() == one_shot.value());
}

void test_update_after_final_fails()
{
	crypto_core::NativeProvider provider;
	auto context = provider.create_hash(crypto_core::HashAlgorithm::sha256);
	require(context.has_value());
	require(context.value()->update(bytes("abc").bytes()).has_value());
	require(context.value()->final().has_value());

	auto update_after_final = context.value()->update(bytes("x").bytes());
	require(!update_after_final.has_value());
	require(update_after_final.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_default_hash_uses_native_sha()
{
	auto digest = crypto_core::hash(crypto_core::HashAlgorithm::sha256, bytes("abc").bytes());
	require(digest.has_value());
	assert_digest_eq(digest.value(), "ba7816bf8f01cfea414140de5dae2223"
	                                 "b00361a396177a9cb410ff61f20015ad");
}

} // namespace

int main()
{
	test_native_provider_supports_sha2();
	test_default_provider_supports_sha2();
	test_sha256_known_answer_vectors();
	test_sha512_known_answer_vectors();
	test_sha256_streaming_matches_one_shot();
	test_sha512_streaming_matches_one_shot();
	test_update_after_final_fails();
	test_default_hash_uses_native_sha();
	return 0;
}
