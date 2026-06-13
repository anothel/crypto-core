#include "crypto_core/crypto_core.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

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
	return 0;
}

#else

int main()
{
	return 0;
}

#endif
