#include "crypto_core/crypto_core.hpp"

#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

class MinimalProvider final : public crypto_core::ICryptoProvider
{
public:
	using crypto_core::ICryptoProvider::supports;

	std::string_view name() const noexcept override
	{
		return "MinimalProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "test", "hash unsupported"));
	}
};

void test_algorithm_name_return_types_are_stable()
{
	static_assert(std::is_same_v<decltype(crypto_core::hash_algorithm_name(crypto_core::HashAlgorithm::sha256)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::mac_algorithm_name(crypto_core::MacAlgorithm::hmac_sha256)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::kdf_algorithm_name(crypto_core::KdfAlgorithm::hkdf_sha256)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::cipher_algorithm_name(crypto_core::CipherAlgorithm::aes_128_cbc)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::aead_algorithm_name(crypto_core::AeadAlgorithm::aes_128_gcm)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::rng_algorithm_name(crypto_core::RngAlgorithm::os_random)), std::string_view>);
	static_assert(std::is_same_v<decltype(crypto_core::key_algorithm_name(crypto_core::KeyAlgorithm::aes_128)), std::string_view>);
}

void test_provider_default_unsupported_contract()
{
	MinimalProvider provider;
	require(!provider.supports(crypto_core::MacAlgorithm::hmac_sha256));
	require(!provider.supports(crypto_core::KdfAlgorithm::hkdf_sha256));
	require(!provider.supports(crypto_core::RngAlgorithm::os_random));
	require(!provider.supports(crypto_core::CipherAlgorithm::aes_128_cbc));
	require(!provider.supports(crypto_core::AeadAlgorithm::aes_128_gcm));

	auto mac = provider.create_mac(crypto_core::MacAlgorithm::hmac_sha256, {});
	require(!mac.has_value());
	require(mac.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto rng = provider.create_rng(crypto_core::RngAlgorithm::os_random);
	require(!rng.has_value());
	require(rng.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto pbkdf2 = provider.pbkdf2(crypto_core::KdfAlgorithm::pbkdf2_hmac_sha256, {}, {}, 1, 32);
	require(!pbkdf2.has_value());
	require(pbkdf2.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	const crypto_core::CipherParams cipher_params{
	    crypto_core::CipherAlgorithm::aes_128_cbc,
	    crypto_core::CipherDirection::encrypt,
	    {},
	    {},
	    crypto_core::CipherPadding::none,
	};
	auto cipher = provider.create_cipher(cipher_params);
	require(!cipher.has_value());
	require(cipher.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	const crypto_core::AeadEncryptParams aead_params{
	    crypto_core::AeadAlgorithm::aes_128_gcm,
	    {},
	    {},
	    {},
	    16,
	};
	auto aead = provider.aead_encrypt(aead_params, {});
	require(!aead.has_value());
	require(aead.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

} // namespace

int main()
{
	test_algorithm_name_return_types_are_stable();
	test_provider_default_unsupported_contract();
	return 0;
}
