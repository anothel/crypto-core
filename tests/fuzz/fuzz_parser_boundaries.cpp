#include "crypto_core/crypto_core.hpp"

#include "../rsa_test_vectors.hpp"
#include "../test_vectors.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

crypto_core::PublicKey import_p256_verify_key()
{
	auto der = crypto_core::test_support::decode_hex(
	    "3059301306072A8648CE3D020106082A8648CE3D03010703420004507A822E9DA764244CCE994EF0BB4ADEE4FD71B66585C56954BBAFC7BBD2FAA45424E4C9C7A95082E8AE73482CE33DAAB6C27530E728B3B8473A38D99704E480");
	crypto_core::test_support::require_fixture(der.has_value());
	auto key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, der.value(), crypto_core::KeyUsage::verify);
	crypto_core::test_support::require_fixture(key.has_value());
	return key.value();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	if (data == nullptr || size == 0)
	{
		return 0;
	}

	const auto selector = data[0] % 11U;
	const auto input = std::span<const std::uint8_t>{data + 1, size - 1};
	const auto text = std::string_view{reinterpret_cast<const char *>(input.data()), input.size()};
	crypto_core::NativeProvider provider;

	switch (selector)
	{
	case 0:
		(void)crypto_core::base64_decode(text);
		break;
	case 1:
		(void)crypto_core::base64url_decode(text);
		break;
	case 2:
		(void)crypto_core::pem_decode(text);
		break;
	case 3:
		(void)crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, input, crypto_core::KeyUsage::verify);
		break;
	case 4:
		(void)crypto_core::PublicKey::import_rsa_pkcs1_der(input, crypto_core::KeyUsage::verify);
		break;
	case 5:
		if (auto buffer = crypto_core::SecureBuffer::copy_from(input); buffer.has_value())
		{
			(void)crypto_core::PrivateKey::import_pkcs8_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(buffer.value()), crypto_core::KeyUsage::sign);
		}
		break;
	case 6:
		if (auto buffer = crypto_core::SecureBuffer::copy_from(input); buffer.has_value())
		{
			(void)crypto_core::PrivateKey::import_sec1_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, std::move(buffer.value()), crypto_core::KeyUsage::sign);
		}
		break;
	default:
	{
		const std::vector<std::uint8_t> key(16, 0x11);
		const std::vector<std::uint8_t> nonce(12, 0x22);
		const auto tag_size = input.size() < 16 ? input.size() : 16;
		const auto tag = input.first(tag_size);
		const auto ciphertext = input.subspan(tag_size);
		(void)crypto_core::aead_decrypt({crypto_core::AeadAlgorithm::aes_128_gcm, key, nonce, {}, tag}, ciphertext);
		break;
	}
	case 8:
	{
		auto key = import_p256_verify_key();
		const std::vector<std::uint8_t> message{'m', 's', 'g'};
		(void)crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, &key, input}, message);
		break;
	}
	case 9:
	{
		auto key = crypto_core::test_support::rsa_reference_verify_key();
		const auto message = crypto_core::test_support::bytes("rsa pss message");
		(void)crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss_sha256, &key, input}, message.bytes());
		break;
	}
	case 10:
	{
		auto key = crypto_core::test_support::rsa_reference_sign_key();
		(void)crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, &key}, input);
		break;
	}
	}

	return 0;
}
