#include "crypto_core/crypto_core.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	if (data == nullptr || size == 0)
	{
		return 0;
	}

	const auto selector = data[0] % 8U;
	const auto input = std::span<const std::uint8_t>{data + 1, size - 1};
	const auto text = std::string_view{reinterpret_cast<const char *>(input.data()), input.size()};

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
	}

	return 0;
}
