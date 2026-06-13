#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>
#include <string_view>

namespace crypto_core
{

class ICryptoProvider;

enum class CipherAlgorithm
{
	aes_128_cbc,
	aes_192_cbc,
	aes_256_cbc,
};

enum class CipherDirection
{
	encrypt,
	decrypt,
};

enum class CipherPadding
{
	none,
	pkcs7,
};

struct CipherParams
{
	CipherAlgorithm algorithm;
	CipherDirection direction;
	std::span<const std::uint8_t> key;
	std::span<const std::uint8_t> iv;
	CipherPadding padding{CipherPadding::none};
};

constexpr std::string_view cipher_algorithm_name(CipherAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case CipherAlgorithm::aes_128_cbc:
		return "AES-128-CBC";
	case CipherAlgorithm::aes_192_cbc:
		return "AES-192-CBC";
	case CipherAlgorithm::aes_256_cbc:
		return "AES-256-CBC";
	}

	return "unknown";
}

[[nodiscard]] Result<ByteBuffer> cipher(const CipherParams &params, std::span<const std::uint8_t> input) noexcept;
[[nodiscard]] Result<ByteBuffer> cipher(ICryptoProvider &provider, const CipherParams &params, std::span<const std::uint8_t> input) noexcept;

} // namespace crypto_core
