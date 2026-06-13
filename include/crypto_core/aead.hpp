#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace crypto_core
{

class ICryptoProvider;

enum class AeadAlgorithm
{
	aes_128_gcm,
	aes_192_gcm,
	aes_256_gcm,
};

struct AeadEncryptParams
{
	AeadAlgorithm algorithm;
	std::span<const std::uint8_t> key;
	std::span<const std::uint8_t> nonce;
	std::span<const std::uint8_t> aad;
	std::size_t tag_size{16};
};

struct AeadDecryptParams
{
	AeadAlgorithm algorithm;
	std::span<const std::uint8_t> key;
	std::span<const std::uint8_t> nonce;
	std::span<const std::uint8_t> aad;
	std::span<const std::uint8_t> tag;
};

struct AeadEncryptResult
{
	ByteBuffer ciphertext;
	ByteBuffer tag;
};

constexpr std::string_view aead_algorithm_name(AeadAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AeadAlgorithm::aes_128_gcm:
		return "AES-128-GCM";
	case AeadAlgorithm::aes_192_gcm:
		return "AES-192-GCM";
	case AeadAlgorithm::aes_256_gcm:
		return "AES-256-GCM";
	}

	return "unknown";
}

[[nodiscard]] Result<AeadEncryptResult> aead_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
[[nodiscard]] Result<AeadEncryptResult> aead_encrypt(ICryptoProvider &provider, const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
[[nodiscard]] Result<ByteBuffer> aead_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;
[[nodiscard]] Result<ByteBuffer> aead_decrypt(ICryptoProvider &provider, const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;

} // namespace crypto_core
