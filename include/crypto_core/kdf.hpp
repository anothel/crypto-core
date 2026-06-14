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

enum class KdfAlgorithm
{
	pbkdf2_hmac_sha256,
	pbkdf2_hmac_sha512,
	hkdf_sha256,
	hkdf_sha512,
};

[[nodiscard]] constexpr std::string_view kdf_algorithm_name(KdfAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KdfAlgorithm::pbkdf2_hmac_sha256:
		return "PBKDF2-HMAC-SHA256";
	case KdfAlgorithm::pbkdf2_hmac_sha512:
		return "PBKDF2-HMAC-SHA512";
	case KdfAlgorithm::hkdf_sha256:
		return "HKDF-SHA256";
	case KdfAlgorithm::hkdf_sha512:
		return "HKDF-SHA512";
	}

	return "unknown";
}

[[nodiscard]] Result<ByteBuffer> pbkdf2(
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> password,
    std::span<const std::uint8_t> salt,
    std::uint32_t iterations,
    std::size_t output_size) noexcept;

[[nodiscard]] Result<ByteBuffer> pbkdf2(
    ICryptoProvider &provider,
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> password,
    std::span<const std::uint8_t> salt,
    std::uint32_t iterations,
    std::size_t output_size) noexcept;

[[nodiscard]] Result<ByteBuffer> hkdf(
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> input_key_material,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::size_t output_size) noexcept;

[[nodiscard]] Result<ByteBuffer> hkdf(
    ICryptoProvider &provider,
    KdfAlgorithm algorithm,
    std::span<const std::uint8_t> input_key_material,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::size_t output_size) noexcept;

} // namespace crypto_core
