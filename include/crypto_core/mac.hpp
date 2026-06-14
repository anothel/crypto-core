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

enum class MacAlgorithm
{
	hmac_sha256,
	hmac_sha512,
};

[[nodiscard]] constexpr std::size_t mac_size(MacAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case MacAlgorithm::hmac_sha256:
		return 32;
	case MacAlgorithm::hmac_sha512:
		return 64;
	}

	return 0;
}

[[nodiscard]] constexpr std::string_view mac_algorithm_name(MacAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case MacAlgorithm::hmac_sha256:
		return "HMAC-SHA256";
	case MacAlgorithm::hmac_sha512:
		return "HMAC-SHA512";
	}

	return "unknown";
}

[[nodiscard]] Result<ByteBuffer> mac(
    MacAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> input) noexcept;

[[nodiscard]] Result<ByteBuffer> mac(
    ICryptoProvider &provider,
    MacAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> input) noexcept;

} // namespace crypto_core
