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

enum class RngAlgorithm
{
	os_random,
};

constexpr std::string_view rng_algorithm_name(RngAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case RngAlgorithm::os_random:
		return "OS-RANDOM";
	}

	return "unknown";
}

[[nodiscard]] Result<ByteBuffer> random_bytes(RngAlgorithm algorithm, std::size_t size) noexcept;
[[nodiscard]] Result<ByteBuffer> random_bytes(ICryptoProvider &provider, RngAlgorithm algorithm, std::size_t size) noexcept;
[[nodiscard]] Result<void> random_bytes(RngAlgorithm algorithm, std::span<std::uint8_t> output) noexcept;
[[nodiscard]] Result<void> random_bytes(ICryptoProvider &provider, RngAlgorithm algorithm, std::span<std::uint8_t> output) noexcept;

} // namespace crypto_core
