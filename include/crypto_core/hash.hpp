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

enum class HashAlgorithm
{
	sha256,
	sha512,
};

[[nodiscard]] constexpr std::size_t digest_size(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return 32;
	case HashAlgorithm::sha512:
		return 64;
	}

	return 0;
}

[[nodiscard]] constexpr std::string_view hash_algorithm_name(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return "SHA256";
	case HashAlgorithm::sha512:
		return "SHA512";
	}

	return "unknown";
}

[[nodiscard]] Result<ByteBuffer> hash(
    HashAlgorithm algorithm,
    std::span<const std::uint8_t> input) noexcept;

[[nodiscard]] Result<ByteBuffer> hash(
    ICryptoProvider &provider,
    HashAlgorithm algorithm,
    std::span<const std::uint8_t> input) noexcept;

} // namespace crypto_core
