#pragma once

#include "crypto_core/result.hpp"
#include "crypto_core/secure_buffer.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace crypto_core
{

enum class KeyAlgorithm
{
	generic_secret,
	aes_128,
	aes_192,
	aes_256,
	hmac_sha256,
	hmac_sha512,
};

enum class KeyUsage : std::uint32_t
{
	none = 0,
	encrypt = 1U << 0U,
	decrypt = 1U << 1U,
	mac = 1U << 2U,
	derive = 1U << 3U,
	sign = 1U << 4U,
	verify = 1U << 5U,
};

using KeyUsageMask = std::uint32_t;

[[nodiscard]] constexpr KeyUsageMask key_usage_value(KeyUsage usage) noexcept
{
	return static_cast<KeyUsageMask>(usage);
}

[[nodiscard]] constexpr KeyUsageMask operator|(KeyUsage lhs, KeyUsage rhs) noexcept
{
	return key_usage_value(lhs) | key_usage_value(rhs);
}

[[nodiscard]] constexpr KeyUsageMask operator|(KeyUsageMask lhs, KeyUsage rhs) noexcept
{
	return lhs | key_usage_value(rhs);
}

[[nodiscard]] constexpr bool has_key_usage(KeyUsageMask usages, KeyUsage usage) noexcept
{
	return (usages & key_usage_value(usage)) != 0U;
}

[[nodiscard]] constexpr std::string_view key_algorithm_name(KeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KeyAlgorithm::generic_secret:
		return "generic-secret";
	case KeyAlgorithm::aes_128:
		return "AES-128";
	case KeyAlgorithm::aes_192:
		return "AES-192";
	case KeyAlgorithm::aes_256:
		return "AES-256";
	case KeyAlgorithm::hmac_sha256:
		return "HMAC-SHA256";
	case KeyAlgorithm::hmac_sha512:
		return "HMAC-SHA512";
	}

	return "unknown";
}

[[nodiscard]] constexpr std::size_t key_algorithm_secret_size(KeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KeyAlgorithm::aes_128:
		return 16;
	case KeyAlgorithm::aes_192:
		return 24;
	case KeyAlgorithm::aes_256:
		return 32;
	case KeyAlgorithm::generic_secret:
	case KeyAlgorithm::hmac_sha256:
	case KeyAlgorithm::hmac_sha512:
		return 0;
	}

	return 0;
}

class Key
{
public:
	[[nodiscard]] KeyAlgorithm algorithm() const noexcept
	{
		return algorithm_;
	}

	[[nodiscard]] KeyUsageMask usages() const noexcept
	{
		return usages_;
	}

	[[nodiscard]] bool allows(KeyUsage usage) const noexcept
	{
		return has_key_usage(usages_, usage);
	}

protected:
	constexpr Key(KeyAlgorithm algorithm, KeyUsageMask usages) noexcept
	    : algorithm_(algorithm), usages_(usages)
	{
	}

private:
	KeyAlgorithm algorithm_;
	KeyUsageMask usages_;
};

class SecretKey final : public Key
{
public:
	SecretKey(const SecretKey &) = delete;
	SecretKey &operator=(const SecretKey &) = delete;
	SecretKey(SecretKey &&) noexcept = default;
	SecretKey &operator=(SecretKey &&) noexcept = default;

	[[nodiscard]] static Result<SecretKey> import_raw(
	    KeyAlgorithm algorithm,
	    std::span<const std::uint8_t> bytes,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<SecretKey> import_raw(
	    KeyAlgorithm algorithm,
	    std::span<const std::uint8_t> bytes,
	    KeyUsage usage);

	[[nodiscard]] static Result<SecretKey> from_buffer(
	    KeyAlgorithm algorithm,
	    SecureBuffer bytes,
	    KeyUsageMask usages);
	[[nodiscard]] static Result<SecretKey> from_buffer(
	    KeyAlgorithm algorithm,
	    SecureBuffer bytes,
	    KeyUsage usage);

	[[nodiscard]] Result<SecureBuffer> export_raw() const;

	[[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
	{
		return bytes_.bytes();
	}

	[[nodiscard]] std::size_t size() const noexcept
	{
		return bytes_.size();
	}

	[[nodiscard]] bool empty() const noexcept
	{
		return bytes_.empty();
	}

private:
	SecretKey(KeyAlgorithm algorithm, KeyUsageMask usages, SecureBuffer bytes) noexcept
	    : Key(algorithm, usages), bytes_(std::move(bytes))
	{
	}

	SecureBuffer bytes_;
};

} // namespace crypto_core
