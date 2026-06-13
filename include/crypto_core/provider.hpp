#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/hash.hpp"
#include "crypto_core/mac.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace crypto_core
{

class IHashContext
{
public:
	virtual ~IHashContext() = default;

	[[nodiscard]] virtual Result<void> update(std::span<const std::uint8_t> input) noexcept = 0;
	[[nodiscard]] virtual Result<ByteBuffer> final() noexcept = 0;
};

class IMacContext
{
public:
	virtual ~IMacContext() = default;

	[[nodiscard]] virtual Result<void> update(std::span<const std::uint8_t> input) noexcept = 0;
	[[nodiscard]] virtual Result<ByteBuffer> final() noexcept = 0;
};

class ICryptoProvider
{
public:
	virtual ~ICryptoProvider() = default;

	[[nodiscard]] virtual std::string_view name() const noexcept = 0;
	[[nodiscard]] virtual bool supports(HashAlgorithm algorithm) const noexcept = 0;
	[[nodiscard]] virtual bool supports(MacAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual Result<std::unique_ptr<IHashContext>> create_hash(HashAlgorithm algorithm) noexcept = 0;
	[[nodiscard]] virtual Result<std::unique_ptr<IMacContext>> create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept;
};

[[nodiscard]] ICryptoProvider &default_provider() noexcept;

} // namespace crypto_core
