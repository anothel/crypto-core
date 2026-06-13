#pragma once

#include "crypto_core/provider.hpp"

#include <memory>
#include <string_view>

namespace crypto_core
{

class NativeProvider final : public ICryptoProvider
{
public:
	[[nodiscard]] std::string_view name() const noexcept override;
	[[nodiscard]] bool supports(HashAlgorithm algorithm) const noexcept override;
	[[nodiscard]] bool supports(MacAlgorithm algorithm) const noexcept override;
	[[nodiscard]] Result<std::unique_ptr<IHashContext>> create_hash(HashAlgorithm algorithm) noexcept override;
	[[nodiscard]] Result<std::unique_ptr<IMacContext>> create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept override;
};

} // namespace crypto_core
