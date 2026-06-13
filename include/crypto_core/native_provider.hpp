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
	[[nodiscard]] Result<std::unique_ptr<IHashContext>> create_hash(HashAlgorithm algorithm) noexcept override;
};

} // namespace crypto_core
