#pragma once

#include "crypto_core/provider.hpp"

namespace crypto_core::internal
{

class OsRng final : public IRng
{
public:
	[[nodiscard]] Result<void> generate(std::span<std::uint8_t> output) noexcept override;
};

} // namespace crypto_core::internal
