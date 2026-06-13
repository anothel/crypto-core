#pragma once

#include "crypto_core/hash.hpp"
#include "crypto_core/provider.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace crypto_core::internal
{

class HmacContext final : public IMacContext
{
public:
	HmacContext(HashAlgorithm hash_algorithm, std::span<const std::uint8_t> key) noexcept;

	[[nodiscard]] bool initialized() const noexcept;
	[[nodiscard]] Result<void> update(std::span<const std::uint8_t> input) noexcept override;
	[[nodiscard]] Result<ByteBuffer> final() noexcept override;

private:
	HashAlgorithm hash_algorithm_;
	std::vector<std::uint8_t> outer_pad_;
	std::unique_ptr<IHashContext> inner_;
	bool initialized_{false};
	bool finalized_{false};
};

} // namespace crypto_core::internal
