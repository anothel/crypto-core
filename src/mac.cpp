#include "crypto_core/mac.hpp"

#include "crypto_core/provider.hpp"

namespace crypto_core
{

Result<ByteBuffer> mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key, std::span<const std::uint8_t> input) noexcept
{
	return mac(default_provider(), algorithm, key, input);
}

Result<ByteBuffer> mac(ICryptoProvider &provider, MacAlgorithm algorithm, std::span<const std::uint8_t> key, std::span<const std::uint8_t> input) noexcept
{
	auto context = provider.create_mac(algorithm, key);
	if (!context)
	{
		return Result<ByteBuffer>::failure(context.error());
	}

	auto update_result = context.value()->update(input);
	if (!update_result)
	{
		return Result<ByteBuffer>::failure(update_result.error());
	}

	return context.value()->final();
}

} // namespace crypto_core
