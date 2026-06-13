#include "crypto_core/hash.hpp"

#include "crypto_core/provider.hpp"

namespace crypto_core
{

Result<ByteBuffer> hash(HashAlgorithm algorithm, std::span<const std::uint8_t> input) noexcept
{
	return hash(default_provider(), algorithm, input);
}

Result<ByteBuffer> hash(ICryptoProvider &provider, HashAlgorithm algorithm, std::span<const std::uint8_t> input) noexcept
{
	auto context = provider.create_hash(algorithm);
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
