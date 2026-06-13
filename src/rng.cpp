#include "crypto_core/rng.hpp"

#include "crypto_core/provider.hpp"

#include <vector>

namespace crypto_core
{

Result<ByteBuffer> random_bytes(RngAlgorithm algorithm, std::size_t size) noexcept
{
	return random_bytes(default_provider(), algorithm, size);
}

Result<ByteBuffer> random_bytes(ICryptoProvider &provider, RngAlgorithm algorithm, std::size_t size) noexcept
{
	if (size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "rng", "random byte size must be greater than zero"));
	}

	ByteBuffer bytes{std::vector<std::uint8_t>(size)};
	auto result = random_bytes(provider, algorithm, bytes.bytes());
	if (!result)
	{
		return Result<ByteBuffer>::failure(result.error());
	}

	return Result<ByteBuffer>::success(std::move(bytes));
}

Result<void> random_bytes(RngAlgorithm algorithm, std::span<std::uint8_t> output) noexcept
{
	return random_bytes(default_provider(), algorithm, output);
}

Result<void> random_bytes(ICryptoProvider &provider, RngAlgorithm algorithm, std::span<std::uint8_t> output) noexcept
{
	if (output.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "rng", "random output must not be empty"));
	}

	auto rng = provider.create_rng(algorithm);
	if (!rng)
	{
		return Result<void>::failure(rng.error());
	}

	return rng.value()->generate(output);
}

} // namespace crypto_core
