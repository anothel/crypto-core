#include "crypto_core/rng.hpp"

#include "crypto_core/provider.hpp"

#include <utility>
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
		return Result<ByteBuffer>::success(ByteBuffer{});
	}

	std::vector<std::uint8_t> storage;
	try
	{
		storage.resize(size);
	}
	catch (...)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::internal_error, "rng", "random byte allocation failed"));
	}

	ByteBuffer bytes{std::move(storage)};
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
		return Result<void>::success();
	}

	auto rng = provider.create_rng(algorithm);
	if (!rng)
	{
		return Result<void>::failure(rng.error());
	}

	return rng.value()->generate(output);
}

} // namespace crypto_core
