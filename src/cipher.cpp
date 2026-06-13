#include "crypto_core/cipher.hpp"

#include "crypto_core/provider.hpp"

#include <vector>

namespace crypto_core
{

Result<ByteBuffer> cipher(const CipherParams &params, std::span<const std::uint8_t> input) noexcept
{
	return cipher(default_provider(), params, input);
}

Result<ByteBuffer> cipher(ICryptoProvider &provider, const CipherParams &params, std::span<const std::uint8_t> input) noexcept
{
	auto context = provider.create_cipher(params);
	if (!context)
	{
		return Result<ByteBuffer>::failure(context.error());
	}

	auto updated = context.value()->update(input);
	if (!updated)
	{
		return Result<ByteBuffer>::failure(updated.error());
	}

	auto finalized = context.value()->final();
	if (!finalized)
	{
		return Result<ByteBuffer>::failure(finalized.error());
	}

	std::vector<std::uint8_t> output;
	output.reserve(updated.value().size() + finalized.value().size());
	output.insert(output.end(), updated.value().bytes().begin(), updated.value().bytes().end());
	output.insert(output.end(), finalized.value().bytes().begin(), finalized.value().bytes().end());
	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

} // namespace crypto_core
