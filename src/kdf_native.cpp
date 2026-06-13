#include "crypto_core/internal/kdf.hpp"

#include "crypto_core/native_provider.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace crypto_core::internal
{
namespace
{

Result<MacAlgorithm> pbkdf2_mac(KdfAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KdfAlgorithm::pbkdf2_hmac_sha256:
		return Result<MacAlgorithm>::success(MacAlgorithm::hmac_sha256);
	case KdfAlgorithm::pbkdf2_hmac_sha512:
		return Result<MacAlgorithm>::success(MacAlgorithm::hmac_sha512);
	case KdfAlgorithm::hkdf_sha256:
	case KdfAlgorithm::hkdf_sha512:
		break;
	}

	return Result<MacAlgorithm>::failure(make_error(ErrorCode::unsupported_algorithm, "kdf", "KDF algorithm is not a PBKDF2 algorithm"));
}

Result<MacAlgorithm> hkdf_mac(KdfAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KdfAlgorithm::hkdf_sha256:
		return Result<MacAlgorithm>::success(MacAlgorithm::hmac_sha256);
	case KdfAlgorithm::hkdf_sha512:
		return Result<MacAlgorithm>::success(MacAlgorithm::hmac_sha512);
	case KdfAlgorithm::pbkdf2_hmac_sha256:
	case KdfAlgorithm::pbkdf2_hmac_sha512:
		break;
	}

	return Result<MacAlgorithm>::failure(make_error(ErrorCode::unsupported_algorithm, "kdf", "KDF algorithm is not an HKDF algorithm"));
}

void append_be32(std::vector<std::uint8_t> &out, std::uint32_t value)
{
	out.push_back(static_cast<std::uint8_t>(value >> 24U));
	out.push_back(static_cast<std::uint8_t>(value >> 16U));
	out.push_back(static_cast<std::uint8_t>(value >> 8U));
	out.push_back(static_cast<std::uint8_t>(value));
}

} // namespace

Result<ByteBuffer> native_pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept
{
	if (iterations == 0 || output_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "kdf", "PBKDF2 iterations and output size must be non-zero"));
	}

	auto mac_algorithm = pbkdf2_mac(algorithm);
	if (!mac_algorithm)
	{
		return Result<ByteBuffer>::failure(mac_algorithm.error());
	}

	const auto digest_size = mac_size(mac_algorithm.value());
	const auto blocks = (output_size + digest_size - 1) / digest_size;
	if (blocks > std::numeric_limits<std::uint32_t>::max())
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "kdf", "PBKDF2 output size is too large"));
	}

	NativeProvider provider;
	std::vector<std::uint8_t> output;
	output.reserve(output_size);
	std::vector<std::uint8_t> block_input(salt.begin(), salt.end());
	const auto salt_size = block_input.size();

	for (std::uint32_t block_index = 1; block_index <= static_cast<std::uint32_t>(blocks); ++block_index)
	{
		block_input.resize(salt_size);
		append_be32(block_input, block_index);

		auto u = mac(provider, mac_algorithm.value(), password, block_input);
		if (!u)
		{
			return Result<ByteBuffer>::failure(u.error());
		}

		std::vector<std::uint8_t> t(u.value().bytes().begin(), u.value().bytes().end());
		for (std::uint32_t iteration = 1; iteration < iterations; ++iteration)
		{
			u = mac(provider, mac_algorithm.value(), password, u.value().bytes());
			if (!u)
			{
				return Result<ByteBuffer>::failure(u.error());
			}

			for (std::size_t i = 0; i < t.size(); ++i)
			{
				t[i] = static_cast<std::uint8_t>(t[i] ^ u.value().bytes()[i]);
			}
		}

		const auto remaining = output_size - output.size();
		const auto take = std::min(remaining, t.size());
		output.insert(output.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(take));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

Result<ByteBuffer> native_hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept
{
	if (output_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "kdf", "HKDF output size must be non-zero"));
	}

	auto mac_algorithm = hkdf_mac(algorithm);
	if (!mac_algorithm)
	{
		return Result<ByteBuffer>::failure(mac_algorithm.error());
	}

	const auto digest_size = mac_size(mac_algorithm.value());
	if (output_size > (255U * digest_size))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "kdf", "HKDF output size is too large"));
	}

	NativeProvider provider;
	std::vector<std::uint8_t> zero_salt(digest_size, std::uint8_t{0});
	const auto salt_span = salt.empty() ? std::span<const std::uint8_t>(zero_salt.data(), zero_salt.size()) : salt;
	auto prk = mac(provider, mac_algorithm.value(), salt_span, input_key_material);
	if (!prk)
	{
		return Result<ByteBuffer>::failure(prk.error());
	}

	std::vector<std::uint8_t> output;
	output.reserve(output_size);
	std::vector<std::uint8_t> previous;
	for (std::uint8_t counter = 1; output.size() < output_size; ++counter)
	{
		auto context = provider.create_mac(mac_algorithm.value(), prk.value().bytes());
		if (!context)
		{
			return Result<ByteBuffer>::failure(context.error());
		}

		auto update = context.value()->update(previous);
		if (!update)
		{
			return Result<ByteBuffer>::failure(update.error());
		}
		update = context.value()->update(info);
		if (!update)
		{
			return Result<ByteBuffer>::failure(update.error());
		}
		const std::array<std::uint8_t, 1> counter_bytes{counter};
		update = context.value()->update(counter_bytes);
		if (!update)
		{
			return Result<ByteBuffer>::failure(update.error());
		}

		auto t = context.value()->final();
		if (!t)
		{
			return Result<ByteBuffer>::failure(t.error());
		}

		previous.assign(t.value().bytes().begin(), t.value().bytes().end());
		const auto remaining = output_size - output.size();
		const auto take = std::min(remaining, previous.size());
		output.insert(output.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(take));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

} // namespace crypto_core::internal
