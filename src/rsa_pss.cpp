#include "crypto_core/internal/rsa_pss.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/sha2.hpp"
#include "crypto_core/memory.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>
#include <vector>

namespace crypto_core::internal
{
namespace
{

[[nodiscard]] Error pss_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "rsa_pss", message);
}

[[nodiscard]] Result<ByteBuffer> digest(HashAlgorithm algorithm, std::span<const std::uint8_t> input)
{
	if (algorithm == HashAlgorithm::sha256)
	{
		Sha256Context context;
		auto update = context.update(input);
		if (!update)
		{
			return Result<ByteBuffer>::failure(update.error());
		}
		return context.final();
	}
	if (algorithm == HashAlgorithm::sha512)
	{
		Sha512Context context;
		auto update = context.update(input);
		if (!update)
		{
			return Result<ByteBuffer>::failure(update.error());
		}
		return context.final();
	}

	return Result<ByteBuffer>::failure(pss_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
}

void store_be32(std::uint32_t value, std::array<std::uint8_t, 4> &output) noexcept
{
	output[0] = static_cast<std::uint8_t>(value >> 24U);
	output[1] = static_cast<std::uint8_t>(value >> 16U);
	output[2] = static_cast<std::uint8_t>(value >> 8U);
	output[3] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] Result<ByteBuffer> mgf1(HashAlgorithm algorithm, std::span<const std::uint8_t> seed, std::size_t output_size)
{
	std::vector<std::uint8_t> output;
	output.reserve(output_size);

	for (std::uint32_t counter = 0; output.size() < output_size; ++counter)
	{
		std::array<std::uint8_t, 4> counter_bytes{};
		store_be32(counter, counter_bytes);

		std::vector<std::uint8_t> input;
		input.reserve(seed.size() + counter_bytes.size());
		input.insert(input.end(), seed.begin(), seed.end());
		input.insert(input.end(), counter_bytes.begin(), counter_bytes.end());

		auto block = digest(algorithm, input);
		if (!block)
		{
			return Result<ByteBuffer>::failure(block.error());
		}

		const auto take = std::min(block.value().size(), output_size - output.size());
		const auto block_bytes = block.value().bytes();
		output.insert(output.end(), block_bytes.begin(), block_bytes.begin() + static_cast<std::ptrdiff_t>(take));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

[[nodiscard]] Result<ByteBuffer> pss_hash(HashAlgorithm algorithm, std::span<const std::uint8_t> message_hash, std::span<const std::uint8_t> salt)
{
	std::vector<std::uint8_t> input(8, 0);
	input.insert(input.end(), message_hash.begin(), message_hash.end());
	input.insert(input.end(), salt.begin(), salt.end());
	return digest(algorithm, input);
}

} // namespace

Result<ByteBuffer> emsa_pss_encode(std::size_t encoded_bits, std::span<const std::uint8_t> message_hash, std::span<const std::uint8_t> salt, const RsaPssParams &params)
{
	const auto hash_size = digest_size(params.message_hash);
	if (hash_size == 0 || digest_size(params.mgf1_hash) == 0)
	{
		return Result<ByteBuffer>::failure(pss_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
	}
	if (message_hash.size() != hash_size)
	{
		return Result<ByteBuffer>::failure(pss_error(ErrorCode::invalid_argument, "message hash size does not match RSA-PSS hash algorithm"));
	}
	if (salt.size() != params.salt_length)
	{
		return Result<ByteBuffer>::failure(pss_error(ErrorCode::invalid_argument, "salt size does not match RSA-PSS salt length"));
	}

	const auto encoded_size = (encoded_bits + 7U) / 8U;
	if (encoded_size < hash_size + salt.size() + 2U)
	{
		return Result<ByteBuffer>::failure(pss_error(ErrorCode::invalid_argument, "RSA-PSS encoded message is too short for hash and salt"));
	}

	auto hash = pss_hash(params.message_hash, message_hash, salt);
	if (!hash)
	{
		return Result<ByteBuffer>::failure(hash.error());
	}

	const auto db_size = encoded_size - hash_size - 1U;
	const auto padding_size = encoded_size - salt.size() - hash_size - 2U;
	std::vector<std::uint8_t> db(db_size, 0);
	db[padding_size] = 0x01U;
	std::copy(salt.begin(), salt.end(), db.begin() + static_cast<std::ptrdiff_t>(padding_size + 1U));

	auto db_mask = mgf1(params.mgf1_hash, hash.value().bytes(), db_size);
	if (!db_mask)
	{
		return Result<ByteBuffer>::failure(db_mask.error());
	}

	for (std::size_t i = 0; i < db.size(); ++i)
	{
		db[i] ^= db_mask.value().bytes()[i];
	}

	const auto unused_bits = (8U * encoded_size) - encoded_bits;
	if (unused_bits > 0)
	{
		db[0] &= static_cast<std::uint8_t>(0xFFU >> unused_bits);
	}

	std::vector<std::uint8_t> encoded_message;
	encoded_message.reserve(encoded_size);
	encoded_message.insert(encoded_message.end(), db.begin(), db.end());
	const auto hash_bytes = hash.value().bytes();
	encoded_message.insert(encoded_message.end(), hash_bytes.begin(), hash_bytes.end());
	encoded_message.push_back(0xBCU);
	return Result<ByteBuffer>::success(ByteBuffer(std::move(encoded_message)));
}

Result<bool> emsa_pss_verify(std::span<const std::uint8_t> encoded_message, std::size_t encoded_bits, std::span<const std::uint8_t> message_hash, const RsaPssParams &params)
{
	const auto hash_size = digest_size(params.message_hash);
	if (hash_size == 0 || digest_size(params.mgf1_hash) == 0)
	{
		return Result<bool>::failure(pss_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
	}
	if (message_hash.size() != hash_size)
	{
		return Result<bool>::failure(pss_error(ErrorCode::invalid_argument, "message hash size does not match RSA-PSS hash algorithm"));
	}
	const auto expected_encoded_size = (encoded_bits + 7U) / 8U;
	if (encoded_message.size() != expected_encoded_size)
	{
		return Result<bool>::failure(pss_error(ErrorCode::invalid_argument, "encoded message size does not match encoded bit count"));
	}
	if (encoded_message.size() < hash_size + params.salt_length + 2U)
	{
		return Result<bool>::success(false);
	}
	std::uint8_t valid_mask = constant_time_is_zero(static_cast<std::uint8_t>(encoded_message.back() ^ 0xBCU));

	const auto masked_db_size = encoded_message.size() - hash_size - 1U;
	const auto masked_db = encoded_message.first(masked_db_size);
	const auto hash = encoded_message.subspan(masked_db_size, hash_size);
	const auto unused_bits = (8U * encoded_message.size()) - encoded_bits;
	if (unused_bits > 0)
	{
		const auto disallowed_mask = static_cast<std::uint8_t>(0xFFU << (8U - unused_bits));
		valid_mask &= constant_time_is_zero(static_cast<std::uint8_t>(masked_db.front() & disallowed_mask));
	}

	auto db_mask = mgf1(params.mgf1_hash, hash, masked_db_size);
	if (!db_mask)
	{
		return Result<bool>::failure(db_mask.error());
	}

	std::vector<std::uint8_t> db(masked_db_size);
	for (std::size_t i = 0; i < masked_db_size; ++i)
	{
		db[i] = masked_db[i] ^ db_mask.value().bytes()[i];
	}
	if (unused_bits > 0)
	{
		db[0] &= static_cast<std::uint8_t>(0xFFU >> unused_bits);
	}

	const auto padding_size = encoded_message.size() - hash_size - params.salt_length - 2U;
	std::uint8_t padding_diff = 0;
	for (std::size_t i = 0; i < padding_size; ++i)
	{
		padding_diff |= db[i];
	}
	valid_mask &= constant_time_is_zero(padding_diff);
	valid_mask &= constant_time_is_zero(static_cast<std::uint8_t>(db[padding_size] ^ 0x01U));

	auto expected_hash = pss_hash(params.message_hash, message_hash, std::span<const std::uint8_t>(db.data() + padding_size + 1U, params.salt_length));
	if (!expected_hash)
	{
		return Result<bool>::failure(expected_hash.error());
	}

	valid_mask &= constant_time_bool_mask(constant_time_equal(hash, expected_hash.value().bytes()));
	return Result<bool>::success(valid_mask == 0xFFU);
}

} // namespace crypto_core::internal
