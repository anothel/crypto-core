#include "crypto_core/internal/rsa_oaep.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/sha2.hpp"
#include "crypto_core/memory.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto_core::internal
{
namespace
{

[[nodiscard]] Error oaep_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "rsa_oaep", message);
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

	return Result<ByteBuffer>::failure(oaep_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
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

} // namespace

Result<ByteBuffer> eme_oaep_encode(std::size_t encoded_size, std::span<const std::uint8_t> message, std::span<const std::uint8_t> seed, const RsaOaepParams &params)
{
	const auto hash_size = digest_size(params.message_hash);
	if (hash_size == 0 || digest_size(params.mgf1_hash) == 0)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
	}
	if (seed.size() != hash_size)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::invalid_argument, "seed size does not match RSA-OAEP hash algorithm"));
	}
	if (encoded_size < (2U * hash_size) + 2U)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::invalid_argument, "RSA-OAEP encoded message is too short"));
	}
	if (message.size() > encoded_size - (2U * hash_size) - 2U)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::invalid_argument, "RSA-OAEP message is too large"));
	}

	auto label_hash = digest(params.message_hash, params.label.bytes());
	if (!label_hash)
	{
		return Result<ByteBuffer>::failure(label_hash.error());
	}
	const auto label_hash_bytes = label_hash.value().bytes();

	const auto db_size = encoded_size - hash_size - 1U;
	std::vector<std::uint8_t> db;
	db.reserve(db_size);
	db.insert(db.end(), label_hash_bytes.begin(), label_hash_bytes.end());
	db.resize(db_size - message.size() - 1U, 0);
	db.push_back(0x01U);
	db.insert(db.end(), message.begin(), message.end());

	auto db_mask = mgf1(params.mgf1_hash, seed, db_size);
	if (!db_mask)
	{
		return Result<ByteBuffer>::failure(db_mask.error());
	}
	for (std::size_t i = 0; i < db.size(); ++i)
	{
		db[i] ^= db_mask.value().bytes()[i];
	}

	auto seed_mask = mgf1(params.mgf1_hash, db, hash_size);
	if (!seed_mask)
	{
		return Result<ByteBuffer>::failure(seed_mask.error());
	}

	std::vector<std::uint8_t> masked_seed(hash_size);
	for (std::size_t i = 0; i < hash_size; ++i)
	{
		masked_seed[i] = seed[i] ^ seed_mask.value().bytes()[i];
	}

	std::vector<std::uint8_t> encoded_message;
	encoded_message.reserve(encoded_size);
	encoded_message.push_back(0);
	encoded_message.insert(encoded_message.end(), masked_seed.begin(), masked_seed.end());
	encoded_message.insert(encoded_message.end(), db.begin(), db.end());
	return Result<ByteBuffer>::success(ByteBuffer(std::move(encoded_message)));
}

Result<ByteBuffer> eme_oaep_decode(std::span<const std::uint8_t> encoded_message, const RsaOaepParams &params)
{
	const auto hash_size = digest_size(params.message_hash);
	if (hash_size == 0 || digest_size(params.mgf1_hash) == 0)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::unsupported_algorithm, "hash algorithm is not supported"));
	}
	if (encoded_message.size() < (2U * hash_size) + 2U)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::authentication_failed, "RSA-OAEP encoded message is invalid"));
	}

	const auto masked_seed = encoded_message.subspan(1U, hash_size);
	const auto masked_db = encoded_message.subspan(1U + hash_size);

	auto seed_mask = mgf1(params.mgf1_hash, masked_db, hash_size);
	if (!seed_mask)
	{
		return Result<ByteBuffer>::failure(seed_mask.error());
	}
	std::vector<std::uint8_t> seed(hash_size);
	for (std::size_t i = 0; i < hash_size; ++i)
	{
		seed[i] = masked_seed[i] ^ seed_mask.value().bytes()[i];
	}

	auto db_mask = mgf1(params.mgf1_hash, seed, masked_db.size());
	if (!db_mask)
	{
		return Result<ByteBuffer>::failure(db_mask.error());
	}
	std::vector<std::uint8_t> db(masked_db.size());
	for (std::size_t i = 0; i < db.size(); ++i)
	{
		db[i] = masked_db[i] ^ db_mask.value().bytes()[i];
	}

	auto label_hash = digest(params.message_hash, params.label.bytes());
	if (!label_hash)
	{
		return Result<ByteBuffer>::failure(label_hash.error());
	}

	const auto label_hash_bytes = label_hash.value().bytes();
	const bool label_matches = constant_time_equal(std::span<const std::uint8_t>(db.data(), hash_size), label_hash_bytes);
	bool valid = encoded_message[0] == 0;
	valid = valid && label_matches;

	std::size_t separator = db.size();
	for (std::size_t i = hash_size; i < db.size(); ++i)
	{
		if (separator == db.size() && db[i] == 0x01U)
		{
			separator = i;
		}
		else if (separator == db.size() && db[i] != 0)
		{
			valid = false;
		}
	}
	if (separator == db.size())
	{
		valid = false;
	}
	if (!valid)
	{
		return Result<ByteBuffer>::failure(oaep_error(ErrorCode::authentication_failed, "RSA-OAEP encoded message is invalid"));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::vector<std::uint8_t>(db.begin() + static_cast<std::ptrdiff_t>(separator + 1U), db.end())));
}

} // namespace crypto_core::internal
