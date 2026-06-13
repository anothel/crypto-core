#include "crypto_core/internal/hmac.hpp"

#include "crypto_core/internal/sha2.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace crypto_core::internal
{
namespace
{

std::size_t block_size(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return 64;
	case HashAlgorithm::sha512:
		return 128;
	}

	return 0;
}

std::unique_ptr<IHashContext> make_hash_context(HashAlgorithm algorithm)
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return std::make_unique<Sha256Context>();
	case HashAlgorithm::sha512:
		return std::make_unique<Sha512Context>();
	}

	return nullptr;
}

Result<ByteBuffer> hash_once(HashAlgorithm algorithm, std::span<const std::uint8_t> input) noexcept
{
	auto context = make_hash_context(algorithm);
	if (context == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "hmac", "hash algorithm is not supported"));
	}

	auto update_result = context->update(input);
	if (!update_result)
	{
		return Result<ByteBuffer>::failure(update_result.error());
	}

	return context->final();
}

} // namespace

HmacContext::HmacContext(HashAlgorithm hash_algorithm, std::span<const std::uint8_t> key) noexcept
    : hash_algorithm_(hash_algorithm)
{
	const auto size = block_size(hash_algorithm_);
	if (size == 0)
	{
		return;
	}

	std::vector<std::uint8_t> normalized_key;
	if (key.size() > size)
	{
		auto hashed_key = hash_once(hash_algorithm_, key);
		if (!hashed_key)
		{
			return;
		}
		normalized_key.assign(hashed_key.value().bytes().begin(), hashed_key.value().bytes().end());
	}
	else
	{
		normalized_key.assign(key.begin(), key.end());
	}

	normalized_key.resize(size, std::uint8_t{0});
	std::vector<std::uint8_t> inner_pad(size);
	outer_pad_.resize(size);
	for (std::size_t i = 0; i < size; ++i)
	{
		inner_pad[i] = static_cast<std::uint8_t>(normalized_key[i] ^ 0x36U);
		outer_pad_[i] = static_cast<std::uint8_t>(normalized_key[i] ^ 0x5cU);
	}

	inner_ = make_hash_context(hash_algorithm_);
	if (inner_ == nullptr)
	{
		return;
	}

	initialized_ = inner_->update(inner_pad).has_value();
}

bool HmacContext::initialized() const noexcept
{
	return initialized_;
}

Result<void> HmacContext::update(std::span<const std::uint8_t> input) noexcept
{
	if (finalized_)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "hmac", "cannot update finalized MAC context"));
	}
	if (!initialized_)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "hmac", "MAC context is not initialized"));
	}

	return inner_->update(input);
}

Result<ByteBuffer> HmacContext::final() noexcept
{
	if (finalized_)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "hmac", "MAC context is already finalized"));
	}
	if (!initialized_)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "hmac", "MAC context is not initialized"));
	}

	finalized_ = true;
	auto inner_digest = inner_->final();
	if (!inner_digest)
	{
		return inner_digest;
	}

	auto outer = make_hash_context(hash_algorithm_);
	if (outer == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "hmac", "hash algorithm is not supported"));
	}

	auto outer_pad_update = outer->update(outer_pad_);
	if (!outer_pad_update)
	{
		return Result<ByteBuffer>::failure(outer_pad_update.error());
	}

	auto inner_digest_update = outer->update(inner_digest.value().bytes());
	if (!inner_digest_update)
	{
		return Result<ByteBuffer>::failure(inner_digest_update.error());
	}

	return outer->final();
}

} // namespace crypto_core::internal
