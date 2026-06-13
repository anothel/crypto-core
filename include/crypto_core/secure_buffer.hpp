#pragma once

#include "crypto_core/memory.hpp"
#include "crypto_core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto_core
{

class SecureBuffer
{
public:
	SecureBuffer() = default;

	explicit SecureBuffer(std::size_t size)
	    : bytes_(size)
	{
	}

	explicit SecureBuffer(std::vector<std::uint8_t> bytes) noexcept
	    : bytes_(std::move(bytes))
	{
	}

	~SecureBuffer() noexcept
	{
		reset();
	}

	SecureBuffer(const SecureBuffer &) = delete;
	SecureBuffer &operator=(const SecureBuffer &) = delete;

	SecureBuffer(SecureBuffer &&other) noexcept
	    : bytes_(std::move(other.bytes_))
	{
		other.bytes_.clear();
	}

	SecureBuffer &operator=(SecureBuffer &&other) noexcept
	{
		if (this != &other)
		{
			reset();
			bytes_ = std::move(other.bytes_);
			other.bytes_.clear();
		}

		return *this;
	}

	[[nodiscard]] static Result<SecureBuffer> copy_from(std::span<const std::uint8_t> bytes)
	{
		return Result<SecureBuffer>::success(
		    SecureBuffer(std::vector<std::uint8_t>(bytes.begin(), bytes.end())));
	}

	[[nodiscard]] Result<SecureBuffer> clone() const
	{
		return copy_from(bytes_);
	}

	void reset() noexcept
	{
		secure_zero_memory(bytes_.data(), bytes_.size());
		bytes_.clear();
	}

	[[nodiscard]] std::span<std::uint8_t> bytes() noexcept
	{
		return bytes_;
	}

	[[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
	{
		return bytes_;
	}

	[[nodiscard]] std::uint8_t *data() noexcept
	{
		return bytes_.data();
	}

	[[nodiscard]] const std::uint8_t *data() const noexcept
	{
		return bytes_.data();
	}

	[[nodiscard]] std::size_t size() const noexcept
	{
		return bytes_.size();
	}

	[[nodiscard]] bool empty() const noexcept
	{
		return bytes_.empty();
	}

private:
	std::vector<std::uint8_t> bytes_;
};

static_assert(!std::is_copy_constructible_v<SecureBuffer>);
static_assert(!std::is_copy_assignable_v<SecureBuffer>);
static_assert(std::is_move_constructible_v<SecureBuffer>);
static_assert(std::is_move_assignable_v<SecureBuffer>);

} // namespace crypto_core
