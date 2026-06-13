#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace crypto_core
{

class ByteBuffer
{
public:
	using value_type = std::uint8_t;

	ByteBuffer() = default;

	explicit ByteBuffer(std::vector<std::uint8_t> bytes) noexcept
	    : bytes_(std::move(bytes))
	{
	}

	[[nodiscard]] static ByteBuffer copy_from(std::span<const std::uint8_t> bytes)
	{
		return ByteBuffer(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
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

[[nodiscard]] inline bool operator==(const ByteBuffer &lhs, const ByteBuffer &rhs) noexcept
{
	return lhs.bytes().size() == rhs.bytes().size() && std::equal(lhs.bytes().begin(), lhs.bytes().end(), rhs.bytes().begin());
}

[[nodiscard]] inline bool operator!=(const ByteBuffer &lhs, const ByteBuffer &rhs) noexcept
{
	return !(lhs == rhs);
}

} // namespace crypto_core
