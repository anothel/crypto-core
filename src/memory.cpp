#include "crypto_core/memory.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace crypto_core
{

void secure_zero_memory(void *data, std::size_t size) noexcept
{
	if (data == nullptr || size == 0)
	{
		return;
	}

#if defined(_WIN32)
	SecureZeroMemory(data, size);
#else
	auto *cursor = static_cast<volatile std::uint8_t *>(data);
	while (size != 0)
	{
		*cursor = 0;
		++cursor;
		--size;
	}
#endif
}

std::uint8_t constant_time_bool_mask(bool value) noexcept
{
	return static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>(value));
}

std::uint8_t constant_time_is_zero(std::uint8_t value) noexcept
{
	const auto wide = static_cast<std::uint32_t>(value);
	const auto non_zero = (wide | (0U - wide)) >> 31U;
	return static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>(non_zero ^ 1U));
}

std::uint8_t constant_time_select(std::uint8_t mask, std::uint8_t if_set, std::uint8_t if_clear) noexcept
{
	const auto canonical_mask = static_cast<std::uint8_t>(0U - static_cast<std::uint8_t>((mask >> 7U) & 1U));
	return static_cast<std::uint8_t>((if_set & canonical_mask) | (if_clear & static_cast<std::uint8_t>(~canonical_mask)));
}

std::size_t constant_time_select_size(std::uint8_t mask, std::size_t if_set, std::size_t if_clear) noexcept
{
	const auto canonical_mask = static_cast<std::size_t>(0U - static_cast<std::size_t>((mask >> 7U) & 1U));
	return (if_set & canonical_mask) | (if_clear & ~canonical_mask);
}

bool constant_time_equal(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs) noexcept
{
	if (lhs.size() != rhs.size())
	{
		return false;
	}

	std::uint8_t diff = 0;
	for (std::size_t i = 0; i < lhs.size(); ++i)
	{
		diff |= static_cast<std::uint8_t>(lhs[i] ^ rhs[i]);
	}

	return diff == 0;
}

} // namespace crypto_core
