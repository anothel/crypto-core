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
