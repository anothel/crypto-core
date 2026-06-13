#include "crypto_core/internal/os_rng.hpp"

#include <limits>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <windows.h>
#endif

namespace crypto_core::internal
{

Result<void> OsRng::generate(std::span<std::uint8_t> output) noexcept
{
	if (output.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "rng", "random output must not be empty"));
	}

#if defined(_WIN32)
	if (output.size() > static_cast<std::size_t>(std::numeric_limits<ULONG>::max()))
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "rng", "random output is too large for Windows BCryptGenRandom"));
	}

	const auto status = BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status < 0)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "BCryptGenRandom failed"));
	}

	return Result<void>::success();
#else
	return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "OS RNG is not implemented on this platform"));
#endif
}

} // namespace crypto_core::internal
