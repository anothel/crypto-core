#include "crypto_core/internal/os_rng.hpp"

#include <algorithm>
#include <cstddef>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <windows.h>
#elif defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <stdlib.h>
#endif

namespace crypto_core::internal
{
namespace
{

constexpr std::size_t rng_chunk_size = 1024 * 1024;

Result<void> fill_os_random_chunk(std::span<std::uint8_t> output) noexcept
{
	if (output.empty())
	{
		return Result<void>::success();
	}

#if defined(_WIN32)
	const auto status = BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status < 0)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "BCryptGenRandom failed"));
	}

	return Result<void>::success();
#elif defined(__linux__)
	auto remaining = output;
	while (!remaining.empty())
	{
		const auto generated = getrandom(remaining.data(), remaining.size(), 0);
		if (generated < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "getrandom failed"));
		}
		if (generated == 0)
		{
			return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "getrandom returned no data"));
		}
		remaining = remaining.subspan(static_cast<std::size_t>(generated));
	}

	return Result<void>::success();
#elif defined(__APPLE__)
	if (SecRandomCopyBytes(kSecRandomDefault, output.size(), output.data()) != errSecSuccess)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "SecRandomCopyBytes failed"));
	}

	return Result<void>::success();
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
	arc4random_buf(output.data(), output.size());
	return Result<void>::success();
#else
	return Result<void>::failure(make_error(ErrorCode::provider_error, "rng", "OS RNG is not implemented on this platform"));
#endif
}

} // namespace

Result<void> OsRng::generate(std::span<std::uint8_t> output) noexcept
{
	std::size_t offset = 0;
	while (offset < output.size())
	{
		const auto remaining = output.size() - offset;
		const auto chunk_size = std::min(remaining, rng_chunk_size);
		auto generated = fill_os_random_chunk(output.subspan(offset, chunk_size));
		if (!generated)
		{
			return Result<void>::failure(generated.error());
		}
		offset += chunk_size;
	}

	return Result<void>::success();
}

} // namespace crypto_core::internal
