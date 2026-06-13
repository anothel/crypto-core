#pragma once

#include <string_view>

namespace crypto_core
{

enum class ErrorCode
{
	ok = 0,
	invalid_argument,
	unsupported_algorithm,
	invalid_key,
	authentication_failed,
	provider_error,
	internal_error,
};

constexpr std::string_view error_code_name(ErrorCode code) noexcept
{
	switch (code)
	{
	case ErrorCode::ok:
		return "ok";
	case ErrorCode::invalid_argument:
		return "invalid_argument";
	case ErrorCode::unsupported_algorithm:
		return "unsupported_algorithm";
	case ErrorCode::invalid_key:
		return "invalid_key";
	case ErrorCode::authentication_failed:
		return "authentication_failed";
	case ErrorCode::provider_error:
		return "provider_error";
	case ErrorCode::internal_error:
		return "internal_error";
	}

	return "unknown";
}

class Error
{
public:
	constexpr Error() noexcept = default;

	constexpr Error(ErrorCode code, std::string_view category, std::string_view message) noexcept
	    : code_(code), category_(category), message_(message)
	{
	}

	[[nodiscard]] constexpr ErrorCode code() const noexcept
	{
		return code_;
	}

	[[nodiscard]] constexpr std::string_view category() const noexcept
	{
		return category_;
	}

	[[nodiscard]] constexpr std::string_view message() const noexcept
	{
		return message_;
	}

	[[nodiscard]] constexpr bool ok() const noexcept
	{
		return code_ == ErrorCode::ok;
	}

private:
	ErrorCode code_{ErrorCode::ok};
	std::string_view category_{"core"};
	std::string_view message_{"ok"};
};

[[nodiscard]] constexpr Error make_error(
    ErrorCode code,
    std::string_view category,
    std::string_view message) noexcept
{
	return Error{code, category, message};
}

} // namespace crypto_core
