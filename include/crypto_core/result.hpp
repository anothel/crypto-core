#pragma once

#include "crypto_core/error.hpp"

#include <optional>
#include <type_traits>
#include <utility>

namespace crypto_core
{

template <typename T>
class Result
{
public:
	static_assert(!std::is_void_v<T>, "Use Result<void> for void results");

	[[nodiscard]] static Result success(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
	{
		return Result(std::move(value));
	}

	[[nodiscard]] static Result failure(Error error) noexcept
	{
		return Result(error);
	}

	[[nodiscard]] bool has_value() const noexcept
	{
		return value_.has_value();
	}

	[[nodiscard]] explicit operator bool() const noexcept
	{
		return has_value();
	}

	[[nodiscard]] T &value() & noexcept
	{
		return *value_;
	}

	[[nodiscard]] const T &value() const & noexcept
	{
		return *value_;
	}

	[[nodiscard]] T &&value() && noexcept
	{
		return std::move(*value_);
	}

	[[nodiscard]] const Error &error() const noexcept
	{
		return error_;
	}

private:
	explicit Result(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
	    : value_(std::move(value))
	{
	}

	explicit Result(Error error) noexcept
	    : value_(std::nullopt), error_(error)
	{
	}

	std::optional<T> value_;
	Error error_{};
};

template <>
class Result<void>
{
public:
	[[nodiscard]] static Result success() noexcept
	{
		return Result();
	}

	[[nodiscard]] static Result failure(Error error) noexcept
	{
		return Result(error);
	}

	[[nodiscard]] bool has_value() const noexcept
	{
		return error_.ok();
	}

	[[nodiscard]] explicit operator bool() const noexcept
	{
		return has_value();
	}

	[[nodiscard]] const Error &error() const noexcept
	{
		return error_;
	}

private:
	Result() noexcept = default;

	explicit Result(Error error) noexcept
	    : error_(error)
	{
	}

	Error error_{};
};

} // namespace crypto_core
