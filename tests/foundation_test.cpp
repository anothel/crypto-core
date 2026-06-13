#include "crypto_core/crypto_core.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

void test_error()
{
	constexpr crypto_core::Error ok;
	assert(ok.ok());
	assert(ok.code() == crypto_core::ErrorCode::ok);
	assert(ok.category() == std::string_view{"core"});
	assert(ok.message() == std::string_view{"ok"});

	constexpr auto error = crypto_core::make_error(
	    crypto_core::ErrorCode::invalid_argument,
	    "foundation",
	    "bad input");
	assert(!error.ok());
	assert(error.code() == crypto_core::ErrorCode::invalid_argument);
	assert(error.category() == std::string_view{"foundation"});
	assert(error.message() == std::string_view{"bad input"});
	assert(crypto_core::error_code_name(error.code()) == std::string_view{"invalid_argument"});
}

void test_result()
{
	auto value = crypto_core::Result<int>::success(42);
	assert(value);
	assert(value.has_value());
	assert(value.value() == 42);
	assert(value.error().ok());

	auto failure = crypto_core::Result<int>::failure(crypto_core::make_error(
	    crypto_core::ErrorCode::provider_error,
	    "provider",
	    "provider failed"));
	assert(!failure);
	assert(!failure.has_value());
	assert(failure.error().code() == crypto_core::ErrorCode::provider_error);

	auto void_ok = crypto_core::Result<void>::success();
	assert(void_ok);
	assert(void_ok.error().ok());

	auto void_failure = crypto_core::Result<void>::failure(crypto_core::make_error(
	    crypto_core::ErrorCode::authentication_failed,
	    "aead",
	    "tag mismatch"));
	assert(!void_failure);
	assert(void_failure.error().code() == crypto_core::ErrorCode::authentication_failed);
}

void test_memory_helpers()
{
	std::array<std::uint8_t, 4> bytes{1, 2, 3, 4};
	crypto_core::secure_zero_memory(bytes.data(), bytes.size());
	assert((bytes == std::array<std::uint8_t, 4>{0, 0, 0, 0}));

	const std::array<std::uint8_t, 3> lhs{1, 2, 3};
	const std::array<std::uint8_t, 3> same{1, 2, 3};
	const std::array<std::uint8_t, 3> different{1, 2, 4};
	const std::array<std::uint8_t, 2> shorter{1, 2};

	assert(crypto_core::constant_time_equal(lhs, same));
	assert(!crypto_core::constant_time_equal(lhs, different));
	assert(!crypto_core::constant_time_equal(lhs, shorter));
}

void test_byte_buffer()
{
	const std::array<std::uint8_t, 3> input{9, 8, 7};
	auto buffer = crypto_core::ByteBuffer::copy_from(input);
	assert(buffer.size() == 3);
	assert(!buffer.empty());
	assert(buffer.bytes()[0] == 9);
	assert(buffer.bytes()[1] == 8);
	assert(buffer.bytes()[2] == 7);

	auto copy = buffer;
	assert(copy == buffer);
	copy.bytes()[0] = 1;
	assert(copy != buffer);

	crypto_core::ByteBuffer moved(std::vector<std::uint8_t>{1, 2, 3});
	assert(moved.size() == 3);
}

void test_secure_buffer()
{
	static_assert(!std::is_copy_constructible_v<crypto_core::SecureBuffer>);
	static_assert(!std::is_copy_assignable_v<crypto_core::SecureBuffer>);
	static_assert(std::is_move_constructible_v<crypto_core::SecureBuffer>);
	static_assert(std::is_move_assignable_v<crypto_core::SecureBuffer>);

	const std::array<std::uint8_t, 4> secret_bytes{4, 3, 2, 1};
	auto secret = crypto_core::SecureBuffer::copy_from(secret_bytes);
	assert(secret);
	assert(secret.value().size() == 4);
	assert(crypto_core::constant_time_equal(secret.value().bytes(), secret_bytes));

	auto clone = secret.value().clone();
	assert(clone);
	assert(crypto_core::constant_time_equal(clone.value().bytes(), secret_bytes));

	auto moved = std::move(secret.value());
	assert(moved.size() == 4);
	assert(crypto_core::constant_time_equal(moved.bytes(), secret_bytes));

	moved.reset();
	assert(moved.empty());
}

int main()
{
	test_error();
	test_result();
	test_memory_helpers();
	test_byte_buffer();
	test_secure_buffer();
	return 0;
}
