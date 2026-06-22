#include "crypto_core/crypto_core.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

class CountingRng final : public crypto_core::IRng
{
public:
	crypto_core::Result<void> generate(std::span<std::uint8_t> output) noexcept override
	{
		for (auto &byte : output)
		{
			byte = next_++;
		}
		return crypto_core::Result<void>::success();
	}

private:
	std::uint8_t next_{0};
};

class FailingRng final : public crypto_core::IRng
{
public:
	crypto_core::Result<void> generate(std::span<std::uint8_t>) noexcept override
	{
		return crypto_core::Result<void>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::provider_error, "test", "rng generation failed"));
	}
};

class DeterministicRngProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "DeterministicRngProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	bool supports(crypto_core::RngAlgorithm algorithm) const noexcept override
	{
		return algorithm == crypto_core::RngAlgorithm::os_random;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "test", "hash unsupported"));
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IRng>> create_rng(crypto_core::RngAlgorithm algorithm) noexcept override
	{
		requested_algorithm = algorithm;
		++create_rng_calls;
		return crypto_core::Result<std::unique_ptr<crypto_core::IRng>>::success(std::make_unique<CountingRng>());
	}

	crypto_core::RngAlgorithm requested_algorithm{crypto_core::RngAlgorithm::os_random};
	int create_rng_calls{0};
};

class FailingCreateRngProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "FailingCreateRngProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "test", "hash unsupported"));
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IRng>> create_rng(crypto_core::RngAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IRng>>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::provider_error, "test", "rng creation failed"));
	}
};

class FailingGenerateRngProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "FailingGenerateRngProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(
		    crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "test", "hash unsupported"));
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IRng>> create_rng(crypto_core::RngAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IRng>>::success(std::make_unique<FailingRng>());
	}
};

void test_rng_algorithm_metadata()
{
	require(std::string_view{crypto_core::rng_algorithm_name(crypto_core::RngAlgorithm::os_random)} == std::string_view{"OS-RANDOM"});
}

void test_native_provider_supports_rng()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::RngAlgorithm::os_random));
}

void test_random_bytes_uses_explicit_provider()
{
	DeterministicRngProvider provider;
	auto bytes = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, 4);
	require(bytes.has_value());
	require(provider.create_rng_calls == 1);
	require(provider.requested_algorithm == crypto_core::RngAlgorithm::os_random);
	require((bytes.value() == crypto_core::ByteBuffer(std::vector<std::uint8_t>{0, 1, 2, 3})));
}

void test_random_fill_uses_explicit_provider()
{
	DeterministicRngProvider provider;
	std::vector<std::uint8_t> output(6);
	auto result = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, output);
	require(result.has_value());
	require((output == std::vector<std::uint8_t>{0, 1, 2, 3, 4, 5}));
}

void test_random_bytes_accepts_zero_size()
{
	DeterministicRngProvider provider;
	auto bytes = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, 0);
	require(bytes.has_value());
	require(bytes.value().empty());
	require(provider.create_rng_calls == 0);
}

void test_random_fill_accepts_empty_output_without_creating_rng()
{
	DeterministicRngProvider provider;
	std::vector<std::uint8_t> output;
	auto result = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, output);
	require(result.has_value());
	require(provider.create_rng_calls == 0);
}

void test_random_bytes_propagates_provider_creation_failure()
{
	FailingCreateRngProvider provider;
	auto bytes = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, 4);
	require(!bytes.has_value());
	require(bytes.error().code() == crypto_core::ErrorCode::provider_error);
}

void test_random_fill_propagates_rng_generation_failure()
{
	FailingGenerateRngProvider provider;
	std::vector<std::uint8_t> output(4);
	auto result = crypto_core::random_bytes(provider, crypto_core::RngAlgorithm::os_random, output);
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::provider_error);
}

void test_default_provider_generates_requested_size()
{
	auto bytes = crypto_core::random_bytes(crypto_core::RngAlgorithm::os_random, 32);
	require(bytes.has_value());
	require(bytes.value().size() == 32);
}

void test_default_provider_accepts_empty_output()
{
	std::vector<std::uint8_t> output;
	auto result = crypto_core::random_bytes(crypto_core::RngAlgorithm::os_random, output);
	require(result.has_value());
}

void test_default_provider_large_request_succeeds()
{
	constexpr std::size_t large_size = (1024 * 1024) + 1;
	auto bytes = crypto_core::random_bytes(crypto_core::RngAlgorithm::os_random, large_size);
	require(bytes.has_value());
	require(bytes.value().size() == large_size);
}

void test_default_provider_outputs_change_between_calls()
{
	auto first = crypto_core::random_bytes(crypto_core::RngAlgorithm::os_random, 32);
	auto second = crypto_core::random_bytes(crypto_core::RngAlgorithm::os_random, 32);
	require(first.has_value());
	require(second.has_value());
	require(first.value() != second.value());
}

} // namespace

int main()
{
	test_rng_algorithm_metadata();
	test_native_provider_supports_rng();
	test_random_bytes_uses_explicit_provider();
	test_random_fill_uses_explicit_provider();
	test_random_bytes_accepts_zero_size();
	test_random_fill_accepts_empty_output_without_creating_rng();
	test_random_bytes_propagates_provider_creation_failure();
	test_random_fill_propagates_rng_generation_failure();
	test_default_provider_generates_requested_size();
	test_default_provider_accepts_empty_output();
	test_default_provider_large_request_succeeds();
	test_default_provider_outputs_change_between_calls();
	return 0;
}
