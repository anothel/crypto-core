#include "crypto_core/crypto_core.hpp"

#include <array>
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

} // namespace

void test_hash_algorithm_metadata()
{
	require(crypto_core::digest_size(crypto_core::HashAlgorithm::sha256) == 32);
	require(crypto_core::digest_size(crypto_core::HashAlgorithm::sha512) == 64);
	require(std::string_view{crypto_core::hash_algorithm_name(crypto_core::HashAlgorithm::sha256)} == std::string_view{"SHA256"});
	require(std::string_view{crypto_core::hash_algorithm_name(crypto_core::HashAlgorithm::sha512)} == std::string_view{"SHA512"});
}

class RecordingHashContext final : public crypto_core::IHashContext
{
public:
	explicit RecordingHashContext(std::vector<std::uint8_t> *updates)
	    : updates_(updates)
	{
	}

	crypto_core::Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		updates_->insert(updates_->end(), input.begin(), input.end());
		return crypto_core::Result<void>::success();
	}

	crypto_core::Result<crypto_core::ByteBuffer> final() noexcept override
	{
		return crypto_core::Result<crypto_core::ByteBuffer>::success(crypto_core::ByteBuffer(std::vector<std::uint8_t>{1, 2, 3}));
	}

private:
	std::vector<std::uint8_t> *updates_;
};

class RecordingProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "RecordingProvider";
	}

	bool supports(crypto_core::HashAlgorithm algorithm) const noexcept override
	{
		return algorithm == crypto_core::HashAlgorithm::sha256;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm algorithm) noexcept override
	{
		requested_algorithm = algorithm;
		++create_hash_calls;
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<RecordingHashContext>(&updates));
	}

	crypto_core::HashAlgorithm requested_algorithm{crypto_core::HashAlgorithm::sha512};
	int create_hash_calls{0};
	std::vector<std::uint8_t> updates;
};

class FailingCreateProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "FailingCreateProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "provider", "hash algorithm is not supported"));
	}
};

void test_native_provider_default_behavior()
{
	crypto_core::NativeProvider native;
	require(native.name() == std::string_view{"NativeProvider"});
	require(native.supports(crypto_core::HashAlgorithm::sha256));
	require(native.supports(crypto_core::HashAlgorithm::sha512));

	auto sha256 = native.create_hash(crypto_core::HashAlgorithm::sha256);
	auto sha512 = native.create_hash(crypto_core::HashAlgorithm::sha512);
	require(sha256.has_value());
	require(sha512.has_value());

	auto &default_provider = crypto_core::default_provider();
	require(default_provider.name() == std::string_view{"NativeProvider"});
	require(&default_provider == &crypto_core::default_provider());
}

void test_hash_wrapper_uses_explicit_provider()
{
	RecordingProvider provider;
	const std::array<std::uint8_t, 4> input{9, 8, 7, 6};

	auto digest = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, input);
	require(digest.has_value());
	require(provider.create_hash_calls == 1);
	require(provider.requested_algorithm == crypto_core::HashAlgorithm::sha256);
	require((provider.updates == std::vector<std::uint8_t>{9, 8, 7, 6}));
	require((digest.value() == crypto_core::ByteBuffer(std::vector<std::uint8_t>{1, 2, 3})));
}

void test_hash_wrapper_returns_provider_error()
{
	FailingCreateProvider provider;
	const std::array<std::uint8_t, 1> input{0};

	auto digest = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, input);
	require(!digest.has_value());
	require(digest.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

void test_default_hash_uses_native_provider()
{
	const std::array<std::uint8_t, 3> input{1, 2, 3};

	auto digest = crypto_core::hash(crypto_core::HashAlgorithm::sha256, input);
	require(digest.has_value());
	require(digest.value().size() == crypto_core::digest_size(crypto_core::HashAlgorithm::sha256));
}

int main()
{
	test_hash_algorithm_metadata();
	test_native_provider_default_behavior();
	test_hash_wrapper_uses_explicit_provider();
	test_hash_wrapper_returns_provider_error();
	test_default_hash_uses_native_provider();
	return 0;
}
