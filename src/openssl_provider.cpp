#include "crypto_core/openssl_provider.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace crypto_core
{
namespace
{

const EVP_MD *evp_md(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return EVP_sha256();
	case HashAlgorithm::sha512:
		return EVP_sha512();
	}

	return nullptr;
}

const char *evp_mac_digest(MacAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case MacAlgorithm::hmac_sha256:
		return "SHA256";
	case MacAlgorithm::hmac_sha512:
		return "SHA512";
	}

	return nullptr;
}

class OpenSSLHashContext final : public IHashContext
{
public:
	explicit OpenSSLHashContext(const EVP_MD *md) noexcept
	    : context_(EVP_MD_CTX_new())
	{
		if (context_ != nullptr)
		{
			initialized_ = EVP_DigestInit_ex(context_, md, nullptr) == 1;
		}
	}

	~OpenSSLHashContext() override
	{
		EVP_MD_CTX_free(context_);
	}

	[[nodiscard]] bool initialized() const noexcept
	{
		return initialized_;
	}

	Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		if (finalized_)
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "cannot update finalized hash context"));
		}
		if (!initialized_ || EVP_DigestUpdate(context_, input.data(), input.size()) != 1)
		{
			return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestUpdate failed"));
		}
		return Result<void>::success();
	}

	Result<ByteBuffer> final() noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "hash context is already finalized"));
		}

		finalized_ = true;
		if (!initialized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "hash context is not initialized"));
		}

		const int expected_size = EVP_MD_CTX_get_size(context_);
		if (expected_size <= 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_get_size failed"));
		}

		std::vector<std::uint8_t> digest(static_cast<std::size_t>(expected_size));
		unsigned int digest_size = 0;
		if (EVP_DigestFinal_ex(context_, digest.data(), &digest_size) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestFinal_ex failed"));
		}

		digest.resize(digest_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
	}

private:
	EVP_MD_CTX *context_{nullptr};
	bool initialized_{false};
	bool finalized_{false};
};

class OpenSSLMacContext final : public IMacContext
{
public:
	OpenSSLMacContext(const char *digest, std::span<const std::uint8_t> key, std::size_t output_size) noexcept
	    : mac_(EVP_MAC_fetch(nullptr, "HMAC", nullptr)), context_(mac_ == nullptr ? nullptr : EVP_MAC_CTX_new(mac_)), output_size_(output_size)
	{
		if (context_ != nullptr)
		{
			OSSL_PARAM params[] = {
			    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(digest), 0),
			    OSSL_PARAM_construct_end(),
			};
			initialized_ = EVP_MAC_init(context_, key.data(), key.size(), params) == 1;
		}
	}

	~OpenSSLMacContext() override
	{
		EVP_MAC_CTX_free(context_);
		EVP_MAC_free(mac_);
	}

	[[nodiscard]] bool initialized() const noexcept
	{
		return initialized_;
	}

	Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		if (finalized_)
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "cannot update finalized MAC context"));
		}
		if (!initialized_ || EVP_MAC_update(context_, input.data(), input.size()) != 1)
		{
			return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_update failed"));
		}
		return Result<void>::success();
	}

	Result<ByteBuffer> final() noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "MAC context is already finalized"));
		}
		if (!initialized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "MAC context is not initialized"));
		}

		finalized_ = true;
		std::vector<std::uint8_t> digest(output_size_);
		std::size_t digest_size = 0;
		if (EVP_MAC_final(context_, digest.data(), &digest_size, digest.size()) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_final failed"));
		}

		digest.resize(digest_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
	}

private:
	EVP_MAC *mac_{nullptr};
	EVP_MAC_CTX *context_{nullptr};
	std::size_t output_size_{0};
	bool initialized_{false};
	bool finalized_{false};
};

} // namespace

std::string_view OpenSSLProvider::name() const noexcept
{
	return "OpenSSLProvider";
}

bool OpenSSLProvider::supports(HashAlgorithm algorithm) const noexcept
{
	return evp_md(algorithm) != nullptr;
}

bool OpenSSLProvider::supports(MacAlgorithm algorithm) const noexcept
{
	return evp_mac_digest(algorithm) != nullptr;
}

Result<std::unique_ptr<IHashContext>> OpenSSLProvider::create_hash(HashAlgorithm algorithm) noexcept
{
	const EVP_MD *md = evp_md(algorithm);
	if (md == nullptr)
	{
		return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "hash algorithm is not supported by OpenSSLProvider"));
	}

	auto context = std::make_unique<OpenSSLHashContext>(md);
	if (!context->initialized())
	{
		return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestInit_ex failed"));
	}

	return Result<std::unique_ptr<IHashContext>>::success(std::move(context));
}

Result<std::unique_ptr<IMacContext>> OpenSSLProvider::create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept
{
	const char *digest = evp_mac_digest(algorithm);
	if (digest == nullptr)
	{
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "MAC algorithm is not supported by OpenSSLProvider"));
	}

	auto context = std::make_unique<OpenSSLMacContext>(digest, key, mac_size(algorithm));
	if (!context->initialized())
	{
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_init failed"));
	}

	return Result<std::unique_ptr<IMacContext>>::success(std::move(context));
}

} // namespace crypto_core

#endif // defined(CRYPTO_CORE_ENABLE_OPENSSL)
