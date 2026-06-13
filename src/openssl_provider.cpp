#include "crypto_core/openssl_provider.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <openssl/evp.h>

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

} // namespace

std::string_view OpenSSLProvider::name() const noexcept
{
	return "OpenSSLProvider";
}

bool OpenSSLProvider::supports(HashAlgorithm algorithm) const noexcept
{
	return evp_md(algorithm) != nullptr;
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

} // namespace crypto_core

#endif // defined(CRYPTO_CORE_ENABLE_OPENSSL)
