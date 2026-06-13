#include "crypto_core/native_provider.hpp"

#include "crypto_core/internal/sha2.hpp"

namespace crypto_core
{

std::string_view NativeProvider::name() const noexcept
{
	return "NativeProvider";
}

bool NativeProvider::supports(HashAlgorithm algorithm) const noexcept
{
	return algorithm == HashAlgorithm::sha256 || algorithm == HashAlgorithm::sha512;
}

Result<std::unique_ptr<IHashContext>> NativeProvider::create_hash(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return Result<std::unique_ptr<IHashContext>>::success(std::make_unique<internal::Sha256Context>());
	case HashAlgorithm::sha512:
		return Result<std::unique_ptr<IHashContext>>::success(std::make_unique<internal::Sha512Context>());
	}

	return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "hash algorithm is not supported by NativeProvider"));
}

ICryptoProvider &default_provider() noexcept
{
	static NativeProvider provider;
	return provider;
}

} // namespace crypto_core
