#include "crypto_core/native_provider.hpp"

namespace crypto_core
{

std::string_view NativeProvider::name() const noexcept
{
	return "NativeProvider";
}

bool NativeProvider::supports(HashAlgorithm) const noexcept
{
	return false;
}

Result<std::unique_ptr<IHashContext>> NativeProvider::create_hash(HashAlgorithm) noexcept
{
	return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "hash algorithm is not implemented by NativeProvider yet"));
}

ICryptoProvider &default_provider() noexcept
{
	static NativeProvider provider;
	return provider;
}

} // namespace crypto_core
