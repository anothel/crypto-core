#include "crypto_core/provider.hpp"

namespace crypto_core
{

bool ICryptoProvider::supports(MacAlgorithm) const noexcept
{
	return false;
}

Result<std::unique_ptr<IMacContext>> ICryptoProvider::create_mac(MacAlgorithm, std::span<const std::uint8_t>) noexcept
{
	return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "MAC algorithm is not supported"));
}

} // namespace crypto_core
