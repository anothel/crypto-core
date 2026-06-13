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

bool ICryptoProvider::supports(KdfAlgorithm) const noexcept
{
	return false;
}

Result<ByteBuffer> ICryptoProvider::pbkdf2(KdfAlgorithm, std::span<const std::uint8_t>, std::span<const std::uint8_t>, std::uint32_t, std::size_t) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "PBKDF2 algorithm is not supported"));
}

Result<ByteBuffer> ICryptoProvider::hkdf(KdfAlgorithm, std::span<const std::uint8_t>, std::span<const std::uint8_t>, std::span<const std::uint8_t>, std::size_t) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "HKDF algorithm is not supported"));
}

bool ICryptoProvider::supports(RngAlgorithm) const noexcept
{
	return false;
}

Result<std::unique_ptr<IRng>> ICryptoProvider::create_rng(RngAlgorithm) noexcept
{
	return Result<std::unique_ptr<IRng>>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "RNG algorithm is not supported"));
}

bool ICryptoProvider::supports(CipherAlgorithm) const noexcept
{
	return false;
}

Result<std::unique_ptr<ICipherContext>> ICryptoProvider::create_cipher(const CipherParams &) noexcept
{
	return Result<std::unique_ptr<ICipherContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "cipher algorithm is not supported"));
}

} // namespace crypto_core
