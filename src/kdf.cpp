#include "crypto_core/kdf.hpp"

#include "crypto_core/provider.hpp"

namespace crypto_core
{

Result<ByteBuffer> pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept
{
	return pbkdf2(default_provider(), algorithm, password, salt, iterations, output_size);
}

Result<ByteBuffer> pbkdf2(ICryptoProvider &provider, KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept
{
	return provider.pbkdf2(algorithm, password, salt, iterations, output_size);
}

Result<ByteBuffer> hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept
{
	return hkdf(default_provider(), algorithm, input_key_material, salt, info, output_size);
}

Result<ByteBuffer> hkdf(ICryptoProvider &provider, KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept
{
	return provider.hkdf(algorithm, input_key_material, salt, info, output_size);
}

} // namespace crypto_core
