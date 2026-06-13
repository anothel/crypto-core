#include "crypto_core/aead.hpp"

#include "crypto_core/provider.hpp"

namespace crypto_core
{

Result<AeadEncryptResult> aead_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	return aead_encrypt(default_provider(), params, plaintext);
}

Result<AeadEncryptResult> aead_encrypt(ICryptoProvider &provider, const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	return provider.aead_encrypt(params, plaintext);
}

Result<ByteBuffer> aead_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	return aead_decrypt(default_provider(), params, ciphertext);
}

Result<ByteBuffer> aead_decrypt(ICryptoProvider &provider, const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	return provider.aead_decrypt(params, ciphertext);
}

} // namespace crypto_core
