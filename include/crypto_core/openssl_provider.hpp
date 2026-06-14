#pragma once

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include "crypto_core/provider.hpp"

#include <memory>
#include <string_view>

namespace crypto_core
{

class OpenSSLProvider final : public ICryptoProvider
{
public:
	using ICryptoProvider::supports;

	[[nodiscard]] std::string_view name() const noexcept override;
	[[nodiscard]] bool supports(HashAlgorithm algorithm) const noexcept override;
	[[nodiscard]] bool supports(MacAlgorithm algorithm) const noexcept override;
	[[nodiscard]] bool supports(KdfAlgorithm algorithm) const noexcept override;
	[[nodiscard]] bool supports(SignatureAlgorithm algorithm) const noexcept override;
	[[nodiscard]] bool supports(AsymmetricEncryptionAlgorithm algorithm) const noexcept override;
	[[nodiscard]] Result<std::unique_ptr<IHashContext>> create_hash(HashAlgorithm algorithm) noexcept override;
	[[nodiscard]] Result<std::unique_ptr<IMacContext>> create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept override;
	[[nodiscard]] Result<ByteBuffer> sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept override;
	[[nodiscard]] Result<VerifyResult> verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept override;
	[[nodiscard]] Result<ByteBuffer> asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept override;
	[[nodiscard]] Result<ByteBuffer> asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept override;
	[[nodiscard]] Result<ByteBuffer> pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept override;
	[[nodiscard]] Result<ByteBuffer> hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept override;
};

} // namespace crypto_core

#endif // defined(CRYPTO_CORE_ENABLE_OPENSSL)
