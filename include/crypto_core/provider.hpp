#pragma once

#include "crypto_core/aead.hpp"
#include "crypto_core/asymmetric.hpp"
#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/cipher.hpp"
#include "crypto_core/hash.hpp"
#include "crypto_core/kdf.hpp"
#include "crypto_core/mac.hpp"
#include "crypto_core/result.hpp"
#include "crypto_core/rng.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace crypto_core
{

class IHashContext
{
public:
	virtual ~IHashContext() = default;

	[[nodiscard]] virtual Result<void> update(std::span<const std::uint8_t> input) noexcept = 0;
	[[nodiscard]] virtual Result<ByteBuffer> final() noexcept = 0;
};

class IMacContext
{
public:
	virtual ~IMacContext() = default;

	[[nodiscard]] virtual Result<void> update(std::span<const std::uint8_t> input) noexcept = 0;
	[[nodiscard]] virtual Result<ByteBuffer> final() noexcept = 0;
};

class IRng
{
public:
	virtual ~IRng() = default;

	[[nodiscard]] virtual Result<void> generate(std::span<std::uint8_t> output) noexcept = 0;
};

class ICipherContext
{
public:
	virtual ~ICipherContext() = default;

	[[nodiscard]] virtual Result<ByteBuffer> update(std::span<const std::uint8_t> input) noexcept = 0;
	[[nodiscard]] virtual Result<ByteBuffer> final() noexcept = 0;
};

class ICryptoProvider
{
public:
	virtual ~ICryptoProvider() = default;

	[[nodiscard]] virtual std::string_view name() const noexcept = 0;
	[[nodiscard]] virtual bool supports(HashAlgorithm algorithm) const noexcept = 0;
	[[nodiscard]] virtual bool supports(MacAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(KdfAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(RngAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(CipherAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(AeadAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(SignatureAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(AsymmetricEncryptionAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual bool supports(KeyAgreementAlgorithm algorithm) const noexcept;
	[[nodiscard]] virtual Result<std::unique_ptr<IHashContext>> create_hash(HashAlgorithm algorithm) noexcept = 0;
	[[nodiscard]] virtual Result<std::unique_ptr<IMacContext>> create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept;
	[[nodiscard]] virtual Result<std::unique_ptr<IRng>> create_rng(RngAlgorithm algorithm) noexcept;
	[[nodiscard]] virtual Result<std::unique_ptr<ICipherContext>> create_cipher(const CipherParams &params) noexcept;
	[[nodiscard]] virtual Result<AeadEncryptResult> aead_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> aead_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept;
	[[nodiscard]] virtual Result<VerifyResult> verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept;
	[[nodiscard]] virtual Result<SecureBuffer> derive_shared_secret(const SharedSecretParams &params) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept;
	[[nodiscard]] virtual Result<ByteBuffer> hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept;
};

[[nodiscard]] ICryptoProvider &default_provider() noexcept;

} // namespace crypto_core
