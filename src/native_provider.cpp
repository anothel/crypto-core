#include "crypto_core/native_provider.hpp"

#include "crypto_core/internal/aes_cbc.hpp"
#include "crypto_core/internal/aes_gcm.hpp"
#include "crypto_core/internal/hmac.hpp"
#include "crypto_core/internal/kdf.hpp"
#include "crypto_core/internal/os_rng.hpp"
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

bool NativeProvider::supports(MacAlgorithm algorithm) const noexcept
{
	return algorithm == MacAlgorithm::hmac_sha256 || algorithm == MacAlgorithm::hmac_sha512;
}

bool NativeProvider::supports(KdfAlgorithm algorithm) const noexcept
{
	return algorithm == KdfAlgorithm::pbkdf2_hmac_sha256 ||
	       algorithm == KdfAlgorithm::pbkdf2_hmac_sha512 ||
	       algorithm == KdfAlgorithm::hkdf_sha256 ||
	       algorithm == KdfAlgorithm::hkdf_sha512;
}

bool NativeProvider::supports(RngAlgorithm algorithm) const noexcept
{
	return algorithm == RngAlgorithm::os_random;
}

bool NativeProvider::supports(CipherAlgorithm algorithm) const noexcept
{
	return algorithm == CipherAlgorithm::aes_128_cbc ||
	       algorithm == CipherAlgorithm::aes_192_cbc ||
	       algorithm == CipherAlgorithm::aes_256_cbc;
}

bool NativeProvider::supports(AeadAlgorithm algorithm) const noexcept
{
	return algorithm == AeadAlgorithm::aes_128_gcm ||
	       algorithm == AeadAlgorithm::aes_192_gcm ||
	       algorithm == AeadAlgorithm::aes_256_gcm;
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

Result<std::unique_ptr<IMacContext>> NativeProvider::create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept
{
	HashAlgorithm hash_algorithm;
	switch (algorithm)
	{
	case MacAlgorithm::hmac_sha256:
		hash_algorithm = HashAlgorithm::sha256;
		break;
	case MacAlgorithm::hmac_sha512:
		hash_algorithm = HashAlgorithm::sha512;
		break;
	default:
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "MAC algorithm is not supported by NativeProvider"));
	}

	auto context = std::make_unique<internal::HmacContext>(hash_algorithm, key);
	if (!context->initialized())
	{
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::provider_error, "native_provider", "failed to initialize HMAC context"));
	}

	return Result<std::unique_ptr<IMacContext>>::success(std::move(context));
}

Result<std::unique_ptr<IRng>> NativeProvider::create_rng(RngAlgorithm algorithm) noexcept
{
	if (algorithm != RngAlgorithm::os_random)
	{
		return Result<std::unique_ptr<IRng>>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "RNG algorithm is not supported by NativeProvider"));
	}

	return Result<std::unique_ptr<IRng>>::success(std::make_unique<internal::OsRng>());
}

Result<std::unique_ptr<ICipherContext>> NativeProvider::create_cipher(const CipherParams &params) noexcept
{
	return internal::create_aes_cbc_context(params);
}

Result<AeadEncryptResult> NativeProvider::aead_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	return internal::aes_gcm_encrypt(params, plaintext);
}

Result<ByteBuffer> NativeProvider::aead_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	return internal::aes_gcm_decrypt(params, ciphertext);
}

Result<ByteBuffer> NativeProvider::pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept
{
	return internal::native_pbkdf2(algorithm, password, salt, iterations, output_size);
}

Result<ByteBuffer> NativeProvider::hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept
{
	return internal::native_hkdf(algorithm, input_key_material, salt, info, output_size);
}

ICryptoProvider &default_provider() noexcept
{
	static NativeProvider provider;
	return provider;
}

} // namespace crypto_core
