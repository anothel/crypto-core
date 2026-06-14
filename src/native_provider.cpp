#include "crypto_core/native_provider.hpp"

#include "crypto_core/internal/aes_cbc.hpp"
#include "crypto_core/internal/aes_gcm.hpp"
#include "crypto_core/internal/hmac.hpp"
#include "crypto_core/internal/kdf.hpp"
#include "crypto_core/internal/os_rng.hpp"
#include "crypto_core/internal/rsa.hpp"
#include "crypto_core/internal/rsa_der.hpp"
#include "crypto_core/internal/rsa_oaep.hpp"
#include "crypto_core/internal/rsa_pss.hpp"
#include "crypto_core/internal/sha2.hpp"

#include <vector>

namespace crypto_core
{
namespace
{

bool is_rsa_pss_algorithm(SignatureAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case SignatureAlgorithm::rsa_pss:
	case SignatureAlgorithm::rsa_pss_sha256:
		return true;
	case SignatureAlgorithm::ecdsa_p256_sha256:
	case SignatureAlgorithm::ecdsa_p384_sha384:
	case SignatureAlgorithm::ed25519:
		return false;
	}

	return false;
}

bool is_rsa_oaep_algorithm(AsymmetricEncryptionAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricEncryptionAlgorithm::rsa_oaep:
	case AsymmetricEncryptionAlgorithm::rsa_oaep_sha256:
		return true;
	}

	return false;
}

RsaPssParams rsa_pss_params(const VerifyParams &params) noexcept
{
	if (params.algorithm == SignatureAlgorithm::rsa_pss_sha256)
	{
		return RsaPssParams::for_hash(HashAlgorithm::sha256);
	}

	return params.rsa_pss;
}

RsaPssParams rsa_pss_params(const SignParams &params) noexcept
{
	if (params.algorithm == SignatureAlgorithm::rsa_pss_sha256)
	{
		return RsaPssParams::for_hash(HashAlgorithm::sha256);
	}

	return params.rsa_pss;
}

const RsaOaepParams &rsa_oaep_params(const AsymmetricEncryptParams &params) noexcept
{
	return params.rsa_oaep;
}

const RsaOaepParams &rsa_oaep_params(const AsymmetricDecryptParams &params) noexcept
{
	return params.rsa_oaep;
}

RsaOaepParams rsa_oaep_sha256_params()
{
	return RsaOaepParams::for_hash(HashAlgorithm::sha256);
}

std::size_t bit_length(std::span<const std::uint8_t> bytes) noexcept
{
	std::size_t offset = 0;
	while (offset < bytes.size() && bytes[offset] == 0)
	{
		++offset;
	}
	if (offset == bytes.size())
	{
		return 0;
	}

	std::size_t high_bits = 0;
	auto value = bytes[offset];
	while (value != 0)
	{
		++high_bits;
		value = static_cast<std::uint8_t>(value >> 1U);
	}

	return ((bytes.size() - offset - 1U) * 8U) + high_bits;
}

} // namespace

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

bool NativeProvider::supports(SignatureAlgorithm algorithm) const noexcept
{
	return is_rsa_pss_algorithm(algorithm);
}

bool NativeProvider::supports(AsymmetricEncryptionAlgorithm algorithm) const noexcept
{
	return is_rsa_oaep_algorithm(algorithm);
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

Result<ByteBuffer> NativeProvider::sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept
{
	if (!is_rsa_pss_algorithm(params.algorithm))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "signature algorithm is not supported by NativeProvider"));
	}
	if (params.private_key == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "native_provider", "private key is required"));
	}
	if (params.private_key->algorithm() != AsymmetricKeyAlgorithm::rsa || !params.private_key->allows(KeyUsage::sign))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_key, "native_provider", "RSA signing key is required"));
	}

	auto key = internal::parse_rsa_private_key_der(params.private_key->bytes());
	if (!key)
	{
		return Result<ByteBuffer>::failure(key.error());
	}

	const auto pss = rsa_pss_params(params);
	auto message_hash = hash(*this, pss.message_hash, message);
	if (!message_hash)
	{
		return Result<ByteBuffer>::failure(message_hash.error());
	}

	std::vector<std::uint8_t> salt(pss.salt_length);
	if (!salt.empty())
	{
		auto rng = create_rng(RngAlgorithm::os_random);
		if (!rng)
		{
			return Result<ByteBuffer>::failure(rng.error());
		}
		auto generated = rng.value()->generate(salt);
		if (!generated)
		{
			return Result<ByteBuffer>::failure(generated.error());
		}
	}

	const auto modulus_bits = bit_length(key.value().modulus.bytes());
	if (modulus_bits == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_key, "native_provider", "RSA modulus must be non-zero"));
	}

	auto encoded_message = internal::emsa_pss_encode(modulus_bits - 1U, message_hash.value().bytes(), salt, pss);
	if (!encoded_message)
	{
		return Result<ByteBuffer>::failure(encoded_message.error());
	}

	return internal::rsa_private_crt_operation(key.value(), encoded_message.value().bytes());
}

Result<VerifyResult> NativeProvider::verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept
{
	if (!is_rsa_pss_algorithm(params.algorithm))
	{
		return Result<VerifyResult>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "signature algorithm is not supported by NativeProvider"));
	}
	if (params.public_key == nullptr)
	{
		return Result<VerifyResult>::failure(make_error(ErrorCode::invalid_argument, "native_provider", "public key is required"));
	}
	if (params.public_key->algorithm() != AsymmetricKeyAlgorithm::rsa || !params.public_key->allows(KeyUsage::verify))
	{
		return Result<VerifyResult>::failure(make_error(ErrorCode::invalid_key, "native_provider", "RSA verification key is required"));
	}

	auto key = internal::parse_rsa_public_key_der(params.public_key->bytes());
	if (!key)
	{
		return Result<VerifyResult>::failure(key.error());
	}
	if (params.signature.size() != key.value().modulus.size())
	{
		return Result<VerifyResult>::success(VerifyResult::invalid());
	}

	auto encoded_message = internal::rsa_public_operation(key.value(), params.signature);
	if (!encoded_message)
	{
		if (encoded_message.error().code() == ErrorCode::invalid_argument)
		{
			return Result<VerifyResult>::success(VerifyResult::invalid());
		}
		return Result<VerifyResult>::failure(encoded_message.error());
	}

	const auto pss = rsa_pss_params(params);
	auto message_hash = hash(*this, pss.message_hash, message);
	if (!message_hash)
	{
		return Result<VerifyResult>::failure(message_hash.error());
	}

	const auto encoded_bits = bit_length(key.value().modulus.bytes()) - 1U;
	const auto encoded_size = (encoded_bits + 7U) / 8U;
	if (encoded_size > encoded_message.value().size())
	{
		return Result<VerifyResult>::success(VerifyResult::invalid());
	}

	const auto encoded = encoded_message.value().bytes().last(encoded_size);
	auto valid = internal::emsa_pss_verify(encoded, encoded_bits, message_hash.value().bytes(), pss);
	if (!valid)
	{
		return Result<VerifyResult>::failure(valid.error());
	}

	return Result<VerifyResult>::success(valid.value() ? VerifyResult::valid() : VerifyResult::invalid());
}

Result<ByteBuffer> NativeProvider::asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	if (!is_rsa_oaep_algorithm(params.algorithm))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "asymmetric encryption algorithm is not supported by NativeProvider"));
	}
	if (params.public_key == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "native_provider", "public key is required"));
	}
	if (params.public_key->algorithm() != AsymmetricKeyAlgorithm::rsa || !params.public_key->allows(KeyUsage::encrypt))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_key, "native_provider", "RSA encryption key is required"));
	}

	auto key = internal::parse_rsa_public_key_der(params.public_key->bytes());
	if (!key)
	{
		return Result<ByteBuffer>::failure(key.error());
	}

	auto default_params = rsa_oaep_sha256_params();
	const auto &oaep = params.algorithm == AsymmetricEncryptionAlgorithm::rsa_oaep_sha256 ? default_params : rsa_oaep_params(params);
	const auto seed_size = digest_size(oaep.message_hash);
	if (seed_size == 0 || digest_size(oaep.mgf1_hash) == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "RSA-OAEP hash algorithm is not supported by NativeProvider"));
	}

	std::vector<std::uint8_t> seed(seed_size);
	auto rng = create_rng(RngAlgorithm::os_random);
	if (!rng)
	{
		return Result<ByteBuffer>::failure(rng.error());
	}
	auto generated = rng.value()->generate(seed);
	if (!generated)
	{
		return Result<ByteBuffer>::failure(generated.error());
	}

	auto encoded = internal::eme_oaep_encode(key.value().modulus.size(), plaintext, seed, oaep);
	if (!encoded)
	{
		return Result<ByteBuffer>::failure(encoded.error());
	}

	return internal::rsa_public_operation(key.value(), encoded.value().bytes());
}

Result<ByteBuffer> NativeProvider::asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	if (!is_rsa_oaep_algorithm(params.algorithm))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "native_provider", "asymmetric encryption algorithm is not supported by NativeProvider"));
	}
	if (params.private_key == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "native_provider", "private key is required"));
	}
	if (params.private_key->algorithm() != AsymmetricKeyAlgorithm::rsa || !params.private_key->allows(KeyUsage::decrypt))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_key, "native_provider", "RSA decryption key is required"));
	}

	auto key = internal::parse_rsa_private_key_der(params.private_key->bytes());
	if (!key)
	{
		return Result<ByteBuffer>::failure(key.error());
	}
	if (ciphertext.size() != key.value().modulus.size())
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::authentication_failed, "native_provider", "RSA-OAEP ciphertext is invalid"));
	}

	auto encoded = internal::rsa_private_crt_operation(key.value(), ciphertext);
	if (!encoded)
	{
		if (encoded.error().code() == ErrorCode::invalid_argument)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::authentication_failed, "native_provider", "RSA-OAEP ciphertext is invalid"));
		}
		return Result<ByteBuffer>::failure(encoded.error());
	}

	auto default_params = rsa_oaep_sha256_params();
	const auto &oaep = params.algorithm == AsymmetricEncryptionAlgorithm::rsa_oaep_sha256 ? default_params : rsa_oaep_params(params);
	return internal::eme_oaep_decode(encoded.value().bytes(), oaep);
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
