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

bool ICryptoProvider::supports(AeadAlgorithm) const noexcept
{
	return false;
}

Result<AeadEncryptResult> ICryptoProvider::aead_encrypt(const AeadEncryptParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<AeadEncryptResult>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "AEAD algorithm is not supported"));
}

Result<ByteBuffer> ICryptoProvider::aead_decrypt(const AeadDecryptParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "AEAD algorithm is not supported"));
}

bool ICryptoProvider::supports(SignatureAlgorithm) const noexcept
{
	return false;
}

bool ICryptoProvider::supports(CryptoOperation, SignatureAlgorithm) const noexcept
{
	return false;
}

bool ICryptoProvider::supports(CryptoOperation, AsymmetricKeyAlgorithm) const noexcept
{
	return false;
}

Result<ByteBuffer> ICryptoProvider::sign(const SignParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "signature algorithm is not supported"));
}

Result<VerifyResult> ICryptoProvider::verify(const VerifyParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<VerifyResult>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "signature algorithm is not supported"));
}

Result<KeyPair> ICryptoProvider::generate_key_pair(const GenerateKeyPairParams &) noexcept
{
	return Result<KeyPair>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "key generation algorithm is not supported"));
}

bool ICryptoProvider::supports(AsymmetricEncryptionAlgorithm) const noexcept
{
	return false;
}

bool ICryptoProvider::supports(CryptoOperation, AsymmetricEncryptionAlgorithm) const noexcept
{
	return false;
}

Result<ByteBuffer> ICryptoProvider::asymmetric_encrypt(const AsymmetricEncryptParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "asymmetric encryption algorithm is not supported"));
}

Result<ByteBuffer> ICryptoProvider::asymmetric_decrypt(const AsymmetricDecryptParams &, std::span<const std::uint8_t>) noexcept
{
	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "asymmetric encryption algorithm is not supported"));
}

bool ICryptoProvider::supports(KeyAgreementAlgorithm) const noexcept
{
	return false;
}

bool ICryptoProvider::supports(CryptoOperation, KeyAgreementAlgorithm) const noexcept
{
	return false;
}

Result<SecureBuffer> ICryptoProvider::derive_shared_secret(const SharedSecretParams &) noexcept
{
	return Result<SecureBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "provider", "key agreement algorithm is not supported"));
}

} // namespace crypto_core
