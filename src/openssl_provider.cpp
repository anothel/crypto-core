#include "crypto_core/openssl_provider.hpp"

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace crypto_core
{
namespace
{

const EVP_MD *evp_md(HashAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case HashAlgorithm::sha256:
		return EVP_sha256();
	case HashAlgorithm::sha512:
		return EVP_sha512();
	}

	return nullptr;
}

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

bool is_ecdsa_algorithm(SignatureAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case SignatureAlgorithm::ecdsa_p256_sha256:
		return true;
	case SignatureAlgorithm::rsa_pss:
	case SignatureAlgorithm::rsa_pss_sha256:
	case SignatureAlgorithm::ecdsa_p384_sha384:
	case SignatureAlgorithm::ed25519:
		return false;
	}

	return false;
}

const EVP_MD *ecdsa_md(SignatureAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case SignatureAlgorithm::ecdsa_p256_sha256:
		return EVP_sha256();
	case SignatureAlgorithm::rsa_pss:
	case SignatureAlgorithm::rsa_pss_sha256:
	case SignatureAlgorithm::ecdsa_p384_sha384:
	case SignatureAlgorithm::ed25519:
		return nullptr;
	}

	return nullptr;
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

RsaPssParams rsa_pss_params(const SignParams &params) noexcept
{
	if (params.algorithm == SignatureAlgorithm::rsa_pss_sha256)
	{
		return RsaPssParams::for_hash(HashAlgorithm::sha256);
	}

	return params.rsa_pss;
}

RsaPssParams rsa_pss_params(const VerifyParams &params) noexcept
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

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

const char *openssl_key_type(AsymmetricKeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::rsa:
		return "RSA";
	case AsymmetricKeyAlgorithm::ecdsa_p256:
	case AsymmetricKeyAlgorithm::ecdsa_p384:
		return "EC";
	case AsymmetricKeyAlgorithm::ed25519:
		return "ED25519";
	}

	return nullptr;
}

int ec_curve_nid(AsymmetricKeyAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::ecdsa_p256:
		return NID_X9_62_prime256v1;
	case AsymmetricKeyAlgorithm::rsa:
	case AsymmetricKeyAlgorithm::ecdsa_p384:
	case AsymmetricKeyAlgorithm::ed25519:
		return NID_undef;
	}

	return NID_undef;
}

bool ec_group_matches(EVP_PKEY *key, int expected_nid) noexcept
{
	char group_name[80]{};
	std::size_t group_name_size = 0;
	if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name), &group_name_size) != 1)
	{
		return false;
	}
	group_name[sizeof(group_name) - 1] = '\0';
	const int group_nid = OBJ_txt2nid(group_name);
	return group_nid == expected_nid;
}

bool pkey_matches_algorithm(EVP_PKEY *key, AsymmetricKeyAlgorithm algorithm) noexcept
{
	const char *type = openssl_key_type(algorithm);
	if (key == nullptr || type == nullptr || EVP_PKEY_is_a(key, type) != 1)
	{
		return false;
	}

	switch (algorithm)
	{
	case AsymmetricKeyAlgorithm::ecdsa_p256:
		return ec_group_matches(key, NID_X9_62_prime256v1);
	case AsymmetricKeyAlgorithm::ecdsa_p384:
		return false;
	case AsymmetricKeyAlgorithm::rsa:
	case AsymmetricKeyAlgorithm::ed25519:
		return true;
	}

	return false;
}

Result<EvpPkeyPtr> import_private_key(
    const PrivateKey &key,
    AsymmetricKeyAlgorithm expected_algorithm,
    KeyUsage required_usage,
    const char *usage_error,
    const char *parse_error) noexcept
{
	if (key.algorithm() != expected_algorithm || !key.allows(required_usage))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", usage_error));
	}
	if (key.size() > static_cast<std::size_t>(LONG_MAX))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", "private key DER is too large for OpenSSL"));
	}

	const unsigned char *input = key.bytes().data();
	EvpPkeyPtr pkey(d2i_AutoPrivateKey(nullptr, &input, static_cast<long>(key.size())), EVP_PKEY_free);
	if (!pkey_matches_algorithm(pkey.get(), expected_algorithm))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", parse_error));
	}

	return Result<EvpPkeyPtr>::success(std::move(pkey));
}

Result<EvpPkeyPtr> import_public_key(
    const PublicKey &key,
    AsymmetricKeyAlgorithm expected_algorithm,
    KeyUsage required_usage,
    const char *usage_error,
    const char *parse_error) noexcept
{
	if (key.algorithm() != expected_algorithm || !key.allows(required_usage))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", usage_error));
	}
	if (key.size() > static_cast<std::size_t>(LONG_MAX))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", "public key DER is too large for OpenSSL"));
	}

	const unsigned char *input = key.bytes().data();
	EvpPkeyPtr pkey(d2i_PUBKEY(nullptr, &input, static_cast<long>(key.size())), EVP_PKEY_free);
	if (!pkey_matches_algorithm(pkey.get(), expected_algorithm))
	{
		return Result<EvpPkeyPtr>::failure(make_error(ErrorCode::invalid_key, "openssl_provider", parse_error));
	}

	return Result<EvpPkeyPtr>::success(std::move(pkey));
}

Result<void> configure_rsa_pss(EVP_PKEY_CTX *context, const RsaPssParams &params) noexcept
{
	const EVP_MD *message_md = evp_md(params.message_hash);
	const EVP_MD *mgf1_md = evp_md(params.mgf1_hash);
	if (message_md == nullptr || mgf1_md == nullptr)
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "RSA-PSS digest is not supported by OpenSSLProvider"));
	}
	if (params.salt_length > static_cast<std::size_t>(std::numeric_limits<int>::max()))
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA-PSS salt length is too large for OpenSSL"));
	}
	if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) != 1 ||
	    EVP_PKEY_CTX_set_rsa_mgf1_md(context, mgf1_md) != 1 ||
	    EVP_PKEY_CTX_set_rsa_pss_saltlen(context, static_cast<int>(params.salt_length)) != 1)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "RSA-PSS parameter configuration failed"));
	}

	return Result<void>::success();
}

Result<void> configure_rsa_oaep(EVP_PKEY_CTX *context, const RsaOaepParams &params) noexcept
{
	const EVP_MD *message_md = evp_md(params.message_hash);
	const EVP_MD *mgf1_md = evp_md(params.mgf1_hash);
	if (message_md == nullptr || mgf1_md == nullptr)
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "RSA-OAEP digest is not supported by OpenSSLProvider"));
	}
	if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) != 1 ||
	    EVP_PKEY_CTX_set_rsa_oaep_md(context, message_md) != 1 ||
	    EVP_PKEY_CTX_set_rsa_mgf1_md(context, mgf1_md) != 1)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "RSA-OAEP parameter configuration failed"));
	}

	const auto label = params.label.bytes();
	if (label.empty())
	{
		return Result<void>::success();
	}
	if (label.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA-OAEP label is too large for OpenSSL"));
	}

	auto *owned_label = static_cast<unsigned char *>(OPENSSL_malloc(label.size()));
	if (owned_label == nullptr)
	{
		return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "OPENSSL_malloc failed"));
	}
	std::memcpy(owned_label, label.data(), label.size());
	if (EVP_PKEY_CTX_set0_rsa_oaep_label(context, owned_label, static_cast<int>(label.size())) != 1)
	{
		OPENSSL_free(owned_label);
		return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "RSA-OAEP label configuration failed"));
	}

	return Result<void>::success();
}

Result<ByteBuffer> export_public_key_der(EVP_PKEY *key) noexcept
{
	const int size = i2d_PUBKEY(key, nullptr);
	if (size <= 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "i2d_PUBKEY size query failed"));
	}

	std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
	auto *output = der.data();
	if (i2d_PUBKEY(key, &output) != size)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "i2d_PUBKEY failed"));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(der)));
}

Result<SecureBuffer> export_private_key_der(EVP_PKEY *key) noexcept
{
	const int size = i2d_PrivateKey(key, nullptr);
	if (size <= 0)
	{
		return Result<SecureBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "i2d_PrivateKey size query failed"));
	}

	std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
	auto *output = der.data();
	if (i2d_PrivateKey(key, &output) != size)
	{
		return Result<SecureBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "i2d_PrivateKey failed"));
	}

	return Result<SecureBuffer>::success(SecureBuffer(std::move(der)));
}

std::vector<std::uint8_t> uint32_to_minimal_be(std::uint32_t value)
{
	std::vector<std::uint8_t> output;
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		const auto byte = static_cast<std::uint8_t>((value >> static_cast<std::uint32_t>(shift)) & 0xFFU);
		if (!output.empty() || byte != 0)
		{
			output.push_back(byte);
		}
	}
	if (output.empty())
	{
		output.push_back(0);
	}

	return output;
}

const char *evp_mac_digest(MacAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case MacAlgorithm::hmac_sha256:
		return "SHA256";
	case MacAlgorithm::hmac_sha512:
		return "SHA512";
	}

	return nullptr;
}

const EVP_MD *pbkdf2_digest(KdfAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KdfAlgorithm::pbkdf2_hmac_sha256:
		return EVP_sha256();
	case KdfAlgorithm::pbkdf2_hmac_sha512:
		return EVP_sha512();
	case KdfAlgorithm::hkdf_sha256:
	case KdfAlgorithm::hkdf_sha512:
		break;
	}

	return nullptr;
}

const char *hkdf_digest(KdfAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case KdfAlgorithm::hkdf_sha256:
		return "SHA256";
	case KdfAlgorithm::hkdf_sha512:
		return "SHA512";
	case KdfAlgorithm::pbkdf2_hmac_sha256:
	case KdfAlgorithm::pbkdf2_hmac_sha512:
		break;
	}

	return nullptr;
}

class OpenSSLHashContext final : public IHashContext
{
public:
	explicit OpenSSLHashContext(const EVP_MD *md) noexcept
	    : context_(EVP_MD_CTX_new())
	{
		if (context_ != nullptr)
		{
			initialized_ = EVP_DigestInit_ex(context_, md, nullptr) == 1;
		}
	}

	~OpenSSLHashContext() override
	{
		EVP_MD_CTX_free(context_);
	}

	[[nodiscard]] bool initialized() const noexcept
	{
		return initialized_;
	}

	Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		if (finalized_)
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "cannot update finalized hash context"));
		}
		if (!initialized_ || EVP_DigestUpdate(context_, input.data(), input.size()) != 1)
		{
			return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestUpdate failed"));
		}
		return Result<void>::success();
	}

	Result<ByteBuffer> final() noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "hash context is already finalized"));
		}

		finalized_ = true;
		if (!initialized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "hash context is not initialized"));
		}

		const int expected_size = EVP_MD_CTX_get_size(context_);
		if (expected_size <= 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_get_size failed"));
		}

		std::vector<std::uint8_t> digest(static_cast<std::size_t>(expected_size));
		unsigned int digest_size = 0;
		if (EVP_DigestFinal_ex(context_, digest.data(), &digest_size) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestFinal_ex failed"));
		}

		digest.resize(digest_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
	}

private:
	EVP_MD_CTX *context_{nullptr};
	bool initialized_{false};
	bool finalized_{false};
};

class OpenSSLMacContext final : public IMacContext
{
public:
	OpenSSLMacContext(const char *digest, std::span<const std::uint8_t> key, std::size_t output_size) noexcept
	    : mac_(EVP_MAC_fetch(nullptr, "HMAC", nullptr)), context_(mac_ == nullptr ? nullptr : EVP_MAC_CTX_new(mac_)), output_size_(output_size)
	{
		if (context_ != nullptr)
		{
			OSSL_PARAM params[] = {
			    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(digest), 0),
			    OSSL_PARAM_construct_end(),
			};
			initialized_ = EVP_MAC_init(context_, key.data(), key.size(), params) == 1;
		}
	}

	~OpenSSLMacContext() override
	{
		EVP_MAC_CTX_free(context_);
		EVP_MAC_free(mac_);
	}

	[[nodiscard]] bool initialized() const noexcept
	{
		return initialized_;
	}

	Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		if (finalized_)
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "cannot update finalized MAC context"));
		}
		if (!initialized_ || EVP_MAC_update(context_, input.data(), input.size()) != 1)
		{
			return Result<void>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_update failed"));
		}
		return Result<void>::success();
	}

	Result<ByteBuffer> final() noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "MAC context is already finalized"));
		}
		if (!initialized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "MAC context is not initialized"));
		}

		finalized_ = true;
		std::vector<std::uint8_t> digest(output_size_);
		std::size_t digest_size = 0;
		if (EVP_MAC_final(context_, digest.data(), &digest_size, digest.size()) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_final failed"));
		}

		digest.resize(digest_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
	}

private:
	EVP_MAC *mac_{nullptr};
	EVP_MAC_CTX *context_{nullptr};
	std::size_t output_size_{0};
	bool initialized_{false};
	bool finalized_{false};
};

} // namespace

std::string_view OpenSSLProvider::name() const noexcept
{
	return "OpenSSLProvider";
}

bool OpenSSLProvider::supports(HashAlgorithm algorithm) const noexcept
{
	return evp_md(algorithm) != nullptr;
}

bool OpenSSLProvider::supports(MacAlgorithm algorithm) const noexcept
{
	return evp_mac_digest(algorithm) != nullptr;
}

bool OpenSSLProvider::supports(KdfAlgorithm algorithm) const noexcept
{
	return pbkdf2_digest(algorithm) != nullptr || hkdf_digest(algorithm) != nullptr;
}

bool OpenSSLProvider::supports(SignatureAlgorithm algorithm) const noexcept
{
	return is_rsa_pss_algorithm(algorithm) || is_ecdsa_algorithm(algorithm);
}

bool OpenSSLProvider::supports(CryptoOperation operation, SignatureAlgorithm algorithm) const noexcept
{
	switch (operation)
	{
	case CryptoOperation::sign:
	case CryptoOperation::verify:
		return is_rsa_pss_algorithm(algorithm) || is_ecdsa_algorithm(algorithm);
	case CryptoOperation::keygen:
	case CryptoOperation::encrypt:
	case CryptoOperation::decrypt:
	case CryptoOperation::derive:
		return false;
	}

	return false;
}

bool OpenSSLProvider::supports(CryptoOperation operation, AsymmetricKeyAlgorithm algorithm) const noexcept
{
	if (operation != CryptoOperation::keygen)
	{
		return false;
	}
	return algorithm == AsymmetricKeyAlgorithm::rsa || algorithm == AsymmetricKeyAlgorithm::ecdsa_p256;
}

bool OpenSSLProvider::supports(AsymmetricEncryptionAlgorithm algorithm) const noexcept
{
	return is_rsa_oaep_algorithm(algorithm);
}

bool OpenSSLProvider::supports(CryptoOperation operation, AsymmetricEncryptionAlgorithm algorithm) const noexcept
{
	switch (operation)
	{
	case CryptoOperation::encrypt:
	case CryptoOperation::decrypt:
		return is_rsa_oaep_algorithm(algorithm);
	case CryptoOperation::sign:
	case CryptoOperation::verify:
	case CryptoOperation::keygen:
	case CryptoOperation::derive:
		return false;
	}

	return false;
}

Result<std::unique_ptr<IHashContext>> OpenSSLProvider::create_hash(HashAlgorithm algorithm) noexcept
{
	const EVP_MD *md = evp_md(algorithm);
	if (md == nullptr)
	{
		return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "hash algorithm is not supported by OpenSSLProvider"));
	}

	auto context = std::make_unique<OpenSSLHashContext>(md);
	if (!context->initialized())
	{
		return Result<std::unique_ptr<IHashContext>>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestInit_ex failed"));
	}

	return Result<std::unique_ptr<IHashContext>>::success(std::move(context));
}

Result<std::unique_ptr<IMacContext>> OpenSSLProvider::create_mac(MacAlgorithm algorithm, std::span<const std::uint8_t> key) noexcept
{
	const char *digest = evp_mac_digest(algorithm);
	if (digest == nullptr)
	{
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "MAC algorithm is not supported by OpenSSLProvider"));
	}

	auto context = std::make_unique<OpenSSLMacContext>(digest, key, mac_size(algorithm));
	if (!context->initialized())
	{
		return Result<std::unique_ptr<IMacContext>>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MAC_init failed"));
	}

	return Result<std::unique_ptr<IMacContext>>::success(std::move(context));
}

Result<ByteBuffer> OpenSSLProvider::sign(const SignParams &params, std::span<const std::uint8_t> message) noexcept
{
	if (is_rsa_pss_algorithm(params.algorithm))
	{
		if (params.private_key == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "private key is required"));
		}

		auto key = import_private_key(*params.private_key, AsymmetricKeyAlgorithm::rsa, KeyUsage::sign, "RSA signing key is required", "private key DER is not an RSA private key");
		if (!key)
		{
			return Result<ByteBuffer>::failure(key.error());
		}

		const auto pss = rsa_pss_params(params);
		const EVP_MD *message_md = evp_md(pss.message_hash);
		if (message_md == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "RSA-PSS digest is not supported by OpenSSLProvider"));
		}

		EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		if (context == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_new failed"));
		}

		EVP_PKEY_CTX *pkey_context = nullptr;
		if (EVP_DigestSignInit(context.get(), &pkey_context, message_md, nullptr, key.value().get()) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignInit failed"));
		}
		auto configured = configure_rsa_pss(pkey_context, pss);
		if (!configured)
		{
			return Result<ByteBuffer>::failure(configured.error());
		}
		if (EVP_DigestSignUpdate(context.get(), message.data(), message.size()) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignUpdate failed"));
		}

		std::size_t signature_size = 0;
		if (EVP_DigestSignFinal(context.get(), nullptr, &signature_size) != 1 || signature_size == 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignFinal size query failed"));
		}

		std::vector<std::uint8_t> signature(signature_size);
		if (EVP_DigestSignFinal(context.get(), signature.data(), &signature_size) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignFinal failed"));
		}

		signature.resize(signature_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(signature)));
	}

	if (is_ecdsa_algorithm(params.algorithm))
	{
		if (params.private_key == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "private key is required"));
		}

		auto key = import_private_key(*params.private_key, AsymmetricKeyAlgorithm::ecdsa_p256, KeyUsage::sign, "ECDSA signing key is required", "private key DER is not an ECDSA P-256 private key");
		if (!key)
		{
			return Result<ByteBuffer>::failure(key.error());
		}

		const EVP_MD *message_md = ecdsa_md(params.algorithm);
		if (message_md == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "ECDSA digest is not supported by OpenSSLProvider"));
		}

		EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		if (context == nullptr)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_new failed"));
		}

		if (EVP_DigestSignInit(context.get(), nullptr, message_md, nullptr, key.value().get()) != 1 ||
		    EVP_DigestSignUpdate(context.get(), message.data(), message.size()) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSign failed"));
		}

		std::size_t signature_size = 0;
		if (EVP_DigestSignFinal(context.get(), nullptr, &signature_size) != 1 || signature_size == 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignFinal size query failed"));
		}

		std::vector<std::uint8_t> signature(signature_size);
		if (EVP_DigestSignFinal(context.get(), signature.data(), &signature_size) != 1)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestSignFinal failed"));
		}

		signature.resize(signature_size);
		return Result<ByteBuffer>::success(ByteBuffer(std::move(signature)));
	}

	return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "signature algorithm is not supported by OpenSSLProvider"));
}

Result<VerifyResult> OpenSSLProvider::verify(const VerifyParams &params, std::span<const std::uint8_t> message) noexcept
{
	if (is_rsa_pss_algorithm(params.algorithm))
	{
		if (params.public_key == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "public key is required"));
		}
		if (params.signature.empty())
		{
			return Result<VerifyResult>::success(VerifyResult::invalid());
		}

		auto key = import_public_key(*params.public_key, AsymmetricKeyAlgorithm::rsa, KeyUsage::verify, "RSA verification key is required", "public key DER is not an RSA public key");
		if (!key)
		{
			return Result<VerifyResult>::failure(key.error());
		}

		const auto pss = rsa_pss_params(params);
		const EVP_MD *message_md = evp_md(pss.message_hash);
		if (message_md == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "RSA-PSS digest is not supported by OpenSSLProvider"));
		}

		EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		if (context == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_new failed"));
		}

		EVP_PKEY_CTX *pkey_context = nullptr;
		if (EVP_DigestVerifyInit(context.get(), &pkey_context, message_md, nullptr, key.value().get()) != 1)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestVerifyInit failed"));
		}
		auto configured = configure_rsa_pss(pkey_context, pss);
		if (!configured)
		{
			return Result<VerifyResult>::failure(configured.error());
		}
		if (EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) != 1)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestVerifyUpdate failed"));
		}

		const int ok = EVP_DigestVerifyFinal(context.get(), params.signature.data(), params.signature.size());
		if (ok == 1)
		{
			return Result<VerifyResult>::success(VerifyResult::valid());
		}
		if (ok == 0)
		{
			return Result<VerifyResult>::success(VerifyResult::invalid());
		}

		return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestVerifyFinal failed"));
	}

	if (is_ecdsa_algorithm(params.algorithm))
	{
		if (params.public_key == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "public key is required"));
		}
		if (params.signature.empty())
		{
			return Result<VerifyResult>::success(VerifyResult::invalid());
		}

		auto key = import_public_key(*params.public_key, AsymmetricKeyAlgorithm::ecdsa_p256, KeyUsage::verify, "ECDSA verification key is required", "public key DER is not an ECDSA P-256 public key");
		if (!key)
		{
			return Result<VerifyResult>::failure(key.error());
		}

		const EVP_MD *message_md = ecdsa_md(params.algorithm);
		if (message_md == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "ECDSA digest is not supported by OpenSSLProvider"));
		}

		EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		if (context == nullptr)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_MD_CTX_new failed"));
		}

		if (EVP_DigestVerifyInit(context.get(), nullptr, message_md, nullptr, key.value().get()) != 1 ||
		    EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) != 1)
		{
			return Result<VerifyResult>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_DigestVerify failed"));
		}

		const int ok = EVP_DigestVerifyFinal(context.get(), params.signature.data(), params.signature.size());
		if (ok == 1)
		{
			return Result<VerifyResult>::success(VerifyResult::valid());
		}
		if (ok == 0)
		{
			return Result<VerifyResult>::success(VerifyResult::invalid());
		}

		return Result<VerifyResult>::success(VerifyResult::invalid());
	}

	return Result<VerifyResult>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "signature algorithm is not supported by OpenSSLProvider"));
}

Result<KeyPair> OpenSSLProvider::generate_key_pair(const GenerateKeyPairParams &params) noexcept
{
	if (params.algorithm == AsymmetricKeyAlgorithm::ecdsa_p256)
	{
		EvpPkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
		if (context == nullptr || EVP_PKEY_keygen_init(context.get()) != 1)
		{
			return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EC keygen init failed"));
		}
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), ec_curve_nid(params.algorithm)) != 1)
		{
			return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EC keygen curve configuration failed"));
		}

		EVP_PKEY *raw_key = nullptr;
		if (EVP_PKEY_keygen(context.get(), &raw_key) != 1 || raw_key == nullptr)
		{
			return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EC keygen failed"));
		}
		EvpPkeyPtr key(raw_key, EVP_PKEY_free);

		auto public_der = export_public_key_der(key.get());
		if (!public_der)
		{
			return Result<KeyPair>::failure(public_der.error());
		}
		auto private_der = export_private_key_der(key.get());
		if (!private_der)
		{
			return Result<KeyPair>::failure(private_der.error());
		}

		auto public_key = PublicKey::import_der(AsymmetricKeyAlgorithm::ecdsa_p256, public_der.value().bytes(), params.ec.public_usages);
		if (!public_key)
		{
			return Result<KeyPair>::failure(public_key.error());
		}
		auto private_key = PrivateKey::import_der(AsymmetricKeyAlgorithm::ecdsa_p256, std::move(private_der.value()), params.ec.private_usages);
		if (!private_key)
		{
			return Result<KeyPair>::failure(private_key.error());
		}

		return Result<KeyPair>::success(KeyPair{public_key.value(), std::move(private_key.value())});
	}
	if (params.algorithm != AsymmetricKeyAlgorithm::rsa)
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "key generation algorithm is not supported by OpenSSLProvider"));
	}
	if (params.rsa.modulus_bits < 2048 || params.rsa.modulus_bits > static_cast<std::size_t>(std::numeric_limits<int>::max()))
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA modulus size must be at least 2048 bits"));
	}
	if (params.rsa.public_exponent < 3 || (params.rsa.public_exponent % 2U) == 0U)
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA public exponent must be an odd integer greater than one"));
	}

	EvpPkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
	if (context == nullptr || EVP_PKEY_keygen_init(context.get()) != 1)
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_PKEY_keygen_init failed"));
	}
	auto modulus_bits = params.rsa.modulus_bits;
	auto exponent_bytes = uint32_to_minimal_be(params.rsa.public_exponent);
	OSSL_PARAM keygen_params[] = {
	    OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &modulus_bits),
	    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, exponent_bytes.data(), exponent_bytes.size()),
	    OSSL_PARAM_construct_end(),
	};
	if (EVP_PKEY_CTX_set_params(context.get(), keygen_params) != 1)
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "RSA keygen parameter configuration failed"));
	}

	EVP_PKEY *raw_key = nullptr;
	if (EVP_PKEY_keygen(context.get(), &raw_key) != 1 || raw_key == nullptr)
	{
		return Result<KeyPair>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_PKEY_keygen failed"));
	}
	EvpPkeyPtr key(raw_key, EVP_PKEY_free);

	auto public_der = export_public_key_der(key.get());
	if (!public_der)
	{
		return Result<KeyPair>::failure(public_der.error());
	}
	auto private_der = export_private_key_der(key.get());
	if (!private_der)
	{
		return Result<KeyPair>::failure(private_der.error());
	}

	auto public_key = PublicKey::import_der(AsymmetricKeyAlgorithm::rsa, public_der.value().bytes(), params.rsa.public_usages);
	if (!public_key)
	{
		return Result<KeyPair>::failure(public_key.error());
	}
	auto private_key = PrivateKey::import_der(AsymmetricKeyAlgorithm::rsa, std::move(private_der.value()), params.rsa.private_usages);
	if (!private_key)
	{
		return Result<KeyPair>::failure(private_key.error());
	}

	return Result<KeyPair>::success(KeyPair{public_key.value(), std::move(private_key.value())});
}

Result<ByteBuffer> OpenSSLProvider::asymmetric_encrypt(const AsymmetricEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	if (!is_rsa_oaep_algorithm(params.algorithm))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "asymmetric encryption algorithm is not supported by OpenSSLProvider"));
	}
	if (params.public_key == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "public key is required"));
	}

	auto key = import_public_key(*params.public_key, AsymmetricKeyAlgorithm::rsa, KeyUsage::encrypt, "RSA encryption key is required", "public key DER is not an RSA public key");
	if (!key)
	{
		return Result<ByteBuffer>::failure(key.error());
	}

	EvpPkeyCtxPtr context(EVP_PKEY_CTX_new(key.value().get(), nullptr), EVP_PKEY_CTX_free);
	if (context == nullptr || EVP_PKEY_encrypt_init(context.get()) != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_PKEY_encrypt_init failed"));
	}

	auto default_params = rsa_oaep_sha256_params();
	const auto &oaep = params.algorithm == AsymmetricEncryptionAlgorithm::rsa_oaep_sha256 ? default_params : rsa_oaep_params(params);
	auto configured = configure_rsa_oaep(context.get(), oaep);
	if (!configured)
	{
		return Result<ByteBuffer>::failure(configured.error());
	}

	std::size_t ciphertext_size = 0;
	if (EVP_PKEY_encrypt(context.get(), nullptr, &ciphertext_size, plaintext.data(), plaintext.size()) != 1 || ciphertext_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA-OAEP plaintext is invalid"));
	}

	std::vector<std::uint8_t> ciphertext(ciphertext_size);
	if (EVP_PKEY_encrypt(context.get(), ciphertext.data(), &ciphertext_size, plaintext.data(), plaintext.size()) != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "RSA-OAEP plaintext is invalid"));
	}

	ciphertext.resize(ciphertext_size);
	return Result<ByteBuffer>::success(ByteBuffer(std::move(ciphertext)));
}

Result<ByteBuffer> OpenSSLProvider::asymmetric_decrypt(const AsymmetricDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	if (!is_rsa_oaep_algorithm(params.algorithm))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "asymmetric encryption algorithm is not supported by OpenSSLProvider"));
	}
	if (params.private_key == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "private key is required"));
	}

	auto key = import_private_key(*params.private_key, AsymmetricKeyAlgorithm::rsa, KeyUsage::decrypt, "RSA decryption key is required", "private key DER is not an RSA private key");
	if (!key)
	{
		return Result<ByteBuffer>::failure(key.error());
	}

	EvpPkeyCtxPtr context(EVP_PKEY_CTX_new(key.value().get(), nullptr), EVP_PKEY_CTX_free);
	if (context == nullptr || EVP_PKEY_decrypt_init(context.get()) != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_PKEY_decrypt_init failed"));
	}

	auto default_params = rsa_oaep_sha256_params();
	const auto &oaep = params.algorithm == AsymmetricEncryptionAlgorithm::rsa_oaep_sha256 ? default_params : rsa_oaep_params(params);
	auto configured = configure_rsa_oaep(context.get(), oaep);
	if (!configured)
	{
		return Result<ByteBuffer>::failure(configured.error());
	}

	std::size_t plaintext_size = 0;
	if (EVP_PKEY_decrypt(context.get(), nullptr, &plaintext_size, ciphertext.data(), ciphertext.size()) != 1 || plaintext_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::authentication_failed, "openssl_provider", "RSA-OAEP ciphertext is invalid"));
	}

	std::vector<std::uint8_t> plaintext(plaintext_size);
	if (EVP_PKEY_decrypt(context.get(), plaintext.data(), &plaintext_size, ciphertext.data(), ciphertext.size()) != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::authentication_failed, "openssl_provider", "RSA-OAEP ciphertext is invalid"));
	}

	plaintext.resize(plaintext_size);
	return Result<ByteBuffer>::success(ByteBuffer(std::move(plaintext)));
}

Result<ByteBuffer> OpenSSLProvider::pbkdf2(KdfAlgorithm algorithm, std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt, std::uint32_t iterations, std::size_t output_size) noexcept
{
	if (iterations == 0 || output_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "PBKDF2 iterations and output size must be non-zero"));
	}
	if (password.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
	    salt.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
	    iterations > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
	    output_size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "PBKDF2 input is too large for OpenSSL"));
	}

	const EVP_MD *digest = pbkdf2_digest(algorithm);
	if (digest == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "PBKDF2 algorithm is not supported by OpenSSLProvider"));
	}

	std::vector<std::uint8_t> output(output_size);
	const int ok = PKCS5_PBKDF2_HMAC(
	    reinterpret_cast<const char *>(password.data()),
	    static_cast<int>(password.size()),
	    salt.data(),
	    static_cast<int>(salt.size()),
	    static_cast<int>(iterations),
	    digest,
	    static_cast<int>(output.size()),
	    output.data());
	if (ok != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "PKCS5_PBKDF2_HMAC failed"));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

Result<ByteBuffer> OpenSSLProvider::hkdf(KdfAlgorithm algorithm, std::span<const std::uint8_t> input_key_material, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info, std::size_t output_size) noexcept
{
	if (output_size == 0)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "openssl_provider", "HKDF output size must be non-zero"));
	}

	const char *digest = hkdf_digest(algorithm);
	if (digest == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::unsupported_algorithm, "openssl_provider", "HKDF algorithm is not supported by OpenSSLProvider"));
	}

	EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
	if (kdf == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_KDF_fetch failed"));
	}

	EVP_KDF_CTX *context = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (context == nullptr)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_KDF_CTX_new failed"));
	}

	std::vector<std::uint8_t> output(output_size);
	OSSL_PARAM params[] = {
	    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>(digest), 0),
	    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t *>(input_key_material.data()), input_key_material.size()),
	    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t *>(salt.data()), salt.size()),
	    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t *>(info.data()), info.size()),
	    OSSL_PARAM_construct_end(),
	};

	const int ok = EVP_KDF_derive(context, output.data(), output.size(), params);
	EVP_KDF_CTX_free(context);
	if (ok != 1)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::provider_error, "openssl_provider", "EVP_KDF_derive failed"));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

} // namespace crypto_core

#endif // defined(CRYPTO_CORE_ENABLE_OPENSSL)
