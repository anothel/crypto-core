#include "crypto_core/crypto_core.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

struct SignatureCapability final
{
	crypto_core::SignatureAlgorithm algorithm;
	bool sign;
	bool verify;
};

struct KeygenCapability final
{
	crypto_core::AsymmetricKeyAlgorithm algorithm;
	bool keygen;
};

struct EncryptionCapability final
{
	crypto_core::AsymmetricEncryptionAlgorithm algorithm;
	bool encrypt;
	bool decrypt;
};

template <typename Provider>
void require_signature_capabilities(const Provider &provider, std::span<const SignatureCapability> capabilities)
{
	for (const auto &capability : capabilities)
	{
		require(provider.supports(capability.algorithm) == (capability.sign || capability.verify));
		require(provider.supports(crypto_core::CryptoOperation::sign, capability.algorithm) == capability.sign);
		require(provider.supports(crypto_core::CryptoOperation::verify, capability.algorithm) == capability.verify);
		require(!provider.supports(crypto_core::CryptoOperation::keygen, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::encrypt, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::decrypt, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::derive, capability.algorithm));
	}
}

template <typename Provider>
void require_keygen_capabilities(const Provider &provider, std::span<const KeygenCapability> capabilities)
{
	for (const auto &capability : capabilities)
	{
		require(provider.supports(crypto_core::CryptoOperation::keygen, capability.algorithm) == capability.keygen);
		require(!provider.supports(crypto_core::CryptoOperation::sign, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::verify, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::encrypt, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::decrypt, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::derive, capability.algorithm));
	}
}

template <typename Provider>
void require_encryption_capabilities(const Provider &provider, std::span<const EncryptionCapability> capabilities)
{
	for (const auto &capability : capabilities)
	{
		require(provider.supports(capability.algorithm) == (capability.encrypt || capability.decrypt));
		require(provider.supports(crypto_core::CryptoOperation::encrypt, capability.algorithm) == capability.encrypt);
		require(provider.supports(crypto_core::CryptoOperation::decrypt, capability.algorithm) == capability.decrypt);
		require(!provider.supports(crypto_core::CryptoOperation::sign, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::verify, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::keygen, capability.algorithm));
		require(!provider.supports(crypto_core::CryptoOperation::derive, capability.algorithm));
	}
}

template <typename Provider>
void require_no_key_agreement_capabilities(const Provider &provider)
{
	require(!provider.supports(crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::KeyAgreementAlgorithm::ecdh_p384));
	require(!provider.supports(crypto_core::CryptoOperation::derive, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::CryptoOperation::derive, crypto_core::KeyAgreementAlgorithm::ecdh_p384));
	require(!provider.supports(crypto_core::CryptoOperation::sign, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::CryptoOperation::verify, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::CryptoOperation::keygen, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::CryptoOperation::encrypt, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
	require(!provider.supports(crypto_core::CryptoOperation::decrypt, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
}

std::string read_doc(std::string_view name)
{
	const auto path = std::filesystem::path{CRYPTO_CORE_SOURCE_DIR} / "docs" / std::string{name};
	std::ifstream input(path);
	require(input.is_open());
	return std::string(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
}

void require_contains(std::string_view haystack, std::string_view needle)
{
	require(haystack.find(needle) != std::string_view::npos);
}

} // namespace

void test_hash_algorithm_metadata()
{
	require(crypto_core::digest_size(crypto_core::HashAlgorithm::sha256) == 32);
	require(crypto_core::digest_size(crypto_core::HashAlgorithm::sha512) == 64);
	require(std::string_view{crypto_core::hash_algorithm_name(crypto_core::HashAlgorithm::sha256)} == std::string_view{"SHA256"});
	require(std::string_view{crypto_core::hash_algorithm_name(crypto_core::HashAlgorithm::sha512)} == std::string_view{"SHA512"});
}

class RecordingHashContext final : public crypto_core::IHashContext
{
public:
	explicit RecordingHashContext(std::vector<std::uint8_t> *updates)
	    : updates_(updates)
	{
	}

	crypto_core::Result<void> update(std::span<const std::uint8_t> input) noexcept override
	{
		updates_->insert(updates_->end(), input.begin(), input.end());
		return crypto_core::Result<void>::success();
	}

	crypto_core::Result<crypto_core::ByteBuffer> final() noexcept override
	{
		return crypto_core::Result<crypto_core::ByteBuffer>::success(crypto_core::ByteBuffer(std::vector<std::uint8_t>{1, 2, 3}));
	}

private:
	std::vector<std::uint8_t> *updates_;
};

class RecordingProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "RecordingProvider";
	}

	bool supports(crypto_core::HashAlgorithm algorithm) const noexcept override
	{
		return algorithm == crypto_core::HashAlgorithm::sha256;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm algorithm) noexcept override
	{
		requested_algorithm = algorithm;
		++create_hash_calls;
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<RecordingHashContext>(&updates));
	}

	crypto_core::HashAlgorithm requested_algorithm{crypto_core::HashAlgorithm::sha512};
	int create_hash_calls{0};
	std::vector<std::uint8_t> updates;
};

class FailingCreateProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "FailingCreateProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::failure(crypto_core::make_error(crypto_core::ErrorCode::unsupported_algorithm, "provider", "hash algorithm is not supported"));
	}
};

void test_native_provider_default_behavior()
{
	crypto_core::NativeProvider native;
	require(native.name() == std::string_view{"NativeProvider"});
	require(native.supports(crypto_core::HashAlgorithm::sha256));
	require(native.supports(crypto_core::HashAlgorithm::sha512));

	auto sha256 = native.create_hash(crypto_core::HashAlgorithm::sha256);
	auto sha512 = native.create_hash(crypto_core::HashAlgorithm::sha512);
	require(sha256.has_value());
	require(sha512.has_value());

	auto &default_provider = crypto_core::default_provider();
	require(default_provider.name() == std::string_view{"NativeProvider"});
	require(&default_provider == &crypto_core::default_provider());
}

void test_hash_wrapper_uses_explicit_provider()
{
	RecordingProvider provider;
	const std::array<std::uint8_t, 4> input{9, 8, 7, 6};

	auto digest = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, input);
	require(digest.has_value());
	require(provider.create_hash_calls == 1);
	require(provider.requested_algorithm == crypto_core::HashAlgorithm::sha256);
	require((provider.updates == std::vector<std::uint8_t>{9, 8, 7, 6}));
	require((digest.value() == crypto_core::ByteBuffer(std::vector<std::uint8_t>{1, 2, 3})));
}

void test_hash_wrapper_returns_provider_error()
{
	FailingCreateProvider provider;
	const std::array<std::uint8_t, 1> input{0};

	auto digest = crypto_core::hash(provider, crypto_core::HashAlgorithm::sha256, input);
	require(!digest.has_value());
	require(digest.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

void test_default_hash_uses_native_provider()
{
	const std::array<std::uint8_t, 3> input{1, 2, 3};

	auto digest = crypto_core::hash(crypto_core::HashAlgorithm::sha256, input);
	require(digest.has_value());
	require(digest.value().size() == crypto_core::digest_size(crypto_core::HashAlgorithm::sha256));
}

void test_native_provider_capability_matrix_matches_status_docs()
{
	crypto_core::NativeProvider provider;

	const std::array<SignatureCapability, 5> signatures{{
	    {crypto_core::SignatureAlgorithm::rsa_pss, true, true},
	    {crypto_core::SignatureAlgorithm::rsa_pss_sha256, true, true},
	    {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, true, true},
	    {crypto_core::SignatureAlgorithm::ecdsa_p384_sha384, false, false},
	    {crypto_core::SignatureAlgorithm::ed25519, true, true},
	}};
	require_signature_capabilities(provider, signatures);

	const std::array<KeygenCapability, 4> keygen{{
	    {crypto_core::AsymmetricKeyAlgorithm::rsa, false},
	    {crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, false},
	    {crypto_core::AsymmetricKeyAlgorithm::ecdsa_p384, false},
	    {crypto_core::AsymmetricKeyAlgorithm::ed25519, false},
	}};
	require_keygen_capabilities(provider, keygen);

	const std::array<EncryptionCapability, 2> encryption{{
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, true, true},
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, true, true},
	}};
	require_encryption_capabilities(provider, encryption);
	require_no_key_agreement_capabilities(provider);
}

void test_algorithm_status_doc_matches_provider_capability_matrix()
{
	const auto doc = read_doc("algorithm-status.md");

	require_contains(doc, "| Signature | RSA-PSS | sign + verify experimental | RSA-2048 current native focus |");
	require_contains(doc, "| Signature | ECDSA P-256 | sign + verify experimental | fixed-limb backend; native signing emits low-S DER signatures; malformed-input regressions covered |");
	require_contains(doc, "| Signature | ECDSA P-384 | unsupported | no active 0.x goal |");
	require_contains(doc, "| Signature | Ed25519 | sign + verify experimental | raw 32-byte public keys and private seeds; Ed25519ctx/ph unsupported |");
	require_contains(doc, "| Encryption | RSA-OAEP | encrypt + decrypt experimental | RSA-2048 current native focus |");
	require_contains(doc, "| Keygen | RSA/ECDSA/Ed25519 | planned | operation-level capability reports false for NativeProvider |");
	require_contains(doc, "| Key agreement | ECDH | planned/deferred | no active 0.x goal |");
	require_contains(doc, "| Signature | Ed25519 | sign + verify experimental | differential oracle against RFC 8032 vector |");
	require_contains(doc, "| Keygen | RSA/ECDSA P-256 | experimental | optional provider |");
}

void test_security_model_documents_recommended_use_and_misuse_rejection()
{
	const auto doc = read_doc("security-model.md");

	require_contains(doc, "## Recommended Public API Use");
	require_contains(doc, "| Operation | Recommended use | Common misuse rejection |");
	require_contains(doc, "| AES-GCM | Supply a unique nonce per key and preserve the returned tag with the ciphertext. | Wrong key, nonce, AAD, ciphertext, or tag returns `authentication_failed`; unsupported tag lengths return `invalid_argument`. |");
	require_contains(doc, "| RSA-PSS/ECDSA/Ed25519 verify | Treat a bad signature as `Result<VerifyResult>` success with `VerifyResult::invalid()`. | Malformed keys or unsupported algorithms fail the `Result`; callers must not treat `Result` failure as a normal invalid signature. |");
	require_contains(doc, "| RSA-OAEP decrypt | Treat decrypt failure as authentication failure and do not branch on internal padding details. | Wrong label/hash/ciphertext returns `authentication_failed`; unusable keys return `invalid_key` or `invalid_argument`. |");
}

void test_release_integrity_doc_defines_artifact_verification_contract()
{
	const auto doc = read_doc("release-integrity.md");

	require_contains(doc, "## Artifact Verification");
	require_contains(doc, "sha256sum -c crypto-core-${version}.sha256");
	require_contains(doc, "cosign verify-blob --key crypto-core-release.pub --signature ${artifact}.sig ${artifact}");
	require_contains(doc, "## Release Checklist");
	require_contains(doc, "- publish SHA-256 checksums for every archive, package, binary, and SBOM");
	require_contains(doc, "- publish SBOM in SPDX JSON or CycloneDX JSON format");
	require_contains(doc, "- publish signing key fingerprint and verification command when artifacts are signed");
}

void test_governance_docs_cover_crypto_policy_envelope_and_key_lifecycle()
{
	const auto policy = read_doc("crypto-policy.md");
	require_contains(policy, "## Allowed Algorithms");
	require_contains(policy, "- AES-128/192/256-GCM");
	require_contains(policy, "- RSA-PKCS1-v1_5 encryption for new data");
	require_contains(policy, "Nonce/IV values for AES-GCM are caller-supplied today");

	const auto envelope = read_doc("crypto-envelope-format.md");
	require_contains(envelope, "## Versioned Envelope");
	require_contains(envelope, "\"suite\"");
	require_contains(envelope, "\"kid\"");
	require_contains(envelope, "New encryption must emit only the latest envelope version");

	const auto key_lifecycle = read_doc("key-lifecycle.md");
	require_contains(key_lifecycle, "## KeyProvider Boundary");
	require_contains(key_lifecycle, "`keyId`");
	require_contains(key_lifecycle, "Production integrations should use KMS, HSM, or Secret Manager");
}

void test_security_review_checklist_covers_uploaded_roadmap_controls()
{
	const auto doc = read_doc("security-review-checklist.md");

	require_contains(doc, "## Required Checks");
	require_contains(doc, "- forbidden algorithms are not introduced");
	require_contains(doc, "- nonce, IV, and salt handling is explicit");
	require_contains(doc, "- logs and errors do not expose plaintext, keys, tokens, passwords, seeds, or private keys");
	require_contains(doc, "- malformed inputs have deterministic negative tests");
	require_contains(doc, "- release artifacts have SBOM, checksums, signing status, and vulnerability reporting notes");
}

#if defined(CRYPTO_CORE_ENABLE_OPENSSL)
void test_openssl_provider_capability_matrix_matches_status_docs()
{
	crypto_core::OpenSSLProvider provider;

	const std::array<SignatureCapability, 5> signatures{{
	    {crypto_core::SignatureAlgorithm::rsa_pss, true, true},
	    {crypto_core::SignatureAlgorithm::rsa_pss_sha256, true, true},
	    {crypto_core::SignatureAlgorithm::ecdsa_p256_sha256, true, true},
	    {crypto_core::SignatureAlgorithm::ecdsa_p384_sha384, false, false},
	    {crypto_core::SignatureAlgorithm::ed25519, true, true},
	}};
	require_signature_capabilities(provider, signatures);

	const std::array<KeygenCapability, 4> keygen{{
	    {crypto_core::AsymmetricKeyAlgorithm::rsa, true},
	    {crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, true},
	    {crypto_core::AsymmetricKeyAlgorithm::ecdsa_p384, false},
	    {crypto_core::AsymmetricKeyAlgorithm::ed25519, false},
	}};
	require_keygen_capabilities(provider, keygen);

	const std::array<EncryptionCapability, 2> encryption{{
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, true, true},
	    {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256, true, true},
	}};
	require_encryption_capabilities(provider, encryption);
	require_no_key_agreement_capabilities(provider);
}
#endif

int main()
{
	test_hash_algorithm_metadata();
	test_native_provider_default_behavior();
	test_hash_wrapper_uses_explicit_provider();
	test_hash_wrapper_returns_provider_error();
	test_default_hash_uses_native_provider();
	test_native_provider_capability_matrix_matches_status_docs();
	test_algorithm_status_doc_matches_provider_capability_matrix();
	test_security_model_documents_recommended_use_and_misuse_rejection();
	test_release_integrity_doc_defines_artifact_verification_contract();
	test_governance_docs_cover_crypto_policy_envelope_and_key_lifecycle();
	test_security_review_checklist_covers_uploaded_roadmap_controls();
#if defined(CRYPTO_CORE_ENABLE_OPENSSL)
	test_openssl_provider_capability_matrix_matches_status_docs();
#endif
	return 0;
}
