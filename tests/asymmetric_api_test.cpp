#include "crypto_core/crypto_core.hpp"

#include "test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
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

class MinimalHashContext final : public crypto_core::IHashContext
{
public:
	crypto_core::Result<void> update(std::span<const std::uint8_t>) noexcept override
	{
		return crypto_core::Result<void>::success();
	}

	crypto_core::Result<crypto_core::ByteBuffer> final() noexcept override
	{
		return crypto_core::Result<crypto_core::ByteBuffer>::success(crypto_core::ByteBuffer{});
	}
};

class UnsupportedAsymmetricProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "UnsupportedAsymmetricProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<MinimalHashContext>());
	}
};

class InvalidSignatureProvider final : public crypto_core::ICryptoProvider
{
public:
	std::string_view name() const noexcept override
	{
		return "InvalidSignatureProvider";
	}

	bool supports(crypto_core::HashAlgorithm) const noexcept override
	{
		return false;
	}

	bool supports(crypto_core::SignatureAlgorithm algorithm) const noexcept override
	{
		return algorithm == crypto_core::SignatureAlgorithm::ed25519;
	}

	crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>> create_hash(crypto_core::HashAlgorithm) noexcept override
	{
		return crypto_core::Result<std::unique_ptr<crypto_core::IHashContext>>::success(std::make_unique<MinimalHashContext>());
	}

	crypto_core::Result<crypto_core::VerifyResult> verify(
	    const crypto_core::VerifyParams &,
	    std::span<const std::uint8_t>) noexcept override
	{
		return crypto_core::Result<crypto_core::VerifyResult>::success(crypto_core::VerifyResult::invalid());
	}
};

void test_asymmetric_algorithm_metadata()
{
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::rsa) == std::string_view{"RSA"});
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256) == std::string_view{"ECDSA-P256"});
	require(crypto_core::asymmetric_key_algorithm_name(crypto_core::AsymmetricKeyAlgorithm::ed25519) == std::string_view{"Ed25519"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::rsa_pss) == std::string_view{"RSA-PSS"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::rsa_pss_sha256) == std::string_view{"RSA-PSS-SHA256"});
	require(crypto_core::asymmetric_encryption_algorithm_name(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep) == std::string_view{"RSA-OAEP"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256) == std::string_view{"ECDSA-P256-SHA256"});
	require(crypto_core::signature_algorithm_name(crypto_core::SignatureAlgorithm::ed25519) == std::string_view{"Ed25519"});
	require(crypto_core::verify_status_name(crypto_core::VerifyStatus::valid) == std::string_view{"valid"});
	require(crypto_core::verify_status_name(crypto_core::VerifyStatus::invalid) == std::string_view{"invalid"});
}

void test_rsa_pss_params_are_explicit()
{
	const auto defaults = crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256);
	require(defaults.message_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.salt_length == crypto_core::digest_size(crypto_core::HashAlgorithm::sha256));

	const crypto_core::RsaPssParams custom{
	    crypto_core::HashAlgorithm::sha512,
	    crypto_core::HashAlgorithm::sha256,
	    20,
	};
	require(custom.message_hash == crypto_core::HashAlgorithm::sha512);
	require(custom.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(custom.salt_length == 20);
}

void test_rsa_oaep_params_own_label()
{
	const std::array<std::uint8_t, 3> label{1, 2, 3};
	auto params = crypto_core::RsaOaepParams::with_label(crypto_core::HashAlgorithm::sha512, label);
	require(params.message_hash == crypto_core::HashAlgorithm::sha512);
	require(params.mgf1_hash == crypto_core::HashAlgorithm::sha512);
	require(params.label.size() == label.size());
	params.label.bytes()[0] = 0xFFU;
	require(label[0] == 1U);

	const auto defaults = crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256);
	require(defaults.message_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.mgf1_hash == crypto_core::HashAlgorithm::sha256);
	require(defaults.label.empty());
}

void test_public_and_private_key_import_export()
{
	const std::array<std::uint8_t, 4> public_der{1, 2, 3, 4};
	const std::array<std::uint8_t, 5> private_der{9, 8, 7, 6, 5};

	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, public_der, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	require(public_key.has_value());
	require(public_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(public_key.value().allows(crypto_core::KeyUsage::verify));
	require(public_key.value().allows(crypto_core::KeyUsage::encrypt));
	require(!public_key.value().allows(crypto_core::KeyUsage::decrypt));
	require(public_key.value().size() == public_der.size());
	require(public_key.value().is_der_encoded());

	auto exported_public = public_key.value().export_der();
	require(exported_public.has_value());
	require(exported_public.value().size() == public_der.size());
	exported_public.value().bytes()[0] = 0xFFU;
	require(public_key.value().bytes()[0] == 1U);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(private_der);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::rsa, std::move(private_buffer.value()), crypto_core::KeyUsage::sign | crypto_core::KeyUsage::decrypt);
	require(private_key.has_value());
	require(private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(private_key.value().allows(crypto_core::KeyUsage::sign));
	require(private_key.value().allows(crypto_core::KeyUsage::decrypt));
	require(!private_key.value().allows(crypto_core::KeyUsage::verify));
	require(private_key.value().size() == private_der.size());
	require(private_key.value().is_der_encoded());

	auto exported_private = private_key.value().export_der();
	require(exported_private.has_value());
	require(exported_private.value().size() == private_der.size());
	exported_private.value().bytes()[0] = 0xAAU;
	require(private_key.value().bytes()[0] == 9U);
}

void test_public_key_import_spki_der_validates_container()
{
	const std::array<std::uint8_t, 29> rsa_spki_der{
	    0x30, 0x1B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x0A, 0x00,
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	const std::array<std::uint8_t, 9> rsa_pkcs1_der{
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};

	auto rsa = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, rsa_spki_der, crypto_core::KeyUsage::verify);
	require(rsa.has_value());
	require(rsa.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(rsa.value().is_der_encoded());
	require(rsa.value().bytes().size() == rsa_spki_der.size());

	auto pkcs1 = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, rsa_pkcs1_der, crypto_core::KeyUsage::verify);
	require(!pkcs1.has_value());
	require(pkcs1.error().code() == crypto_core::ErrorCode::invalid_key);

	auto p256_der = crypto_core::test_support::decode_hex("3059301306072A8648CE3D020106082A8648CE3D030107034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	require(p256_der.has_value());
	auto p256 = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256, p256_der.value(), crypto_core::KeyUsage::verify);
	require(p256.has_value());
	require(p256.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256);
	require(p256.value().is_der_encoded());

	auto ed25519 = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, rsa_spki_der, crypto_core::KeyUsage::verify);
	require(!ed25519.has_value());
	require(ed25519.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_rsa_pkcs1_der_import_validates_container()
{
	const std::array<std::uint8_t, 9> public_pkcs1_der{
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	const std::array<std::uint8_t, 29> public_spki_der{
	    0x30, 0x1B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x0A, 0x00,
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	const std::array<std::uint8_t, 31> private_pkcs1_der{
	    0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C, 0xA1, 0x02,
	    0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01, 0x3D, 0x02,
	    0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31, 0x02, 0x01,
	    0x26};
	const std::array<std::uint8_t, 53> private_pkcs8_der{
	    0x30, 0x33, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A,
	    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
	    0x04, 0x1F, 0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C,
	    0xA1, 0x02, 0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01,
	    0x3D, 0x02, 0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31,
	    0x02, 0x01, 0x26};

	auto public_key = crypto_core::PublicKey::import_rsa_pkcs1_der(public_pkcs1_der, crypto_core::KeyUsage::verify);
	require(public_key.has_value());
	require(public_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(public_key.value().is_der_encoded());
	require(public_key.value().bytes().size() == public_pkcs1_der.size());

	auto spki = crypto_core::PublicKey::import_rsa_pkcs1_der(public_spki_der, crypto_core::KeyUsage::verify);
	require(!spki.has_value());
	require(spki.error().code() == crypto_core::ErrorCode::invalid_key);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(private_pkcs1_der);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(private_buffer.value()), crypto_core::KeyUsage::sign);
	require(private_key.has_value());
	require(private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(private_key.value().is_der_encoded());
	require(private_key.value().bytes().size() == private_pkcs1_der.size());

	auto pkcs8_buffer = crypto_core::SecureBuffer::copy_from(private_pkcs8_der);
	require(pkcs8_buffer.has_value());
	auto pkcs8 = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(pkcs8_buffer.value()), crypto_core::KeyUsage::sign);
	require(!pkcs8.has_value());
	require(pkcs8.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_pkcs8_der_import_validates_container()
{
	const std::array<std::uint8_t, 31> private_pkcs1_der{
	    0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C, 0xA1, 0x02,
	    0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01, 0x3D, 0x02,
	    0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31, 0x02, 0x01,
	    0x26};
	const std::array<std::uint8_t, 53> private_pkcs8_der{
	    0x30, 0x33, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A,
	    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
	    0x04, 0x1F, 0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C,
	    0xA1, 0x02, 0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01,
	    0x3D, 0x02, 0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31,
	    0x02, 0x01, 0x26};
	auto p256_pkcs8_der = crypto_core::test_support::decode_hex("304D020100301306072A8648CE3D020106082A8648CE3D0301070433303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require(p256_pkcs8_der.has_value());
	auto p256_sec1_der = crypto_core::test_support::decode_hex("303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require(p256_sec1_der.has_value());

	auto pkcs8_buffer = crypto_core::SecureBuffer::copy_from(private_pkcs8_der);
	require(pkcs8_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_pkcs8_der(
	    crypto_core::AsymmetricKeyAlgorithm::rsa,
	    std::move(pkcs8_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(private_key.has_value());
	require(private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::rsa);
	require(private_key.value().is_der_encoded());
	require(private_key.value().bytes().size() == private_pkcs8_der.size());

	auto p256_pkcs8_buffer = crypto_core::SecureBuffer::copy_from(p256_pkcs8_der.value());
	require(p256_pkcs8_buffer.has_value());
	auto p256_private_key = crypto_core::PrivateKey::import_pkcs8_der(
	    crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256,
	    std::move(p256_pkcs8_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(p256_private_key.has_value());
	require(p256_private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256);
	require(p256_private_key.value().is_der_encoded());
	require(p256_private_key.value().bytes().size() == p256_pkcs8_der.value().size());

	auto pkcs1_buffer = crypto_core::SecureBuffer::copy_from(private_pkcs1_der);
	require(pkcs1_buffer.has_value());
	auto pkcs1 = crypto_core::PrivateKey::import_pkcs8_der(
	    crypto_core::AsymmetricKeyAlgorithm::rsa,
	    std::move(pkcs1_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(!pkcs1.has_value());
	require(pkcs1.error().code() == crypto_core::ErrorCode::invalid_key);

	auto sec1_buffer = crypto_core::SecureBuffer::copy_from(p256_sec1_der.value());
	require(sec1_buffer.has_value());
	auto sec1 = crypto_core::PrivateKey::import_pkcs8_der(
	    crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256,
	    std::move(sec1_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(!sec1.has_value());
	require(sec1.error().code() == crypto_core::ErrorCode::invalid_key);

	auto ed25519_buffer = crypto_core::SecureBuffer::copy_from(private_pkcs8_der);
	require(ed25519_buffer.has_value());
	auto ed25519 = crypto_core::PrivateKey::import_pkcs8_der(
	    crypto_core::AsymmetricKeyAlgorithm::ed25519,
	    std::move(ed25519_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(!ed25519.has_value());
	require(ed25519.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_sec1_der_import_validates_container()
{
	auto sec1_der = crypto_core::test_support::decode_hex("303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require(sec1_der.has_value());
	auto sec1_buffer = crypto_core::SecureBuffer::copy_from(sec1_der.value());
	require(sec1_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_sec1_der(
	    crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256,
	    std::move(sec1_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(private_key.has_value());
	require(private_key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256);
	require(private_key.value().is_der_encoded());
	require(private_key.value().bytes().size() == sec1_der.value().size());

	auto pkcs8_der = crypto_core::test_support::decode_hex("304D020100301306072A8648CE3D020106082A8648CE3D0301070433303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require(pkcs8_der.has_value());
	auto pkcs8_buffer = crypto_core::SecureBuffer::copy_from(pkcs8_der.value());
	require(pkcs8_buffer.has_value());
	auto pkcs8 = crypto_core::PrivateKey::import_sec1_der(
	    crypto_core::AsymmetricKeyAlgorithm::ecdsa_p256,
	    std::move(pkcs8_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(!pkcs8.has_value());
	require(pkcs8.error().code() == crypto_core::ErrorCode::invalid_key);

	auto rsa_buffer = crypto_core::SecureBuffer::copy_from(sec1_der.value());
	require(rsa_buffer.has_value());
	auto rsa = crypto_core::PrivateKey::import_sec1_der(
	    crypto_core::AsymmetricKeyAlgorithm::rsa,
	    std::move(rsa_buffer.value()),
	    crypto_core::KeyUsage::sign);
	require(!rsa.has_value());
	require(rsa.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_asymmetric_keys_reject_empty_der()
{
	const std::array<std::uint8_t, 0> empty{};

	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, empty, crypto_core::KeyUsage::verify);
	require(!public_key.has_value());
	require(public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(empty);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, std::move(private_buffer.value()), crypto_core::KeyUsage::sign);
	require(!private_key.has_value());
	require(private_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_ed25519_der_import_rejects_raw_material()
{
	std::array<std::uint8_t, 32> raw{};

	auto public_key = crypto_core::PublicKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, raw, crypto_core::KeyUsage::verify);
	require(!public_key.has_value());
	require(public_key.error().code() == crypto_core::ErrorCode::invalid_key);

	auto private_buffer = crypto_core::SecureBuffer::copy_from(raw);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_der(crypto_core::AsymmetricKeyAlgorithm::ed25519, std::move(private_buffer.value()), crypto_core::KeyUsage::sign);
	require(!private_key.has_value());
	require(private_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_ed25519_raw_public_key_import_validates_length_and_owns_bytes()
{
	std::array<std::uint8_t, 32> raw{};
	raw[0] = 0xA5U;

	auto key = crypto_core::PublicKey::import_raw_ed25519(raw, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	require(key.has_value());
	require(key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::ed25519);
	require(key.value().allows(crypto_core::KeyUsage::verify));
	require(key.value().allows(crypto_core::KeyUsage::encrypt));
	require(key.value().size() == raw.size());
	require(!key.value().is_der_encoded());

	raw[0] = 0x5AU;
	require(key.value().bytes()[0] == 0xA5U);
	auto exported_der = key.value().export_der();
	require(!exported_der.has_value());
	require(exported_der.error().code() == crypto_core::ErrorCode::invalid_key);

	std::array<std::uint8_t, 31> short_raw{};
	auto short_key = crypto_core::PublicKey::import_raw_ed25519(short_raw, crypto_core::KeyUsage::verify);
	require(!short_key.has_value());
	require(short_key.error().code() == crypto_core::ErrorCode::invalid_key);

	std::array<std::uint8_t, 33> long_raw{};
	auto long_key = crypto_core::PublicKey::import_raw_ed25519(long_raw, crypto_core::KeyUsage::verify);
	require(!long_key.has_value());
	require(long_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_ed25519_raw_private_seed_import_validates_length_and_moves_buffer()
{
	std::array<std::uint8_t, 32> raw{};
	raw[0] = 0x11U;
	auto buffer = crypto_core::SecureBuffer::copy_from(raw);
	require(buffer.has_value());

	auto key = crypto_core::PrivateKey::import_raw_ed25519_seed(std::move(buffer.value()), crypto_core::KeyUsage::sign);
	require(key.has_value());
	require(key.value().algorithm() == crypto_core::AsymmetricKeyAlgorithm::ed25519);
	require(key.value().allows(crypto_core::KeyUsage::sign));
	require(key.value().size() == raw.size());
	require(key.value().bytes()[0] == 0x11U);
	require(!key.value().is_der_encoded());
	auto exported_der = key.value().export_der();
	require(!exported_der.has_value());
	require(exported_der.error().code() == crypto_core::ErrorCode::invalid_key);

	std::array<std::uint8_t, 31> short_raw{};
	auto short_buffer = crypto_core::SecureBuffer::copy_from(short_raw);
	require(short_buffer.has_value());
	auto short_key = crypto_core::PrivateKey::import_raw_ed25519_seed(std::move(short_buffer.value()), crypto_core::KeyUsage::sign);
	require(!short_key.has_value());
	require(short_key.error().code() == crypto_core::ErrorCode::invalid_key);

	std::array<std::uint8_t, 33> long_raw{};
	auto long_buffer = crypto_core::SecureBuffer::copy_from(long_raw);
	require(long_buffer.has_value());
	auto long_key = crypto_core::PrivateKey::import_raw_ed25519_seed(std::move(long_buffer.value()), crypto_core::KeyUsage::sign);
	require(!long_key.has_value());
	require(long_key.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_private_key_and_key_pair_are_move_only()
{
	static_assert(std::is_copy_constructible_v<crypto_core::PublicKey>);
	static_assert(!std::is_copy_constructible_v<crypto_core::PrivateKey>);
	static_assert(!std::is_copy_assignable_v<crypto_core::PrivateKey>);
	static_assert(std::is_move_constructible_v<crypto_core::PrivateKey>);
	static_assert(std::is_move_assignable_v<crypto_core::PrivateKey>);
	static_assert(!std::is_copy_constructible_v<crypto_core::KeyPair>);
	static_assert(!std::is_copy_assignable_v<crypto_core::KeyPair>);
	static_assert(std::is_move_constructible_v<crypto_core::KeyPair>);
	static_assert(std::is_move_assignable_v<crypto_core::KeyPair>);
}

void test_rsa_key_generation_params_have_safe_defaults()
{
	const crypto_core::RsaKeyGenerationParams params{};
	require(params.modulus_bits == 2048);
	require(params.public_exponent == 65537);
	require(crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::verify));
	require(crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::encrypt));
	require(crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::sign));
	require(crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::decrypt));
}

void test_ec_key_generation_params_have_sign_verify_defaults()
{
	const crypto_core::EcKeyGenerationParams params{};
	require(crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::verify));
	require(!crypto_core::has_key_usage(params.public_usages, crypto_core::KeyUsage::encrypt));
	require(crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::sign));
	require(!crypto_core::has_key_usage(params.private_usages, crypto_core::KeyUsage::decrypt));
}

void test_default_provider_reports_signature_support()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss));
	require(provider.supports(crypto_core::SignatureAlgorithm::rsa_pss_sha256));
	require(provider.supports(crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
	require(!provider.supports(crypto_core::SignatureAlgorithm::ecdsa_p384_sha384));
	require(provider.supports(crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep));
	require(provider.supports(crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256));
	require(!provider.supports(crypto_core::KeyAgreementAlgorithm::ecdh_p256));
}

void test_default_provider_reports_operation_level_asymmetric_support()
{
	crypto_core::NativeProvider provider;
	require(provider.supports(crypto_core::CryptoOperation::sign, crypto_core::SignatureAlgorithm::rsa_pss_sha256));
	require(provider.supports(crypto_core::CryptoOperation::verify, crypto_core::SignatureAlgorithm::rsa_pss_sha256));
	require(provider.supports(crypto_core::CryptoOperation::sign, crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
	require(provider.supports(crypto_core::CryptoOperation::verify, crypto_core::SignatureAlgorithm::ecdsa_p256_sha256));
	require(provider.supports(crypto_core::CryptoOperation::sign, crypto_core::SignatureAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::verify, crypto_core::SignatureAlgorithm::ed25519));
	require(!provider.supports(crypto_core::CryptoOperation::keygen, crypto_core::AsymmetricKeyAlgorithm::ed25519));
	require(provider.supports(crypto_core::CryptoOperation::encrypt, crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256));
	require(provider.supports(crypto_core::CryptoOperation::decrypt, crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep_sha256));
	require(!provider.supports(crypto_core::CryptoOperation::derive, crypto_core::KeyAgreementAlgorithm::ecdh_p256));
}

void test_asymmetric_provider_defaults_return_unsupported_algorithm()
{
	UnsupportedAsymmetricProvider provider;
	const std::array<std::uint8_t, 3> message{1, 2, 3};
	const std::array<std::uint8_t, 29> public_der{
	    0x30, 0x1B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x0A, 0x00,
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	const std::array<std::uint8_t, 31> private_der{
	    0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0C, 0xA1, 0x02,
	    0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1, 0x02, 0x01, 0x3D, 0x02,
	    0x01, 0x35, 0x02, 0x01, 0x35, 0x02, 0x01, 0x31, 0x02, 0x01,
	    0x26};
	const std::array<std::uint8_t, 2> signature{7, 8};

	auto private_buffer = crypto_core::SecureBuffer::copy_from(private_der);
	require(private_buffer.has_value());
	auto private_key = crypto_core::PrivateKey::import_rsa_pkcs1_der(std::move(private_buffer.value()), crypto_core::KeyUsage::sign | crypto_core::KeyUsage::decrypt | crypto_core::KeyUsage::derive);
	require(private_key.has_value());
	auto public_key = crypto_core::PublicKey::import_spki_der(crypto_core::AsymmetricKeyAlgorithm::rsa, public_der, crypto_core::KeyUsage::verify | crypto_core::KeyUsage::encrypt);
	require(public_key.has_value());

	auto sign_result = crypto_core::sign(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &private_key.value(), crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!sign_result.has_value());
	require(sign_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto verify_result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::rsa_pss, &public_key.value(), signature, crypto_core::RsaPssParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!verify_result.has_value());
	require(verify_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto encrypt_result = crypto_core::asymmetric_encrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &public_key.value(), crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!encrypt_result.has_value());
	require(encrypt_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto decrypt_result = crypto_core::asymmetric_decrypt(provider, {crypto_core::AsymmetricEncryptionAlgorithm::rsa_oaep, &private_key.value(), crypto_core::RsaOaepParams::for_hash(crypto_core::HashAlgorithm::sha256)}, message);
	require(!decrypt_result.has_value());
	require(decrypt_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto secret_result = crypto_core::derive_shared_secret(provider, {crypto_core::KeyAgreementAlgorithm::ecdh_p256, &private_key.value(), &public_key.value()});
	require(!secret_result.has_value());
	require(secret_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);

	auto key_pair_result = crypto_core::generate_key_pair(provider, {crypto_core::AsymmetricKeyAlgorithm::rsa});
	require(!key_pair_result.has_value());
	require(key_pair_result.error().code() == crypto_core::ErrorCode::unsupported_algorithm);
}

void test_invalid_signature_is_successful_verify_result()
{
	InvalidSignatureProvider provider;
	const std::array<std::uint8_t, 3> message{1, 2, 3};
	const std::array<std::uint8_t, 32> key_raw{};
	const std::array<std::uint8_t, 2> signature{7, 8};
	auto public_key = crypto_core::PublicKey::import_raw_ed25519(key_raw, crypto_core::KeyUsage::verify);
	require(public_key.has_value());

	auto result = crypto_core::verify(provider, {crypto_core::SignatureAlgorithm::ed25519, &public_key.value(), signature}, message);
	require(result.has_value());
	require(result.value().status == crypto_core::VerifyStatus::invalid);
	require(!result.value().is_valid());
}

} // namespace

int main()
{
	test_asymmetric_algorithm_metadata();
	test_rsa_pss_params_are_explicit();
	test_rsa_oaep_params_own_label();
	test_public_and_private_key_import_export();
	test_public_key_import_spki_der_validates_container();
	test_rsa_pkcs1_der_import_validates_container();
	test_pkcs8_der_import_validates_container();
	test_sec1_der_import_validates_container();
	test_asymmetric_keys_reject_empty_der();
	test_ed25519_der_import_rejects_raw_material();
	test_ed25519_raw_public_key_import_validates_length_and_owns_bytes();
	test_ed25519_raw_private_seed_import_validates_length_and_moves_buffer();
	test_private_key_and_key_pair_are_move_only();
	test_rsa_key_generation_params_have_safe_defaults();
	test_ec_key_generation_params_have_sign_verify_defaults();
	test_default_provider_reports_signature_support();
	test_default_provider_reports_operation_level_asymmetric_support();
	test_asymmetric_provider_defaults_return_unsupported_algorithm();
	test_invalid_signature_is_successful_verify_result();
	return 0;
}
