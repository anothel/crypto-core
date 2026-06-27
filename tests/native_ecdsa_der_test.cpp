#include "crypto_core/internal/ec_der.hpp"

#include "test_vectors.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>
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

void require_bytes(std::span<const std::uint8_t> actual, std::span<const std::uint8_t> expected)
{
	require(actual.size() == expected.size());
	for (std::size_t i = 0; i < actual.size(); ++i)
	{
		require(actual[i] == expected[i]);
	}
}

std::vector<std::uint8_t> bytes(std::string_view hex)
{
	auto decoded = crypto_core::test_support::decode_hex(hex);
	require(decoded.has_value());
	return std::move(decoded.value());
}

void require_invalid_key(auto result)
{
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_parses_p256_spki_uncompressed_point()
{
	auto der = bytes("3059301306072A8648CE3D020106082A8648CE3D030107034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	auto key = crypto_core::internal::parse_p256_public_key_der(der);
	require(key.has_value());
	require_bytes(key.value().x.bytes(), bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
	require_bytes(key.value().y.bytes(), bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
}

void test_rejects_wrong_curve_spki()
{
	auto der = bytes("3059301306072A8648CE3D020106082A8648CE3D030108034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	require_invalid_key(crypto_core::internal::parse_p256_public_key_der(der));
}

void test_rejects_missing_curve_spki_parameters()
{
	auto der = bytes("304F300906072A8648CE3D0201034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	require_invalid_key(crypto_core::internal::parse_p256_public_key_der(der));
}

void test_rejects_compressed_point_spki()
{
	auto der = bytes("3059301306072A8648CE3D020106082A8648CE3D030107034200026B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	require_invalid_key(crypto_core::internal::parse_p256_public_key_der(der));
}

void test_rejects_trailing_spki_data()
{
	auto der = bytes("3059301306072A8648CE3D020106082A8648CE3D030107034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F500");
	require_invalid_key(crypto_core::internal::parse_p256_public_key_der(der));
}

void test_parses_ecdsa_signature_der()
{
	auto der = bytes("3006020101020102");
	auto signature = crypto_core::internal::parse_ecdsa_signature_der(der);
	require(signature.has_value());
	require_bytes(signature.value().r.bytes(), std::array<std::uint8_t, 1>{0x01});
	require_bytes(signature.value().s.bytes(), std::array<std::uint8_t, 1>{0x02});
}

void test_parses_required_integer_sign_padding()
{
	auto der = bytes("300702020080020101");
	auto signature = crypto_core::internal::parse_ecdsa_signature_der(der);
	require(signature.has_value());
	require_bytes(signature.value().r.bytes(), std::array<std::uint8_t, 1>{0x80});
	require_bytes(signature.value().s.bytes(), std::array<std::uint8_t, 1>{0x01});
}

void test_rejects_negative_signature_integer()
{
	auto der = bytes("3006020180020101");
	require_invalid_key(crypto_core::internal::parse_ecdsa_signature_der(der));
}

void test_rejects_overlong_signature_integer()
{
	auto der = bytes("300702020001020101");
	require_invalid_key(crypto_core::internal::parse_ecdsa_signature_der(der));
}

void test_rejects_signature_trailing_data()
{
	auto der = bytes("300602010102010200");
	require_invalid_key(crypto_core::internal::parse_ecdsa_signature_der(der));
}

void test_parses_sec1_p256_private_key()
{
	auto der = bytes("303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	auto key = crypto_core::internal::parse_p256_private_key_der(der);
	require(key.has_value());
	require_bytes(key.value().private_scalar.bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000001"));
}

void test_rejects_sec1_p256_private_key_trailing_data()
{
	auto der = bytes("303302010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D0301070500");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(der));
}

void test_rejects_sec1_p256_private_key_without_parameters()
{
	auto der = bytes("302502010104200000000000000000000000000000000000000000000000000000000000000001");
	require_invalid_key(crypto_core::internal::parse_p256_sec1_private_key_der(der));
}

void test_rejects_invalid_p256_private_scalar()
{
	auto zero = bytes("303102010104200000000000000000000000000000000000000000000000000000000000000000A00A06082A8648CE3D030107");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(zero));

	auto group_order = bytes("30310201010420FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551A00A06082A8648CE3D030107");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(group_order));

	auto pkcs8_zero = bytes("304D020100301306072A8648CE3D020106082A8648CE3D0301070433303102010104200000000000000000000000000000000000000000000000000000000000000000A00A06082A8648CE3D030107");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(pkcs8_zero));
}

void test_parses_sec1_p256_private_key_with_public_key()
{
	auto der = bytes("307702010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107A144034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
	auto key = crypto_core::internal::parse_p256_private_key_der(der);
	require(key.has_value());
	require_bytes(key.value().private_scalar.bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000001"));
}

void test_rejects_sec1_p256_private_key_with_malformed_public_key()
{
	auto der = bytes("303602010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107A1030500");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(der));
}

void test_rejects_sec1_p256_private_key_with_off_curve_public_key()
{
	auto der = bytes("307702010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107A1440342000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(der));
}

void test_rejects_sec1_p256_private_key_with_mismatched_public_key()
{
	auto der = bytes("307702010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107A144034200047CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(der));
}

void test_parses_pkcs8_p256_private_key()
{
	auto der = bytes("304D020100301306072A8648CE3D020106082A8648CE3D0301070433303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	auto key = crypto_core::internal::parse_p256_private_key_der(der);
	require(key.has_value());
	require_bytes(key.value().private_scalar.bytes(), bytes("0000000000000000000000000000000000000000000000000000000000000001"));
}

void test_rejects_pkcs8_p256_algorithm_variants()
{
	auto missing_curve = bytes("3043020100300906072A8648CE3D02010433303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require_invalid_key(crypto_core::internal::parse_p256_pkcs8_private_key_der(missing_curve));

	auto wrong_algorithm = bytes("304D020100301306072A8648CE3D020206082A8648CE3D0301070433303102010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D030107");
	require_invalid_key(crypto_core::internal::parse_p256_pkcs8_private_key_der(wrong_algorithm));
}

void test_rejects_pkcs8_p256_private_key_with_trailing_inner_sec1_data()
{
	auto der = bytes("304F020100301306072A8648CE3D020106082A8648CE3D0301070435303302010104200000000000000000000000000000000000000000000000000000000000000001A00A06082A8648CE3D0301070500");
	require_invalid_key(crypto_core::internal::parse_p256_private_key_der(der));
}

void test_encodes_ecdsa_signature_der()
{
	auto encoded = crypto_core::internal::encode_ecdsa_signature_der(
	    bytes("80"),
	    bytes("01"));
	require(encoded.has_value());
	require_bytes(encoded.value().bytes(), bytes("300702020080020101"));
}

} // namespace

int main()
{
	test_parses_p256_spki_uncompressed_point();
	test_rejects_wrong_curve_spki();
	test_rejects_missing_curve_spki_parameters();
	test_rejects_compressed_point_spki();
	test_rejects_trailing_spki_data();
	test_parses_ecdsa_signature_der();
	test_parses_required_integer_sign_padding();
	test_rejects_negative_signature_integer();
	test_rejects_overlong_signature_integer();
	test_rejects_signature_trailing_data();
	test_parses_sec1_p256_private_key();
	test_rejects_sec1_p256_private_key_trailing_data();
	test_rejects_sec1_p256_private_key_without_parameters();
	test_rejects_invalid_p256_private_scalar();
	test_parses_sec1_p256_private_key_with_public_key();
	test_rejects_sec1_p256_private_key_with_malformed_public_key();
	test_rejects_sec1_p256_private_key_with_off_curve_public_key();
	test_rejects_sec1_p256_private_key_with_mismatched_public_key();
	test_parses_pkcs8_p256_private_key();
	test_rejects_pkcs8_p256_algorithm_variants();
	test_rejects_pkcs8_p256_private_key_with_trailing_inner_sec1_data();
	test_encodes_ecdsa_signature_der();
	return 0;
}
