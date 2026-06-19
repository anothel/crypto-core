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

} // namespace

int main()
{
	test_parses_p256_spki_uncompressed_point();
	test_rejects_wrong_curve_spki();
	test_rejects_compressed_point_spki();
	test_rejects_trailing_spki_data();
	test_parses_ecdsa_signature_der();
	test_parses_required_integer_sign_padding();
	test_rejects_negative_signature_integer();
	test_rejects_overlong_signature_integer();
	test_rejects_signature_trailing_data();
	return 0;
}
