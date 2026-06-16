#include "crypto_core/internal/rsa.hpp"
#include "crypto_core/internal/rsa_der.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>

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

constexpr std::array<std::uint8_t, 9> pkcs1_public_key_der{
    0x30,
    0x07,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
};

constexpr std::array<std::uint8_t, 31> pkcs1_private_key_der{
    0x30,
    0x1D,
    0x02,
    0x01,
    0x00,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
    0x02,
    0x02,
    0x0A,
    0xC1,
    0x02,
    0x01,
    0x3D,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x31,
    0x02,
    0x01,
    0x26,
};

void test_rsa_public_operation()
{
	auto key = crypto_core::internal::parse_rsa_public_key_der(pkcs1_public_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 1> message{0x41};
	auto output = crypto_core::internal::rsa_public_operation(key.value(), message);
	require(output.has_value());
	require_bytes(output.value().bytes(), std::array<std::uint8_t, 2>{0x0A, 0xE6});
}

void test_rsa_private_operation()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> ciphertext{0x0A, 0xE6};
	auto output = crypto_core::internal::rsa_private_operation(key.value(), ciphertext);
	require(output.has_value());
	require_bytes(output.value().bytes(), std::array<std::uint8_t, 2>{0x00, 0x41});
}

void test_rsa_private_crt_operation_matches_private_operation()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> ciphertext{0x0A, 0xE6};
	auto plain = crypto_core::internal::rsa_private_operation(key.value(), ciphertext);
	auto crt = crypto_core::internal::rsa_private_crt_operation(key.value(), ciphertext);
	require(plain.has_value());
	require(crt.has_value());
	require_bytes(crt.value().bytes(), plain.value().bytes());
}

void test_rsa_private_crt_blinded_operation_matches_private_operation()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> ciphertext{0x0A, 0xE6};
	const std::array<std::uint8_t, 1> blinding_factor{0x05};
	auto plain = crypto_core::internal::rsa_private_operation(key.value(), ciphertext);
	auto blinded = crypto_core::internal::rsa_private_crt_blinded_operation(key.value(), ciphertext, blinding_factor);
	require(plain.has_value());
	require(blinded.has_value());
	require_bytes(blinded.value().bytes(), plain.value().bytes());
}

void test_rsa_private_crt_blinded_operation_rejects_invalid_blinding_factor()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> ciphertext{0x0A, 0xE6};
	const std::array<std::uint8_t, 1> zero_factor{0x00};
	auto zero = crypto_core::internal::rsa_private_crt_blinded_operation(key.value(), ciphertext, zero_factor);
	require(!zero.has_value());
	require(zero.error().code() == crypto_core::ErrorCode::invalid_argument);

	const std::array<std::uint8_t, 1> shares_prime_factor{0x3D};
	auto non_invertible = crypto_core::internal::rsa_private_crt_blinded_operation(key.value(), ciphertext, shares_prime_factor);
	require(!non_invertible.has_value());
	require(non_invertible.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_rsa_operation_left_pads_to_modulus_width()
{
	auto key = crypto_core::internal::parse_rsa_public_key_der(pkcs1_public_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 1> one{0x01};
	auto output = crypto_core::internal::rsa_public_operation(key.value(), one);
	require(output.has_value());
	require_bytes(output.value().bytes(), std::array<std::uint8_t, 2>{0x00, 0x01});
}

void test_rsa_operation_rejects_representative_not_less_than_modulus()
{
	auto key = crypto_core::internal::parse_rsa_public_key_der(pkcs1_public_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> too_large{0x0C, 0xA1};
	auto output = crypto_core::internal::rsa_public_operation(key.value(), too_large);
	require(!output.has_value());
	require(output.error().code() == crypto_core::ErrorCode::invalid_argument);
}

void test_rsa_private_crt_operation_rejects_representative_not_less_than_modulus()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());

	const std::array<std::uint8_t, 2> too_large{0x0C, 0xA1};
	auto output = crypto_core::internal::rsa_private_crt_operation(key.value(), too_large);
	require(!output.has_value());
	require(output.error().code() == crypto_core::ErrorCode::invalid_argument);
}

} // namespace

int main()
{
	test_rsa_public_operation();
	test_rsa_private_operation();
	test_rsa_private_crt_operation_matches_private_operation();
	test_rsa_private_crt_blinded_operation_matches_private_operation();
	test_rsa_private_crt_blinded_operation_rejects_invalid_blinding_factor();
	test_rsa_operation_left_pads_to_modulus_width();
	test_rsa_operation_rejects_representative_not_less_than_modulus();
	test_rsa_private_crt_operation_rejects_representative_not_less_than_modulus();
	return 0;
}
